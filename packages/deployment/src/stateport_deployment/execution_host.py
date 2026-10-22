"""Deployment adapter backed by the confined execution-host daemon."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import os
from pathlib import Path
import tempfile
import threading
from typing import Any, Callable, Iterator, Mapping

from execution_host import daemon_contract
from execution_host.client import (
    ExecutionHostClient,
    ExecutionHostContractError,
    ExecutionHostRefusal,
    ExecutionHostTransportError,
)
from execution_host.deployment_staging import (
    DeploymentStagingError,
    build_deployment_archive,
    reopen_archive_read_only,
)

from .errors import AdapterError
from .podman import RootlessPodmanAdapter


class ExecutionHostDeploymentAdapter:
    """Preserve the deployment adapter API while moving every effect host-side."""

    def __init__(
        self,
        client: ExecutionHostClient | None,
        *,
        unavailable_reason: str | None = None,
    ) -> None:
        self._client = client
        self._unavailable_reason = unavailable_reason
        self._contexts: dict[str, dict[str, Any]] = {}
        self._context_lock = threading.Lock()
        self._operation_context: ContextVar[dict[str, Any] | None] = ContextVar(
            f"stateport-deployment-operation-{id(self)}",
            default=None,
        )

    @classmethod
    def configured(
        cls,
        *,
        socket_path: str,
        grant_id: str,
        authority_grant_digest: str,
        timeout_seconds: int = 1200,
        output_byte_bound: int = 256 * 1024,
    ) -> "ExecutionHostDeploymentAdapter":
        if not socket_path or not grant_id or not authority_grant_digest:
            return cls(
                None,
                unavailable_reason=(
                    "the deployment execution-host socket and grant are not configured"
                ),
            )
        return cls(
            ExecutionHostClient(
                socket_path,
                grant_id=grant_id,
                authority_grant_digest=authority_grant_digest,
                timeout_seconds=timeout_seconds,
                output_byte_bound=output_byte_bound,
            )
        )

    @staticmethod
    def _failure_code(value: object, fallback: str) -> str:
        if not isinstance(value, str) or not value:
            return fallback
        normalized = value.replace("-", "_")
        if not normalized[0].isalpha() or any(
            not (character.islower() or character.isdigit() or character == "_")
            for character in normalized
        ):
            return fallback
        return normalized[:128]

    def _invoke(self, call: Callable[[], Mapping[str, Any]]) -> dict[str, Any]:
        if self._client is None:
            raise AdapterError(
                "execution_host_unavailable",
                self._unavailable_reason or "the deployment execution host is unavailable",
            )
        try:
            receipt = call()
        except ExecutionHostRefusal as exc:
            refusal = exc.receipt.get("refusal") or {}
            raise AdapterError(
                "execution_host_refused",
                "the execution host refused the typed deployment operation",
                details={"reason": refusal.get("reason"), "detail": refusal.get("detail")},
            ) from exc
        except ExecutionHostTransportError as exc:
            raise AdapterError(
                "execution_host_unavailable",
                "the confined deployment execution host is unavailable",
            ) from exc
        except ExecutionHostContractError as exc:
            raise AdapterError(
                "execution_host_protocol_violation",
                "the execution host returned an invalid deployment receipt",
            ) from exc
        result = receipt.get("result")
        if not isinstance(result, Mapping) or result.get("outcome") not in {
            "succeeded",
            "failed",
        }:
            raise AdapterError(
                "execution_host_protocol_violation",
                "the execution host deployment outcome is invalid",
            )
        cleanup = receipt.get("cleanup")
        if isinstance(cleanup, Mapping) and cleanup.get("outcome") == "failed":
            raise AdapterError(
                "execution_host_cleanup_failed",
                "the execution host could not reclaim its deployment context snapshot",
                details={"executionHostCleanup": dict(cleanup)},
            )
        if result["outcome"] == "failed":
            failure = result.get("failure")
            if not isinstance(failure, Mapping):
                raise AdapterError(
                    "execution_host_protocol_violation",
                    "the execution host deployment failure is invalid",
                )
            details = failure.get("details")
            raise AdapterError(
                self._failure_code(failure.get("code"), "deployment_effect_failed"),
                str(failure.get("message") or "the deployment effect failed")[:500],
                details=dict(details) if isinstance(details, Mapping) else {},
            )
        value = result.get("value")
        if not isinstance(value, Mapping):
            raise AdapterError(
                "execution_host_protocol_violation",
                "the execution host deployment result is invalid",
            )
        return dict(value)

    @contextmanager
    def bind_operation(
        self,
        operation_id: str,
        authority: Mapping[str, Any],
    ) -> Iterator[None]:
        context = daemon_contract.build_deployment_control_context(
            operation_id,
            authority,
        )
        token = self._operation_context.set(context)
        try:
            yield
        finally:
            self._operation_context.reset(token)

    def _bound_control_context(self) -> dict[str, Any]:
        context = self._operation_context.get()
        if context is None:
            raise AdapterError(
                "execution_authority_context_missing",
                "deployment effects require an exact canonical control-plane decision",
            )
        return dict(context)

    def probe(self) -> dict[str, Any]:
        client = self._client
        return self._invoke(
            client.probe_deployment_target if client is not None else lambda: {}
        )

    def materialize_context(
        self, plan: Mapping[str, Any], destination: Path
    ) -> dict[str, Any]:
        # Materialization is the one non-effect adapter step. It remains in the
        # control container because only that container can see the canonical
        # Git object database; the resulting bytes cross the boundary solely
        # as a verified read-only file descriptor during apply/update.
        receipt = RootlessPodmanAdapter.materialize_context(self, plan, destination)
        key = str(destination.resolve(strict=True))
        with self._context_lock:
            if key in self._contexts:
                raise AdapterError(
                    "build_context_conflict", "deployment context identity was already reserved"
                )
            self._contexts[key] = dict(receipt)
        return receipt

    def _with_archive(
        self,
        plan: Mapping[str, Any],
        *,
        context_root: Path,
        overlay_root: Path,
        invoke: Callable[[int, Mapping[str, Any]], Mapping[str, Any]],
    ) -> dict[str, Any]:
        key = str(context_root.resolve(strict=True))
        with self._context_lock:
            context_receipt = self._contexts.pop(key, None)
        if not isinstance(context_receipt, Mapping):
            raise AdapterError(
                "build_context_missing",
                "deployment context was not materialized by this execution-host adapter",
            )
        try:
            read_fd: int | None = None
            with tempfile.TemporaryFile(mode="w+b", dir=context_root.parent) as archive:
                metadata = build_deployment_archive(
                    archive,
                    plan=plan,
                    context_root=context_root,
                    overlay_root=overlay_root,
                    context_digest=str(context_receipt["contextDigest"]),
                )
                read_fd = reopen_archive_read_only(archive)
            try:
                return self._invoke(lambda: invoke(read_fd, metadata))
            finally:
                os.close(read_fd)
        except DeploymentStagingError as exc:
            raise AdapterError(
                self._failure_code(exc.code, "deployment_context_invalid"),
                exc.detail,
            ) from exc
        except OSError as exc:
            raise AdapterError(
                "deployment_context_unavailable",
                "the deployment context archive could not be created privately",
            ) from exc

    def apply(
        self,
        plan: Mapping[str, Any],
        *,
        context_root: Path,
        overlay_root: Path,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        return self._with_archive(
            plan,
            context_root=context_root,
            overlay_root=overlay_root,
            invoke=lambda source_fd, metadata: self._client.apply_deployment(
                plan,
                metadata,
                source_fd=source_fd,
                control_context=self._bound_control_context(),
                failpoint=failpoint,
            ),
        )

    def apply_update(
        self,
        plan: Mapping[str, Any],
        *,
        predecessor_plan: Mapping[str, Any],
        predecessor_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
        context_root: Path,
        overlay_root: Path,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        return self._with_archive(
            plan,
            context_root=context_root,
            overlay_root=overlay_root,
            invoke=lambda source_fd, metadata: self._client.update_deployment(
                plan,
                predecessor_plan=predecessor_plan,
                predecessor_images=predecessor_images,
                infrastructure=infrastructure,
                source_archive=metadata,
                source_fd=source_fd,
                control_context=self._bound_control_context(),
                failpoint=failpoint,
            ),
        )

    def observe(
        self,
        spec: Mapping[str, Any],
        *,
        expected_revision: str | None = None,
        expected_images: Mapping[str, str] | None = None,
        verify_health: bool = False,
        infrastructure: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._invoke(
            lambda: self._client.observe_deployment(
                spec,
                expected_revision=expected_revision,
                expected_images=expected_images,
                verify_health=verify_health,
                infrastructure=infrastructure,
                control_context=self._bound_control_context(),
            )
        )

    def logs(
        self,
        spec: Mapping[str, Any],
        *,
        service_id: str | None = None,
        tail: int = 200,
        expected_revision: str | None = None,
    ) -> dict[str, Any]:
        return self._invoke(
            lambda: self._client.collect_deployment_logs(
                spec,
                service_id=service_id,
                tail=tail,
                expected_revision=expected_revision,
                control_context=self._bound_control_context(),
            )
        )

    def restart(
        self,
        spec: Mapping[str, Any],
        *,
        expected_revision: str | None = None,
        expected_images: Mapping[str, str] | None = None,
        infrastructure: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._invoke(
            lambda: self._client.restart_deployment(
                spec,
                expected_revision=expected_revision,
                expected_images=expected_images,
                infrastructure=infrastructure,
                control_context=self._bound_control_context(),
            )
        )

    def remove_runtime(
        self,
        spec: Mapping[str, Any],
        *,
        expected_revision: str | None = None,
        recovery_operation: str | None = None,
    ) -> dict[str, Any]:
        return self._invoke(
            lambda: self._client.remove_deployment_runtime(
                spec,
                expected_revision=expected_revision,
                recovery_operation=recovery_operation,
                control_context=self._bound_control_context(),
            )
        )

    def backup_data(
        self,
        spec: Mapping[str, Any],
        *,
        backup_id: str,
        plan_digest: str,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        expected_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        return self._invoke(
            lambda: self._client.backup_deployment_data(
                spec,
                backup_id=backup_id,
                plan_digest=plan_digest,
                expected_volumes=expected_volumes,
                expected_revision=expected_revision,
                expected_images=expected_images,
                infrastructure=infrastructure,
                control_context=self._bound_control_context(),
            )
        )

    def restore_data(
        self,
        spec: Mapping[str, Any],
        *,
        backup: Mapping[str, Any],
        plan_digest: str,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        expected_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        return self._invoke(
            lambda: self._client.restore_deployment_data(
                spec,
                backup=backup,
                plan_digest=plan_digest,
                expected_volumes=expected_volumes,
                expected_revision=expected_revision,
                expected_images=expected_images,
                infrastructure=infrastructure,
                control_context=self._bound_control_context(),
            )
        )

    def purge_data(
        self,
        spec: Mapping[str, Any],
        *,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        recover_interrupted: bool = False,
    ) -> dict[str, Any]:
        return self._invoke(
            lambda: self._client.purge_deployment_data(
                spec,
                expected_volumes=expected_volumes,
                expected_revision=expected_revision,
                recover_interrupted=recover_interrupted,
                control_context=self._bound_control_context(),
            )
        )


__all__ = ["ExecutionHostDeploymentAdapter"]
