"""Package-owned updater service and diagnostics CLI."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib
import json
import logging
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Mapping, Sequence

from stateport_release import (
    CosignVerificationError,
    ReleaseContractError,
    bundle_slot,
    canonical_digest,
    canonical_json_bytes,
    load_release_index_file,
    signature_bundle_name,
    to_updater_release_envelope,
    verify_release_index,
)

from .authority import UpdateAuthorityError
from .engine import (
    TARGET_ID,
    UPDATER_VERSION,
    UpdateEngine,
    UpdateError,
    historic_verification_policy as _historic_verification_policy,
)
from .installed import (
    AUTHORIZATION_BUNDLE_SCHEMA,
    ControlPlaneBinding,
    InstalledAuthorityAdapter,
)
from .models import UPDATE_CHANNELS, UPDATE_POLICIES, ContractError, UpdatePolicy
from .safe_io import MAX_DOCUMENT_BYTES, SafeIOError, _bounded, create_bytes, create_json, ensure_private_directory, read_bytes, read_json
from .service import UpdaterDiagnostics, UpdaterServiceError, build_server, health_status
from .store import StoreError, UpdateStore


PUBLIC_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
CONTROL_PLANE_ENV = "STATEPORT_UPDATER_CONTROL_PLANE"
RECONCILE_RESOLUTIONS = ("observe", "retry_cleanup", "retry_rollback", "accept_successor")
TYPED_ERRORS = (
    StoreError,
    UpdaterServiceError,
    UpdateError,
    UpdateAuthorityError,
    ContractError,
    SafeIOError,
)


def _public_error_code(exc: Exception, default: str) -> str:
    code = getattr(exc, "code", None) if isinstance(exc, TYPED_ERRORS) else None
    return str(code) if isinstance(code, str) and PUBLIC_ERROR_CODE.fullmatch(code) else default


def _authority_refusal() -> dict[str, str]:
    return {
        "schema": "stateport.updater-error/v1",
        "code": "installed_authority_adapter_required",
        "status": "not_executed",
    }


class _ExactArgumentParser(argparse.ArgumentParser):
    """Transport path rewriting requires the documented full option names."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)


def _parser() -> argparse.ArgumentParser:
    parser = _ExactArgumentParser(prog="stateport-updater")
    parser.add_argument(
        "--state-root",
        type=Path,
        default=Path("/var/lib/stateport-updater"),
        help="absolute owner-private updater state root",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("health", help="print process health")
    subcommands.add_parser("ready", help="validate durable readiness")
    subcommands.add_parser("status", help="print canonical update status")
    check = subcommands.add_parser(
        "check",
        help="verify an exact release index against the installed state without mutating it",
    )
    check.add_argument("--release-index", type=Path, required=True)
    plan = subcommands.add_parser(
        "plan",
        help="plan an exact verified update or the retained-predecessor rollback",
    )
    plan_source = plan.add_mutually_exclusive_group(required=True)
    plan_source.add_argument("--release-index", type=Path)
    plan_source.add_argument("--rollback", action="store_true")
    policy = subcommands.add_parser("policy", help="print the canonical update policy")
    policy_subcommands = policy.add_subparsers(dest="policy_command")
    policy_set = policy_subcommands.add_parser(
        "set",
        help="modify the update policy through installed authority",
    )
    policy_set.add_argument("--mode", choices=sorted(UPDATE_POLICIES))
    policy_set.add_argument("--channel", choices=sorted(UPDATE_CHANNELS))
    policy_set.add_argument(
        "--schedule-days",
        help="comma-separated ISO weekdays (1=Monday..7=Sunday) for scheduled modes",
    )
    policy_set.add_argument("--schedule-start-minute", type=int)
    policy_set.add_argument("--accepted-predecessors", type=int)
    policy_set.add_argument("--failed-successors", type=int)
    policy_set.add_argument("--maximum-versions", type=int)
    policy_set.add_argument("--maximum-age-days", type=int)
    authorize = subcommands.add_parser(
        "authorize",
        help="reserve installed authority for an exact plan and write the authorization bundle",
    )
    authorize.add_argument("--plan-id", required=True)
    authorize.add_argument("--output", type=Path, required=True, help="private output file, or - for stdout")
    apply = subcommands.add_parser(
        "apply",
        help="apply an exact authorized plan when the control plane injects the typed seam",
    )
    apply.add_argument("--plan-id", required=True)
    apply.add_argument("--authorization", type=Path, help="private authorization file, or - for stdin")
    rollback = subcommands.add_parser(
        "rollback",
        help="apply an exact authorized rollback plan when the control plane injects the seam",
    )
    rollback.add_argument("--plan-id", required=True)
    rollback.add_argument("--authorization", type=Path, help="private authorization file, or - for stdin")
    reconcile = subcommands.add_parser(
        "reconcile",
        help="observe or explicitly resolve one interrupted update journal",
    )
    reconcile.add_argument("--resolution", choices=RECONCILE_RESOLUTIONS, default="observe")
    serve = subcommands.add_parser("serve", help="serve loopback health/readiness/status")
    serve.add_argument("--listen", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8091)
    return parser


def _print(value: object) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")


def _load_control_plane(state_root: Path) -> ControlPlaneBinding | None:
    spec = os.environ.get(CONTROL_PLANE_ENV, "").strip()
    if not spec:
        return None
    module_name, separator, factory_name = spec.partition(":")
    if not separator or not module_name or not factory_name:
        raise UpdateAuthorityError(
            "control_plane_binding_invalid",
            "control-plane binding must be named as module:factory",
        )
    try:
        module = importlib.import_module(module_name)
        factory = getattr(module, factory_name)
    except (ImportError, AttributeError) as exc:
        raise UpdateAuthorityError(
            "control_plane_binding_invalid",
            "control-plane binding module or factory is unavailable",
        ) from exc
    if not callable(factory):
        raise UpdateAuthorityError(
            "control_plane_binding_invalid",
            "control-plane binding factory is not callable",
        )
    binding = factory(state_root)
    if not isinstance(binding, ControlPlaneBinding):
        raise UpdateAuthorityError(
            "control_plane_binding_invalid",
            "control-plane binding factory did not return a typed binding",
        )
    return binding.validated(
        expected_target=binding.verification_policy.expected_target
    )


def _signature_bundle_source(
    source_root: Path, bundle_root: Path | None, signature: Mapping[str, Any]
) -> Path:
    """Resolve a signature bundle to one regular file on disk.

    The published release tree keeps image signature bundles URI-relative
    beneath a ``signatures/`` directory beside the release index, and durable
    retention keys every bundle by its digest slot.  Local staging and the
    operator fixture layout keep bundles flat.  Candidates are tried in
    deterministic order and the first regular file wins; the durable digest
    slot is consulted last so a staged download can never shadow a retained
    slot, and resolution still works when only the durable root remains.
    """

    name = signature_bundle_name(signature)
    candidates = [source_root / name, source_root / "signatures" / name,
                  source_root / "image-bundles" / name, bundle_slot(source_root, signature)]
    if bundle_root is not None:
        candidates.append(bundle_root / name)
    if bundle_root is not None:
        candidates.append(bundle_slot(bundle_root, signature))
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return candidates[0]


class _CandidateVerifier:
    """Route exact staged descriptors to their live verifier, all others to history."""

    def __init__(self, candidate: Any, durable: Any, signatures: list[Mapping[str, Any]], images: list[Mapping[str, Any]]) -> None:
        self.candidate, self.durable = candidate, durable
        self.signatures = {canonical_digest(signature) for signature in signatures}
        self.images = {(image["imageId"], image["digest"]) for image in images}

    def _select(self, signature: Mapping[str, Any]) -> Any:
        return self.candidate if canonical_digest(signature) in self.signatures else self.durable

    def verify_blob(self, payload: bytes, signature: Mapping[str, Any]) -> Any:
        return self._select(signature).verify_blob(payload, signature)

    def verify_image(self, reference: str, signature: Mapping[str, Any]) -> Any:
        return self._select(signature).verify_image(reference, signature)

    def resolve_local_image_manifest(self, image_id: str, digest: str) -> bytes | None:
        verifier = self.candidate if (image_id, digest) in self.images else self.durable
        resolver = getattr(verifier, "resolve_local_image_manifest", None)
        return resolver(image_id, digest) if callable(resolver) else None


def _retain_image_manifests(binding: ControlPlaneBinding, index: Any, source_root: Path, target_root: Path) -> None:
    images = [image for image in index.document["signed"]["images"]
              if image["signature"].get("subjectKind") == "oci-manifest-blob"]
    if not images:
        return
    source_verifier = binding.transport_verifier_factory(source_root)
    for image in images:
        resolver = getattr(source_verifier, "resolve_local_image_manifest", None)
        content = resolver(image["imageId"], image["digest"]) if callable(resolver) else None
        if content is None:
            resolver = getattr(binding.signature_verifier, "resolve_local_image_manifest", None)
            content = resolver(image["imageId"], image["digest"]) if callable(resolver) else None
        if (not isinstance(content, bytes) or len(content) > 2 * 1024 * 1024
                or "sha256:" + hashlib.sha256(content).hexdigest() != image["digest"]):
            raise UpdateAuthorityError("release_manifest_unavailable", "exact candidate image manifest is unavailable")
        directory = ensure_private_directory(target_root / "image-manifests")
        path = directory / (image["digest"].removeprefix("sha256:") + ".json")
        if path.exists() or path.is_symlink():
            if read_bytes(path, "candidate image manifest") != content:
                raise UpdateAuthorityError("release_manifest_conflict", "retained image manifest differs")
        else:
            create_bytes(path, content, "candidate image manifest")


@contextmanager
def _verified_envelope(
    binding: ControlPlaneBinding, release_index: Path, store: UpdateStore
) -> Any:
    index = load_release_index_file(release_index)
    signatures: list[Mapping[str, Any]] = list(index.document["signatures"])
    for image in index.document["signed"]["images"]:
        signature = image.get("signature")
        if isinstance(signature, Mapping):
            signatures.append(signature)
    successor = index.document["signed"].get("successor")
    predecessor = None
    if successor is not None and successor["predecessor"] is not None:
        predecessor_id = str(successor["predecessor"]["releaseId"])
        try:
            predecessor = load_release_index_file(
                store.releases / f"{predecessor_id}.release-index.json",
                legacy_predecessor=True,
            )
        except (OSError, ReleaseContractError) as exc:
            raise UpdateAuthorityError(
                "release_predecessor_unavailable",
                "successor predecessor is not durable in installed state",
            ) from exc
    factory = binding.transport_verifier_factory
    if not callable(factory):
        raise UpdateAuthorityError(
            "control_plane_binding_invalid",
            "control-plane binding has no read-only transport verifier factory",
        )
    with tempfile.TemporaryDirectory(prefix="stateport-update-verify-") as retained:
        retained_root = Path(retained)
        retained_root.chmod(0o700)
        verifier = factory(retained_root)
        source_root = release_index.parent
        for signature in signatures:
            try:
                source = _signature_bundle_source(
                    source_root, binding.bundle_root, signature
                )
                verifier.retain_bundle(source, signature)
            except CosignVerificationError as exc:
                raise UpdateAuthorityError(
                    "release_bundle_retention_refused",
                    f"release signature bundle cannot be retained: {exc}",
                ) from exc
        if predecessor is not None:
            claimed = successor["predecessor"] if isinstance(successor, Mapping) else None
            predecessor_signature = (
                claimed.get("signature") if isinstance(claimed, Mapping) else None
            )
            if not isinstance(predecessor_signature, Mapping):
                raise UpdateAuthorityError(
                    "release_predecessor_unavailable",
                    "successor predecessor signature is missing",
                )
            try:
                verifier.retain_bundle(
                    source_root
                    / "predecessor-bundle"
                    / signature_bundle_name(predecessor_signature),
                    predecessor_signature,
                )
                signatures.append(predecessor_signature)
            except CosignVerificationError as exc:
                raise UpdateAuthorityError(
                    "release_bundle_retention_refused",
                    f"predecessor signature bundle cannot be retained: {exc}",
                ) from exc
        _retain_image_manifests(binding, index, source_root, retained_root)
        verified = verify_release_index(
            index,
            policy=binding.verification_policy,
            verifier=verifier,
            predecessor=predecessor,
        )
        yield to_updater_release_envelope(verified), _CandidateVerifier(
            verifier, binding.signature_verifier, signatures, index.document["signed"]["images"]
        )


def _retain_release_bundles(
    binding: ControlPlaneBinding, release_index: Path
) -> None:
    index = load_release_index_file(release_index)
    source_root = release_index.parent
    try:
        sources: list[tuple[Path, Mapping[str, Any]]] = []
        for signature in index.document["signatures"]:
            sources.append(
                (
                    _signature_bundle_source(source_root, binding.bundle_root, signature),
                    signature,
                )
            )
        for image in index.document["signed"]["images"]:
            signature = image.get("signature")
            if isinstance(signature, Mapping):
                sources.append(
                    (
                        _signature_bundle_source(source_root, binding.bundle_root, signature),
                        signature,
                    )
                )
        successor = index.document["signed"].get("successor")
        claimed = successor.get("predecessor") if isinstance(successor, Mapping) else None
        if isinstance(claimed, Mapping) and isinstance(claimed.get("signature"), Mapping):
            signature = claimed["signature"]
            sources.append(
                (
                    source_root
                    / "predecessor-bundle"
                    / signature_bundle_name(signature),
                    signature,
                )
            )
        for source, signature in sources:
            binding.signature_verifier.retain_bundle(source, signature)
        if binding.bundle_root is not None:
            _retain_image_manifests(binding, index, source_root, binding.bundle_root)
    except CosignVerificationError as exc:
        raise UpdateAuthorityError(
            "release_bundle_retention_refused",
            f"release signature bundle cannot be retained: {exc}",
        ) from exc


def _load_authorization(path: Path) -> dict[str, Any]:
    if path == Path("-"):
        try:
            content = sys.stdin.buffer.read(MAX_DOCUMENT_BYTES + 1)
            if len(content) > MAX_DOCUMENT_BYTES:
                raise ValueError("authorization input exceeds its byte bound")
            document = json.loads(content)
            _bounded(document, label="update authorization bundle")
        except (ValueError, UnicodeError, RecursionError, SafeIOError) as exc:
            raise UpdateAuthorityError("authority_reservation_invalid", "authorization stdin is malformed or oversized") from exc
    else:
        document = read_json(path, "update authorization bundle")
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "decision", "reservation"}
        or document.get("schema") != AUTHORIZATION_BUNDLE_SCHEMA
    ):
        raise UpdateAuthorityError(
            "authority_reservation_invalid",
            "update authorization bundle is malformed",
        )
    return {"decision": document["decision"], "reservation": document["reservation"]}


def _parse_schedule_days(raw: str) -> tuple[int, ...]:
    try:
        days = tuple(sorted({int(item, 10) for item in raw.split(",")}))
    except ValueError as exc:
        raise ContractError("policy_invalid", "update schedule days are malformed") from exc
    if not days or any(day < 1 or day > 7 for day in days):
        raise ContractError("policy_invalid", "update schedule days are malformed")
    return days


def _policy_from_arguments(arguments: argparse.Namespace, current: UpdatePolicy) -> UpdatePolicy:
    scheduled_days: tuple[int, ...] | None
    if arguments.schedule_days is not None:
        scheduled_days = _parse_schedule_days(arguments.schedule_days)
    else:
        scheduled_days = current.schedule_days
    start_minute = (
        current.schedule_start_minute_utc
        if arguments.schedule_start_minute is None
        else arguments.schedule_start_minute
    )
    policy = UpdatePolicy(
        mode=arguments.mode or current.mode,
        channel=arguments.channel or current.channel,
        schedule_days=scheduled_days,
        schedule_start_minute_utc=start_minute,
        accepted_predecessors=(
            current.accepted_predecessors
            if arguments.accepted_predecessors is None
            else arguments.accepted_predecessors
        ),
        failed_successors=(
            current.failed_successors
            if arguments.failed_successors is None
            else arguments.failed_successors
        ),
        maximum_versions=(
            current.maximum_versions
            if arguments.maximum_versions is None
            else arguments.maximum_versions
        ),
        maximum_age_days=(
            current.maximum_age_days
            if arguments.maximum_age_days is None
            else arguments.maximum_age_days
        ),
    )
    # Strictly re-validate through the canonical serializer before returning.
    policy.to_mapping()
    return policy


def _serve(arguments: argparse.Namespace, state_root: Path) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    server = build_server(
        listen=arguments.listen,
        port=arguments.port,
        state_root=state_root,
        service_version=UPDATER_VERSION,
    )
    address, port = server.server_address[:2]
    logging.getLogger("stateport_updater.service").info(
        json.dumps(
            {
                "event": "updater_service_ready",
                "service": "stateport-updater",
                "version": UPDATER_VERSION,
                "listen": address,
                "port": port,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _dispatch(
    arguments: argparse.Namespace,
    state_root: Path,
    control_plane: ControlPlaneBinding | None,
) -> int:
    command = arguments.command
    if command in {"ready", "status"}:
        diagnostics = UpdaterDiagnostics(
            UpdateStore.open_existing(state_root),
            service_version=UPDATER_VERSION,
        )
        result = diagnostics.readiness() if command == "ready" else diagnostics.status()
        _print(result.payload)
        return 0 if int(result.http_status) < 400 else 1
    if command == "serve":
        return _serve(arguments, state_root)

    store = UpdateStore.open_existing(state_root)
    adapter = InstalledAuthorityAdapter(store)
    if command == "authorize":
        with store.transaction() as session:
            plan = session.load_plan(arguments.plan_id)
        bundle = adapter.reserve(plan)
        if arguments.output == Path("-"):
            _print({"schema": AUTHORIZATION_BUNDLE_SCHEMA, **bundle})
            return 0
        create_json(
            arguments.output,
            {"schema": AUTHORIZATION_BUNDLE_SCHEMA, **bundle},
            "update authorization bundle",
        )
        _print(
            {
                "schema": "stateport.updater-result/v1",
                "result": "authorization_reserved",
                "planId": arguments.plan_id,
                "requestId": bundle["decision"]["requestId"],
            }
        )
        return 0
    if command == "policy":
        with store.transaction() as session:
            status = session.load_status()
        if arguments.policy_command != "set":
            _print(status["policy"])
            return 0
        policy = _policy_from_arguments(
            arguments,
            UpdatePolicy.from_mapping(status["policy"]),
        )
        historic_policy = _historic_verification_policy(store)
        engine = UpdateEngine(
            store,
            object(),
            adapter,
            verification_policy=historic_policy,
            signature_verifier=object(),
            target_id=historic_policy.expected_target,
        )
        changed = engine.set_policy(
            policy,
            expected_status_digest=canonical_digest(status),
            mutate=adapter.execute_scoped,
        )
        _print(changed)
        return 0

    binding = control_plane
    if binding is None:
        binding = _load_control_plane(state_root)
    if binding is None:
        _print(_authority_refusal())
        return 3
    binding = binding.validated(
        expected_target=binding.verification_policy.expected_target
    )
    adapter = InstalledAuthorityAdapter(store, clock=binding.clock)
    engine = UpdateEngine(
        store,
        binding.host,
        adapter,
        verification_policy=binding.verification_policy,
        signature_verifier=binding.signature_verifier,
        target_id=binding.verification_policy.expected_target,
        clock=binding.clock,
    )
    if command == "check" or (command == "plan" and not arguments.rollback):
        with _verified_envelope(binding, arguments.release_index, store) as (envelope, verifier):
            engine.signature_verifier = verifier
            if command == "check":
                result = engine.check(envelope)
            else:
                result = engine.plan(
                    envelope,
                    retain_candidate=lambda: _retain_release_bundles(binding, arguments.release_index),
                )
            _print(result)
        return 0
    if command == "plan":
        _print(engine.plan(operation="rollback"))
        return 0
    if command in {"apply", "rollback"}:
        authorization = _load_authorization(arguments.authorization)
        _print(engine.apply(arguments.plan_id, authorization))
        return 0
    _print(engine.reconcile(resolution=arguments.resolution))
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    control_plane: ControlPlaneBinding | None = None,
) -> int:
    arguments = _parser().parse_args(argv)
    state_root = arguments.state_root
    if arguments.command == "health":
        result = health_status(UPDATER_VERSION)
        _print(result.payload)
        return 0
    if arguments.command in {"apply", "rollback"} and arguments.authorization is None:
        _print(_authority_refusal())
        return 3
    if not state_root.is_absolute():
        _print(
            {
                "schema": "stateport.updater-error/v1",
                "code": "state_root_invalid",
                "status": "not_executed",
            }
        )
        return 2
    try:
        return _dispatch(arguments, state_root, control_plane)
    except UpdateAuthorityError as exc:
        _print(
            {
                "schema": "stateport.updater-error/v1",
                "code": _public_error_code(exc, "authority_error"),
                "status": "not_executed",
            }
        )
        return 3
    except (StoreError, UpdaterServiceError, UpdateError, ContractError, SafeIOError) as exc:
        _print(
            {
                "schema": "stateport.updater-error/v1",
                "code": _public_error_code(exc, "updater_error"),
                "status": "not_executed",
            }
        )
        return 2
    except ValueError:
        _print(
            {
                "schema": "stateport.updater-error/v1",
                "code": "updater_error",
                "status": "not_executed",
            }
        )
        return 2
    except Exception:
        _print(
            {
                "schema": "stateport.updater-error/v1",
                "code": "updater_internal_error",
                "status": "not_executed",
            }
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
