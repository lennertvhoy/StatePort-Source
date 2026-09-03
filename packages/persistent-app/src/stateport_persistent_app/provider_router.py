"""One durable provider authority for the first StatePort AI vertical slice.

The router deliberately supports one selected Codex profile. It does not own
credentials, fallback chains, or agent state. Those remain outside canonical
application state and are only widened after the first application outcome is
qualified.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Mapping

from codex_adapter import CodexAdapter
from execution_host.contracts import AgentRunSpec, CapabilityRequest, require_accepted
from external_engine_runtime import ProcessIdentity, ProcessRuntimeError, decode_jsonl


FORMAT = "stateport.provider-router/v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|"
    r"access[_-]?token|refresh[_-]?token)",
    re.I,
)


class ProviderRouterError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderInvocation:
    assistant_text: str
    runtime_profile: dict[str, Any]
    adapter: dict[str, str]
    provider: dict[str, str]
    model: dict[str, str]
    usage: dict[str, Any]
    duration_ms: int
    cleanup: str
    normalized_events: tuple[dict[str, Any], ...]

    def durable_result(self) -> dict[str, Any]:
        return {
            "assistantText": self.assistant_text,
            "runtime": self.runtime_profile,
            "adapter": self.adapter,
            "provider": self.provider,
            "model": self.model,
            "usage": self.usage,
            "durationMs": self.duration_ms,
            "cleanup": self.cleanup,
        }


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ProviderRouterError("provider profile is not canonical JSON") from exc


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _reject_secret_keys(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProviderRouterError(f"{path} keys must be strings")
            if _SECRET_KEY.search(key):
                raise ProviderRouterError(f"credential-like field is forbidden at {path}.{key}")
            _reject_secret_keys(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_keys(item, f"{path}[{index}]")


def _safe_path(value: Path | str) -> Path:
    path = Path(os.path.abspath(os.fspath(value)))
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ProviderRouterError("provider profile path is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or path.is_symlink():
        raise ProviderRouterError("provider profile path is unsafe")
    return path


class ProviderRouter:
    """Resolve and invoke the one explicitly selected Codex runtime profile."""

    def __init__(
        self,
        profile_path: Path | str,
        *,
        adapter: CodexAdapter | None = None,
    ) -> None:
        self.profile_path = _safe_path(profile_path)
        self.adapter = adapter or CodexAdapter()
        self._profile = self._load_profile()

    @staticmethod
    def configure_codex(
        profile_path: Path | str,
        *,
        model_identifier: str,
        time_seconds: int = 120,
        steps: int = 8,
    ) -> dict[str, Any]:
        path = _safe_path(profile_path)
        if _MODEL.fullmatch(model_identifier) is None:
            raise ProviderRouterError("model identifier is invalid")
        if (
            isinstance(time_seconds, bool)
            or not isinstance(time_seconds, int)
            or not 5 <= time_seconds <= 3600
        ):
            raise ProviderRouterError("time_seconds must be between 5 and 3600")
        if isinstance(steps, bool) or not isinstance(steps, int) or not 1 <= steps <= 64:
            raise ProviderRouterError("steps must be between 1 and 64")
        profile: dict[str, Any] = {
            "formatVersion": FORMAT,
            "revision": 1,
            "provider": {
                "id": "codex-local",
                "backendId": "codex",
                "adapterId": "codex-cli",
                "authenticationRouteClass": "operator_authenticated_unverified",
            },
            "model": {"id": model_identifier},
            "sandbox": {"profile": "workspace-write"},
            "budgets": {
                "token": 0,
                "costMinor": 0,
                "timeSeconds": time_seconds,
                "steps": steps,
            },
        }
        profile["profileDigest"] = _digest(profile)
        temporary: Path | None = None
        try:
            descriptor, raw_temp = tempfile.mkstemp(
                prefix=".provider-router.", suffix=".tmp", dir=path.parent
            )
            temporary = Path(raw_temp)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(_canonical(profile) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return profile

    def _load_profile(self) -> dict[str, Any]:
        if not self.profile_path.is_file() or self.profile_path.is_symlink():
            raise ProviderRouterError(
                "provider profile is not configured; select an explicit Codex model first"
            )
        try:
            value = json.loads(self.profile_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProviderRouterError("provider profile is unreadable") from exc
        if not isinstance(value, dict):
            raise ProviderRouterError("provider profile must be a mapping")
        _reject_secret_keys(value)
        expected = {
            "formatVersion", "revision", "provider", "model",
            "sandbox", "budgets", "profileDigest",
        }
        if set(value) != expected or value.get("formatVersion") != FORMAT:
            raise ProviderRouterError("provider profile shape is invalid")
        digest = value.get("profileDigest")
        body = {key: item for key, item in value.items() if key != "profileDigest"}
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None or digest != _digest(body):
            raise ProviderRouterError("provider profile digest is invalid")
        provider = value.get("provider")
        model = value.get("model")
        sandbox = value.get("sandbox")
        budgets = value.get("budgets")
        if not isinstance(provider, dict) or set(provider) != {
            "id", "backendId", "adapterId", "authenticationRouteClass"
        }:
            raise ProviderRouterError("provider identity is invalid")
        if provider != {
            "id": "codex-local",
            "backendId": "codex",
            "adapterId": "codex-cli",
            "authenticationRouteClass": "operator_authenticated_unverified",
        }:
            raise ProviderRouterError("only the bounded Codex provider is supported")
        if (
            not isinstance(model, dict)
            or set(model) != {"id"}
            or not isinstance(model["id"], str)
            or _MODEL.fullmatch(model["id"]) is None
        ):
            raise ProviderRouterError("model identity is invalid")
        if sandbox != {"profile": "workspace-write"}:
            raise ProviderRouterError("sandbox profile is unsupported")
        if not isinstance(budgets, dict) or set(budgets) != {
            "token", "costMinor", "timeSeconds", "steps"
        }:
            raise ProviderRouterError("provider budgets are invalid")
        for key in ("token", "costMinor", "timeSeconds", "steps"):
            amount = budgets[key]
            if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
                raise ProviderRouterError(f"provider budget {key} is invalid")
        if not 5 <= budgets["timeSeconds"] <= 3600 or not 1 <= budgets["steps"] <= 64:
            raise ProviderRouterError("provider execution budgets are outside bounds")
        return value

    @property
    def runtime_profile(self) -> dict[str, Any]:
        capabilities = self.adapter.capabilities()
        return {
            "formatVersion": FORMAT,
            "profileDigest": self._profile["profileDigest"],
            "provider": dict(self._profile["provider"]),
            "model": dict(self._profile["model"]),
            "sandbox": dict(self._profile["sandbox"]),
            "budgets": dict(self._profile["budgets"]),
            "adapterVersion": capabilities.adapter_version,
            "productionEligible": capabilities.production_eligible,
            "authenticationStatus": "unverified",
        }

    def status(self) -> dict[str, Any]:
        capabilities = self.adapter.capabilities()
        return {
            "configured": True,
            "available": self.adapter.probe.installed,
            "runtimeProfile": self.runtime_profile,
            "capabilities": capabilities.to_dict(),
        }

    def invoke(
        self,
        *,
        work_id: str,
        attempt_id: str,
        attempt_ordinal: int,
        instance_id: str,
        conversation_id: str,
        message_id: str,
        source_sequence: int,
        objective: str,
        context_digest: str,
        staging_root: Path,
        cancel_event: Any | None = None,
        on_started: Callable[[ProcessIdentity], None] | None = None,
        on_finished: Callable[[ProcessIdentity], None] | None = None,
    ) -> ProviderInvocation:
        for value, label in (
            (work_id, "work_id"), (attempt_id, "attempt_id"),
            (instance_id, "instance_id"), (conversation_id, "conversation_id"),
            (message_id, "message_id"),
        ):
            if not isinstance(value, str) or _ID.fullmatch(value) is None:
                raise ProviderRouterError(f"{label} is invalid")
        if (
            isinstance(attempt_ordinal, bool)
            or not isinstance(attempt_ordinal, int)
            or attempt_ordinal < 1
            or isinstance(source_sequence, bool)
            or not isinstance(source_sequence, int)
            or source_sequence < 1
        ):
            raise ProviderRouterError("assistant attempt or sequence is invalid")
        if not isinstance(objective, str) or not objective.strip():
            raise ProviderRouterError("assistant objective is empty")
        if not isinstance(context_digest, str) or _DIGEST.fullmatch(context_digest) is None:
            raise ProviderRouterError("assistant context digest is invalid")
        if not staging_root.is_absolute() or not staging_root.is_dir() or staging_root.is_symlink():
            raise ProviderRouterError("assistant staging root is invalid")

        capabilities = self.adapter.capabilities()
        provider = self._profile["provider"]
        model = self._profile["model"]
        spec = AgentRunSpec(
            run_id=f"run.{work_id}.{attempt_ordinal}",
            instance_id=instance_id,
            source_revision=f"conversation:{message_id}:{source_sequence}",
            objective=objective.strip(),
            statepack_reference=f"conversation:{conversation_id}:through:{source_sequence}",
            statepack_digest=context_digest,
            required_capabilities=(CapabilityRequest("nonInteractiveExecution"),),
            optional_capabilities=("structuredEvents", "cancellation"),
            backend_id=provider["backendId"],
            adapter_id=provider["adapterId"],
            adapter_version=capabilities.adapter_version,
            model_identifier=model["id"],
            authentication_route_class=provider["authenticationRouteClass"],
            permitted_capabilities=("read_staging", "write_staging"),
            sandbox_profile=self._profile["sandbox"]["profile"],
            budgets=dict(self._profile["budgets"]),
            validation_commands=(),
            required_output_artifacts=(),
            benchmark_configuration={"purpose": "application_conversation"},
            approval_required_level="conversation_response_no_canonical_mutation",
            repository_instructions=(
                "Do not access or modify canonical application state.",
                "Return one concise assistant response grounded in the supplied conversation.",
            ),
        )
        require_accepted(spec, capabilities)
        generation = "generation." + hashlib.sha256(
            f"{work_id}:{attempt_id}".encode()
        ).hexdigest()
        result = self.adapter.execute(
            spec,
            staging_root,
            cancel_event=cancel_event,
            on_started=on_started,
            on_finished=on_finished,
            process_generation=generation,
        )
        if not result.ok:
            if result.timed_out:
                reason = "provider_timed_out"
            elif result.cancelled:
                reason = "provider_cancelled"
            elif result.output_limited:
                reason = "provider_output_limited"
            else:
                reason = "provider_failed"
            raise ProviderRouterError(reason)
        try:
            events = decode_jsonl(result.stdout)
        except ProcessRuntimeError as exc:
            raise ProviderRouterError("provider output was not valid JSONL") from exc
        assistant_text = self._assistant_text(events)
        usage = self._usage(events)
        return ProviderInvocation(
            assistant_text=assistant_text,
            runtime_profile=self.runtime_profile,
            adapter={"id": provider["adapterId"], "version": capabilities.adapter_version},
            provider={"id": provider["id"]},
            model={"id": model["id"]},
            usage=usage,
            duration_ms=result.duration_ms,
            cleanup=result.cleanup,
            normalized_events=events,
        )

    @staticmethod
    def _assistant_text(events: tuple[dict[str, Any], ...]) -> str:
        texts: list[str] = []
        for event in events:
            event_type = event.get("type")
            item = event.get("item")
            if (
                event_type == "item.completed"
                and isinstance(item, dict)
                and item.get("type") == "agent_message"
                and isinstance(item.get("text"), str)
                and item["text"].strip()
            ):
                texts.append(ProviderRouter._normalise_assistant_message(item["text"]))
            elif (
                event_type == "message"
                and event.get("role") == "assistant"
                and isinstance(event.get("content"), str)
                and event["content"].strip()
            ):
                texts.append(ProviderRouter._normalise_assistant_message(event["content"]))
        if not texts:
            raise ProviderRouterError("provider completed without an assistant message")
        text = "\n\n".join(texts)
        if len(text.encode("utf-8")) > 256 * 1024:
            raise ProviderRouterError("assistant response exceeded the durable result bound")
        return text

    @staticmethod
    def _normalise_assistant_message(value: str) -> str:
        """Unwrap only the exact public-safe response envelope Codex may emit.

        The adapter preserves the original event stream.  The durable response
        field is a user-facing message, so exact ``assistant_response`` and
        ``assistant_message`` wrappers are presentation metadata rather than
        content. Other JSON (or malformed JSON) stays verbatim to avoid
        inventing semantics.
        """

        text = value.strip()
        try:
            envelope = json.loads(text)
        except json.JSONDecodeError:
            return text
        if (
            isinstance(envelope, dict)
            and set(envelope) == {"type", "content"}
            and envelope.get("type") in {"assistant_response", "assistant_message"}
            and isinstance(envelope.get("content"), str)
            and envelope["content"].strip()
        ):
            return envelope["content"].strip()
        return text

    @staticmethod
    def _usage(events: tuple[dict[str, Any], ...]) -> dict[str, Any]:
        for event in reversed(events):
            usage = event.get("usage")
            if not isinstance(usage, dict):
                continue
            input_tokens = usage.get("input_tokens")
            output_tokens = usage.get("output_tokens")
            if (
                isinstance(input_tokens, int)
                and input_tokens >= 0
                and isinstance(output_tokens, int)
                and output_tokens >= 0
            ):
                return {
                    "availability": "exact",
                    "inputTokens": input_tokens,
                    "outputTokens": output_tokens,
                }
        return {"availability": "unavailable"}


__all__ = ["ProviderInvocation", "ProviderRouter", "ProviderRouterError"]
