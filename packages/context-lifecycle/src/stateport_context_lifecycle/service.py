"""Noncanonical storage and bounded vertical service for context lifecycle."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import threading
from typing import Any, Callable, Mapping

import yaml

from .contracts import (
    CONTINUITY_FORMAT,
    PREFERENCE_MODES,
    ContextLifecycleError,
    ContextLifecyclePolicy,
    ContextLifecycleReceipt,
    ContinuityState,
    EffectiveContextPolicy,
    TokenUsage,
    build_compression_artifact,
    build_handoff_artifact,
    canonical_digest,
    compression_due,
    handoff_due,
    preference_policy,
    resolve_effective_policy,
)


PREFERENCES_FORMAT = "stateport.context-preferences/v1"
RECORD_FORMAT = "stateport.context-lifecycle-record/v1"
VIEW_FORMAT = "stateport.context-lifecycle-view/v1"
GIT_EXECUTABLE = "/usr/bin/git"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ContextLifecycleError(f"invalid_{label}")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ContextLifecycleError(f"invalid_{label}")
    return value


def _git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise ContextLifecycleError(f"invalid_{label}")
    return value


def _safe_root(root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts or root.is_symlink():
        raise ContextLifecycleError("unsafe_instance_root")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ContextLifecycleError("instance_root_unavailable") from exc
    if resolved != root or not resolved.is_dir():
        raise ContextLifecycleError("unsafe_instance_root")
    return resolved


def _private_directory(path: Path, reason: str) -> Path:
    """Create or validate a StatePort-owned operational directory.

    Existing unsafe permissions are refused rather than silently changed. That
    keeps a caller from using this service to chmod or traverse an unrelated
    directory through a configured path.
    """

    if not path.is_absolute() or ".." in path.parts or path.is_symlink():
        raise ContextLifecycleError(reason)
    existed = path.exists()
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved = path.resolve(strict=True)
        metadata = path.stat()
    except OSError as exc:
        raise ContextLifecycleError(reason) from exc
    if (
        resolved != path
        or not path.is_dir()
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
    ):
        raise ContextLifecycleError(reason)
    if not existed:
        try:
            os.chmod(path, 0o700)
        except OSError as exc:
            raise ContextLifecycleError(reason) from exc
    return resolved


def _atomic_json(path: Path, value: Mapping[str, Any], *, operational_root: Path) -> None:
    parent = _private_directory(path.parent, "unsafe_operational_record_path")
    try:
        parent.relative_to(operational_root)
    except ValueError as exc:
        raise ContextLifecycleError("unsafe_operational_record_path") from exc
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ContextLifecycleError("unsafe_operational_record_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _load_json(path: Path, default: Mapping[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return dict(default)
    try:
        metadata = path.stat()
    except OSError as exc:
        raise ContextLifecycleError("unsafe_context_preferences") from exc
    if (
        path.is_symlink()
        or not path.is_file()
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        or metadata.st_size > 1_048_576
    ):
        raise ContextLifecycleError("unsafe_context_preferences")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContextLifecycleError("invalid_context_preferences") from exc
    if not isinstance(value, dict):
        raise ContextLifecycleError("invalid_context_preferences")
    return value


class ContextLifecycleService:
    """Store preferences and artifacts outside every application repository."""

    def __init__(
        self,
        *,
        policy_path: Path,
        preference_file: Path,
        record_root: Path,
        clock: Callable[[], str] = _now,
    ) -> None:
        self._policy_path = policy_path
        self._preference_file = preference_file
        self._record_root = record_root
        self._clock = clock
        self._mutex = threading.RLock()
        self._base_policy = self._load_policy()
        self._preference_root = _private_directory(
            preference_file.parent, "unsafe_context_preferences",
        )
        self._record_root = _private_directory(
            record_root, "unsafe_operational_record_path",
        )
        if preference_file.parent.resolve(strict=True) != self._preference_root:
            raise ContextLifecycleError("unsafe_context_preferences")

    def _load_policy(self) -> ContextLifecyclePolicy:
        if (
            not self._policy_path.is_absolute()
            or self._policy_path.is_symlink()
            or not self._policy_path.is_file()
            or self._policy_path.stat().st_size > 1_048_576
        ):
            raise ContextLifecycleError("context_policy_unavailable")
        try:
            value = yaml.safe_load(self._policy_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ContextLifecycleError("context_policy_invalid") from exc
        try:
            return ContextLifecyclePolicy.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise ContextLifecycleError("context_policy_invalid") from exc

    def _preferences(self) -> dict[str, Any]:
        value = _load_json(
            self._preference_file,
            {"formatVersion": PREFERENCES_FORMAT, "preferences": {}},
        )
        if value.get("formatVersion") != PREFERENCES_FORMAT or not isinstance(value.get("preferences"), dict):
            raise ContextLifecycleError("invalid_context_preferences")
        for instance_id, item in value["preferences"].items():
            if (
                not isinstance(instance_id, str)
                or _ID.fullmatch(instance_id) is None
                or not isinstance(item, dict)
                or set(item) != {"mode", "updatedAt"}
                or item.get("mode") not in PREFERENCE_MODES
                or not isinstance(item.get("updatedAt"), str)
            ):
                raise ContextLifecycleError("invalid_context_preferences")
        return value

    def preference_mode(self, instance_id: str) -> str:
        _id(instance_id, "instance_id")
        with self._mutex:
            return str(self._preferences()["preferences"].get(instance_id, {}).get("mode", "balanced"))

    def effective_policy(self, instance_id: str) -> EffectiveContextPolicy:
        mode = self.preference_mode(instance_id)
        return resolve_effective_policy((
            ("operator", self._base_policy),
            ("user_preference", preference_policy(self._base_policy, mode)),
        ))

    @staticmethod
    def git_identity(root: Path) -> dict[str, Any]:
        root = _safe_root(root)
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}

        def run(arguments: tuple[str, ...], *, binary: bool = False, allow_failure: bool = False) -> bytes:
            try:
                result = subprocess.run(
                    (GIT_EXECUTABLE, "-C", root.as_posix(), *arguments),
                    check=False, capture_output=True, timeout=5, env=environment,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise ContextLifecycleError("git_identity_unavailable") from exc
            if result.returncode and not allow_failure:
                raise ContextLifecycleError("git_identity_unavailable")
            return result.stdout if binary else result.stdout.strip()

        head = run(("rev-parse", "HEAD")).decode("ascii")
        tree = run(("rev-parse", "HEAD^{tree}")).decode("ascii")
        branch_raw = run(("symbolic-ref", "--quiet", "--short", "HEAD"), allow_failure=True)
        branch = branch_raw.decode("utf-8") if branch_raw else "HEAD"
        status = run(("status", "--porcelain=v2", "--untracked-files=all", "-z"), binary=True)
        if _GIT_SHA.fullmatch(head) is None or _GIT_SHA.fullmatch(tree) is None:
            raise ContextLifecycleError("git_identity_unavailable")
        return {
            "repositoryId": "repository." + hashlib.sha256(root.as_posix().encode("utf-8")).hexdigest()[:32],
            "branch": branch,
            "baseSha": head,
            "headSha": head,
            "treeSha": tree,
            "worktreeStatusDigest": "sha256:" + hashlib.sha256(status).hexdigest(),
            "worktreeClean": not status,
        }

    def inspect(
        self,
        instance_id: str,
        instance_root: Path,
        *,
        continuity: ContinuityState | None = None,
        usage: TokenUsage | None = None,
    ) -> dict[str, Any]:
        _id(instance_id, "instance_id")
        mode = self.preference_mode(instance_id)
        policy = self.effective_policy(instance_id)
        try:
            git: dict[str, Any] | None = self.git_identity(instance_root)
            git_reason = None
        except ContextLifecycleError as exc:
            git = None
            git_reason = exc.reason_code
        if continuity is not None and not isinstance(continuity, ContinuityState):
            raise ContextLifecycleError("invalid_continuity_contract")
        if usage is not None and not isinstance(usage, TokenUsage):
            raise ContextLifecycleError("invalid_context_usage")
        continuity_value = continuity.to_dict() if continuity is not None else None
        continuity_fresh = False
        if continuity_value is not None:
            try:
                now = datetime.fromisoformat(self._clock().replace("Z", "+00:00"))
                compiled_at = datetime.fromisoformat(
                    str(continuity_value["contextManifest"]["compiledAt"]).replace("Z", "+00:00")
                )
                fresh_until = datetime.fromisoformat(
                    str(continuity_value["contextManifest"]["freshUntil"]).replace("Z", "+00:00")
                )
                continuity_fresh = compiled_at <= now < fresh_until
            except (KeyError, TypeError, ValueError):
                continuity_fresh = False
        continuity_matches = bool(
            git is not None
            and continuity_value is not None
            and continuity_fresh
            and continuity.instance_id == instance_id
            and continuity_value["baseSha"] == git["headSha"]
            and continuity_value["exactGitIdentity"] == git
        )
        usage = usage or TokenUsage(None, "unavailable", "unavailable")
        policy_value = policy.to_dict()
        records = self._record_root / instance_id
        record_count = len(tuple(records.glob("*.json"))) if records.is_dir() and not records.is_symlink() else 0
        return {
            "formatVersion": VIEW_FORMAT,
            "instanceId": instance_id,
            "preference": {
                "mode": mode,
                "availableModes": [
                    {"id": "faster", "label": "Faster", "description": "Compact earlier and use a smaller context target."},
                    {"id": "balanced", "label": "Balanced", "description": "Use the candidate default context and handoff thresholds."},
                    {"id": "deeper", "label": "Deeper", "description": "Keep more relevant context when platform limits permit."},
                ],
                "rawPromptFieldsAllowed": False,
            },
            "effectivePolicy": policy_value,
            "usage": usage.to_dict(),
            "usageDisplay": (
                f"Approximately {usage.input_tokens} input tokens from the StatePort estimator; provider accounting is unavailable."
                if usage.quality == "estimated"
                else "Token use unavailable — no provider accounting is attached to this conversation."
            ),
            "gitIdentity": git,
            "gitIdentityReason": git_reason,
            "continuity": {
                "available": continuity_matches,
                "reasonCode": (
                    None
                    if continuity_matches
                    else "context_manifest_stale"
                    if continuity_value is not None and not continuity_fresh
                    else "conversation_context_not_available"
                ),
                "manualCompactAvailable": continuity_matches and policy.compression_mode != "disabled",
                "manualHandoffAvailable": continuity_matches and policy.handoff_mode != "disabled" and policy_value["handoff"]["createArtifact"],
                "continuityDigest": continuity.digest if continuity_matches else None,
                "conversationId": continuity.conversation_id if continuity_matches else None,
                "workstreamId": continuity.workstream_id if continuity_matches else None,
                "expectedBaseSha": git["headSha"] if continuity_matches and git is not None else None,
                "expectedPolicyDigest": policy_value["effectivePolicyDigest"] if continuity_matches else None,
            },
            "storedRecordCount": record_count,
            "defaultsEvidence": "candidate_not_benchmarked",
            "authorityClassification": "operational_noncanonical",
            "canonicalStateMutation": False,
        }

    def set_preference(
        self,
        instance_id: str,
        instance_root: Path,
        *,
        expected_instance_id: str,
        expected_policy_digest: str,
        mode: str,
    ) -> dict[str, Any]:
        _id(instance_id, "instance_id")
        if expected_instance_id != instance_id:
            raise ContextLifecycleError("instance_identity_mismatch")
        _digest(expected_policy_digest, "policy_digest")
        if mode not in PREFERENCE_MODES:
            raise ContextLifecycleError("invalid_preference_mode")
        with self._mutex:
            current = self.effective_policy(instance_id).to_dict()["effectivePolicyDigest"]
            if expected_policy_digest != current:
                raise ContextLifecycleError("context_policy_changed")
            value = self._preferences()
            value["preferences"][instance_id] = {"mode": mode, "updatedAt": self._clock()}
            _atomic_json(
                self._preference_file, value, operational_root=self._preference_root,
            )
        return self.inspect(instance_id, instance_root)

    def _request_context(
        self,
        instance_id: str,
        instance_root: Path,
        request: Mapping[str, Any],
    ) -> tuple[EffectiveContextPolicy, TokenUsage, ContinuityState, dict[str, Any], str, str]:
        if not isinstance(request, Mapping) or set(request) != {
            "expectedInstanceId", "expectedBaseSha", "expectedPolicyDigest", "actorId",
            "trigger", "usage", "continuity",
        }:
            raise ContextLifecycleError("invalid_context_lifecycle_request")
        if request["expectedInstanceId"] != instance_id:
            raise ContextLifecycleError("instance_identity_mismatch")
        actor_id = _id(request["actorId"], "actor_id")
        expected_base = _git_sha(request["expectedBaseSha"], "base_sha")
        expected_policy = _digest(request["expectedPolicyDigest"], "policy_digest")
        if request["trigger"] not in {"automatic", "manual"}:
            raise ContextLifecycleError("invalid_lifecycle_trigger")
        trigger = str(request["trigger"])
        try:
            usage = TokenUsage.from_dict(request["usage"])
            continuity = ContinuityState.from_dict(request["continuity"])
        except (TypeError, ValueError) as exc:
            raise ContextLifecycleError("invalid_continuity_contract") from exc
        policy = self.effective_policy(instance_id)
        if policy.to_dict()["effectivePolicyDigest"] != expected_policy:
            raise ContextLifecycleError("context_policy_changed")
        current = self.git_identity(instance_root)
        if expected_base != current["headSha"]:
            raise ContextLifecycleError("base_snapshot_changed")
        if continuity.instance_id != instance_id:
            raise ContextLifecycleError("instance_identity_mismatch")
        continuity_value = continuity.to_dict()
        expected_git = continuity_value["exactGitIdentity"]
        if continuity_value["baseSha"] != expected_base or any(
            expected_git[key] != current[key]
            for key in (
                "repositoryId", "branch", "baseSha", "headSha", "treeSha",
                "worktreeStatusDigest", "worktreeClean",
            )
        ):
            raise ContextLifecycleError("base_snapshot_changed")
        manifest = continuity_value["contextManifest"]
        now = datetime.fromisoformat(self._clock().replace("Z", "+00:00"))
        compiled_at = datetime.fromisoformat(str(manifest["compiledAt"]).replace("Z", "+00:00"))
        fresh_until = datetime.fromisoformat(str(manifest["freshUntil"]).replace("Z", "+00:00"))
        if compiled_at > now:
            raise ContextLifecycleError("context_manifest_from_future")
        if now >= fresh_until:
            raise ContextLifecycleError("context_manifest_stale")
        return policy, usage, continuity, current, actor_id, trigger

    def _persist_record(
        self,
        instance_id: str,
        artifact: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> None:
        record = {
            "formatVersion": RECORD_FORMAT,
            "instanceId": instance_id,
            "artifact": dict(artifact),
            "receipt": dict(receipt),
            "authorityClassification": "operational_noncanonical",
            "canonicalStateMutation": False,
        }
        record["recordDigest"] = canonical_digest(record)
        artifact_id = _id(artifact["artifactId"], "artifact_id")
        _atomic_json(
            self._record_root / instance_id / f"{artifact_id}.json",
            record,
            operational_root=self._record_root,
        )

    def compress(self, instance_id: str, instance_root: Path, request: Mapping[str, Any]) -> dict[str, Any]:
        with self._mutex:
            policy, usage, continuity, before, actor_id, trigger = self._request_context(
                instance_id, instance_root, request,
            )
            if policy.compression_mode == "disabled":
                raise ContextLifecycleError("compression_disabled_by_policy")
            if trigger == "automatic" and not compression_due(usage, policy):
                raise ContextLifecycleError("compression_threshold_not_reached")
            occurred_at = self._clock()
            artifact = build_compression_artifact(
                continuity, usage, policy, trigger=trigger, created_at=occurred_at,
            )
            after = self.git_identity(instance_root)
            if before != after:
                raise ContextLifecycleError("base_snapshot_changed")
            value = artifact.to_dict()
            receipt = ContextLifecycleReceipt.create(
                action="compression", outcome="completed", actor_id=actor_id,
                instance_id=instance_id, conversation_id=continuity.conversation_id,
                workstream_id=continuity.workstream_id,
                policy_digest=value["policyDigest"], input_provenance_digest=continuity.digest,
                artifact_digest=value["artifactDigest"], reason_codes=(), occurred_at=occurred_at,
            ).to_dict()
            self._persist_record(instance_id, value, receipt)
            return {"artifact": value, "receipt": receipt, "canonicalStateUnchanged": True}

    def handoff(self, instance_id: str, instance_root: Path, request: Mapping[str, Any]) -> dict[str, Any]:
        with self._mutex:
            policy, usage, continuity, before, actor_id, trigger = self._request_context(
                instance_id, instance_root, request,
            )
            policy_value = policy.to_dict()
            if policy.handoff_mode == "disabled" or not policy_value["handoff"]["createArtifact"]:
                raise ContextLifecycleError("handoff_disabled_by_policy")
            if trigger == "automatic" and not handoff_due(usage, policy):
                raise ContextLifecycleError("handoff_threshold_not_reached")
            occurred_at = self._clock()
            artifact = build_handoff_artifact(
                continuity, usage, policy, trigger=trigger, created_at=occurred_at,
            )
            after = self.git_identity(instance_root)
            if before != after:
                raise ContextLifecycleError("base_snapshot_changed")
            value = artifact.to_dict()
            receipt = ContextLifecycleReceipt.create(
                action="handoff", outcome="completed", actor_id=actor_id,
                instance_id=instance_id, conversation_id=continuity.conversation_id,
                workstream_id=continuity.workstream_id,
                policy_digest=value["policyDigest"], input_provenance_digest=continuity.digest,
                artifact_digest=value["artifactDigest"], reason_codes=(), occurred_at=occurred_at,
            ).to_dict()
            self._persist_record(instance_id, value, receipt)
            return {"artifact": value, "receipt": receipt, "canonicalStateUnchanged": True}
