from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


FORMAT = "stateport.run-bundle/v1"
_SECRET = re.compile(r"(?:api[_-]?key|authorization|cookie|credential|password|secret|access[_-]?token|refresh[_-]?token|private[_-]?key|^token$)", re.I)
_PRIVATE_CANARY = "study" + "_lenny"


class RunBundleError(ValueError):
    """Bundle input is unsafe, incomplete, or tampered."""


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _safe_path(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise RunBundleError("bundle paths must be relative POSIX paths")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise RunBundleError("bundle path escapes its root")
    if _PRIVATE_CANARY in value.lower():
        raise RunBundleError("private canary content is forbidden in RunBundles")
    return value


def _check_no_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RunBundleError(f"{path} contains a non-string key")
            metric_token = key == "token" and isinstance(item, Mapping) and set(item) == {"quality", "value"} and item.get("quality") in {"exact", "approximate", "unavailable"} and (item.get("value") is None or isinstance(item.get("value"), (int, float)))
            if _SECRET.search(key) and not (key == "token" and path.endswith(".budgets")) and not metric_token:
                raise RunBundleError(f"credential-like field is forbidden at {path}.{key}")
            _check_no_secrets(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_no_secrets(item, f"{path}[{index}]")
    elif isinstance(value, str) and _PRIVATE_CANARY in value.lower():
        raise RunBundleError("private canary content is forbidden in RunBundles")


def _encode(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    _check_no_secrets(value)
    return _canonical(value)


@dataclass(frozen=True)
class RunBundleWriter:
    """Write a deterministic directory bundle with content-addressed files."""

    destination: Path

    def write(self, *, manifest: Mapping[str, Any], artifacts: Mapping[str, Any]) -> dict[str, Any]:
        if manifest.get("formatVersion") not in {None, FORMAT}:
            raise RunBundleError("unsupported RunBundle format")
        if not isinstance(manifest.get("runId"), str) or not manifest["runId"]:
            raise RunBundleError("RunBundle manifest requires runId")
        _check_no_secrets(manifest)
        encoded: dict[str, bytes] = {}
        for path, value in artifacts.items():
            safe = _safe_path(path)
            if safe in {"bundle-manifest.json", "SHA256SUMS"}:
                raise RunBundleError("reserved bundle artifact path")
            encoded[safe] = _encode(value)
        if "execution/agent-run-spec.json" not in encoded:
            raise RunBundleError("RunBundle requires the exact AgentRunSpec")
        if "execution/capability-negotiation.json" not in encoded:
            raise RunBundleError("RunBundle requires capability negotiation")
        if "identities/state-before.json" not in encoded:
            raise RunBundleError("RunBundle requires before-state identity")

        file_hashes = {path: "sha256:" + hashlib.sha256(value).hexdigest() for path, value in sorted(encoded.items())}
        bundle_manifest = dict(manifest)
        bundle_manifest.update({"formatVersion": FORMAT, "files": file_hashes})
        bundle_manifest["contentDigest"] = "sha256:" + hashlib.sha256(_canonical(file_hashes)).hexdigest()
        encoded["bundle-manifest.json"] = _canonical(bundle_manifest)
        checksums = "".join(f"{digest.removeprefix('sha256:')}  {path}\n" for path, digest in sorted({path: "sha256:" + hashlib.sha256(value).hexdigest() for path, value in encoded.items()}.items()))
        encoded["SHA256SUMS"] = checksums.encode("utf-8")

        temporary = self.destination.with_name(self.destination.name + ".tmp")
        if temporary.exists():
            raise RunBundleError("temporary bundle path already exists")
        temporary.mkdir(parents=True, mode=0o700)
        try:
            for path, value in encoded.items():
                target = temporary / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(value)
            if self.destination.exists():
                raise RunBundleError("RunBundles are immutable; destination already exists")
            temporary.replace(self.destination)
        except Exception:
            import shutil
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return {
            "formatVersion": FORMAT,
            "runId": bundle_manifest["runId"],
            "path": self.destination.as_posix(),
            "contentDigest": bundle_manifest["contentDigest"],
            "fileCount": len(encoded),
        }


def verify_bundle(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    manifest_path = root / "bundle-manifest.json"
    sums_path = root / "SHA256SUMS"
    if not root.is_dir() or not manifest_path.is_file() or not sums_path.is_file():
        raise RunBundleError("RunBundle manifest or checksums are missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("formatVersion") != FORMAT:
        raise RunBundleError("unsupported RunBundle format")
    expected = manifest.get("files")
    if not isinstance(expected, dict):
        raise RunBundleError("RunBundle file map is invalid")
    for path, digest in expected.items():
        _safe_path(path)
        actual = root / path
        if not actual.is_file() or "sha256:" + hashlib.sha256(actual.read_bytes()).hexdigest() != digest:
            raise RunBundleError(f"RunBundle artifact digest mismatch: {path}")
    checksum_entries: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest_value, separator, path = line.partition("  ")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest_value):
            raise RunBundleError("RunBundle SHA256SUMS is malformed")
        safe = _safe_path(path)
        checksum_entries[safe] = digest_value
    expected_checksums = {path: digest.removeprefix("sha256:") for path, digest in expected.items()}
    expected_checksums["bundle-manifest.json"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if checksum_entries != expected_checksums:
        raise RunBundleError("RunBundle SHA256SUMS does not match its manifest")
    return {"formatVersion": FORMAT, "runId": manifest.get("runId"), "contentDigest": manifest.get("contentDigest"), "verified": True, "fileCount": len(expected) + 2}
