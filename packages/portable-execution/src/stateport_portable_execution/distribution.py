"""Deterministic StatePack distribution envelopes.

This is deliberately distinct from ``statepack/v1`` (compiled model context)
and ``stateport.instance-portable/v1`` (private instance transfer).  The first
bounded implementation packages public-safe application sources only.  The
schema reserves the private-instance and derived-deployment kinds without
pretending those exporters exist yet.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import posixpath
import stat
import tempfile
from typing import Any, Iterable, Mapping
import zipfile

import yaml

from instance_backup import remove_owned_directory


DISTRIBUTION_FORMAT = "stateport.statepack-distribution/v1"
IMPORT_PLAN_FORMAT = "stateport.statepack-distribution-import-plan/v1"
IMPORT_RECEIPT_FORMAT = "stateport.statepack-distribution-import/v1"
MANIFEST_NAME = "statepack.json"
FILES_PREFIX = "files/"
PACKAGE_KINDS = ("stateport.application", "stateport.instance", "stateport.deployment")
PROFILE_IDS = ("stateport-native", "agent-package", "standalone-web-oci")

_MAX_FILES = 50_000
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_EXCLUDED_PARTS = {
    ".git",
    ".stateport",
    "engine_sessions",
    "__pycache__",
    "node_modules",
}
_EXCLUDED_PREFIXES = (".statedd/runtime/", "runtime/", "sessions/")
_SECRET_FILENAMES = {
    ".env",
    "credentials.json",
    "credentials.yaml",
    "credentials.yml",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "secret.json",
    "secret.yaml",
    "secret.yml",
}


class DistributionError(ValueError):
    """A StatePack distribution operation is invalid or unsafe."""


def _reject_symlinked_components(path: Path, *, label: str) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path(".")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise DistributionError(f"{label} has a symlinked path component")


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _contains_secret_classification(value: Any) -> bool:
    classification_keys = {"classification", "privacyclassification", "sensitivity", "sourceclassification"}
    sensitive_keys = {
        "access_token", "access_token_value", "api_key", "apikey", "client_secret",
        "credential", "credentials", "password", "private_key", "privatekey",
        "secret", "secrets", "token_value",
    }
    secret_values = {"secret", "secret-bearing", "sensitive"}
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str):
                normalized_key = key.casefold().replace("-", "_")
                if normalized_key in sensitive_keys and nested not in (None, False, ""):
                    return True
                if normalized_key in classification_keys:
                    if isinstance(nested, str) and nested.casefold() in secret_values:
                        return True
            if _contains_secret_classification(nested):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_secret_classification(item) for item in value)
    return False


def _read_stable_source_file(
    path: Path, label: str, *, maximum_bytes: int = _MAX_FILE_BYTES,
) -> tuple[bytes, int]:
    parent_fd = -1
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise DistributionError(f"{label} is not a single regular file")
        data = bytearray()
        while len(data) <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        final = os.fstat(descriptor)
        observed = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        initial_identity = (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns)
        final_identity = (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns)
        observed_identity = (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or initial_identity != final_identity
            or initial_identity != observed_identity
            or len(data) != final.st_size
        ):
            raise DistributionError(f"{label} changed during read")
        if len(data) > maximum_bytes:
            raise DistributionError(f"{label} exceeds the bounded size")
        return bytes(data), stat.S_IMODE(final.st_mode)
    except DistributionError:
        raise
    except OSError as exc:
        raise DistributionError(f"{label} could not be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _safe_relative(value: str, *, label: str = "path") -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise DistributionError(f"{label} must be a non-empty POSIX relative path")
    if value.startswith("/") or value.startswith("//"):
        raise DistributionError(f"{label} must not be absolute")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts) or posixpath.normpath(value) != value:
        raise DistributionError(f"{label} is not a normalized safe relative path")
    return value


def _validate_secret_references(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, Mapping) or set(value) - {"id", "capability", "optional"}:
            raise DistributionError("required secrets may contain id, capability, and optional references only")
        secret_id = value.get("id")
        capability = value.get("capability")
        optional = value.get("optional", False)
        if not isinstance(secret_id, str) or not secret_id or not isinstance(capability, str) or not capability:
            raise DistributionError("required secret references need non-empty id and capability")
        if not isinstance(optional, bool):
            raise DistributionError("required secret optional must be boolean")
        normalized.append({"id": secret_id, "capability": capability, "optional": optional})
    return sorted(normalized, key=lambda item: (item["id"], item["capability"]))


def _profile(profile_id: str) -> dict[str, Any]:
    if profile_id == "stateport-native":
        return {
            "id": profile_id,
            "status": "packaged",
            "artifacts": ["application-source"],
            "degradation": [],
        }
    if profile_id == "agent-package":
        return {
            "id": profile_id,
            "status": "packaged_with_degradation",
            "artifacts": ["application-source", "agent-instructions-if-present"],
            "degradation": ["host capabilities and permissions must be negotiated at import/run time"],
        }
    if profile_id == "standalone-web-oci":
        return {
            "id": profile_id,
            "status": "declared_not_built",
            "artifacts": [],
            "degradation": ["no OCI image, Compose runtime, SBOM, or provenance artifact is included"],
        }
    raise DistributionError(f"unsupported StatePack profile: {profile_id}")


def _descriptor(source_root: Path) -> tuple[dict[str, Any], bytes]:
    path = source_root / "application.yaml"
    if not path.is_file() or path.is_symlink():
        raise DistributionError("application.yaml must be a regular file")
    try:
        data, _mode = _read_stable_source_file(path, "application.yaml")
        value = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError, DistributionError) as exc:
        raise DistributionError("application.yaml could not be read") from exc
    if not isinstance(value, dict) or value.get("formatVersion") != "stateport.application/v1":
        raise DistributionError("application.yaml must use stateport.application/v1")
    if value.get("privacyClassification") != "public_safe":
        raise DistributionError("the first StatePack slice exports public_safe applications only")
    if _contains_secret_classification(value):
        raise DistributionError("application.yaml contains secret-classified fields")
    if not isinstance(value.get("applicationId"), str) or not value["applicationId"]:
        raise DistributionError("application.yaml must declare applicationId")
    return value, data


def _is_excluded(relative: str) -> str | None:
    parts = relative.split("/")
    if any(part in _EXCLUDED_PARTS for part in parts):
        return "transient_or_tool_state"
    if any(relative == prefix[:-1] or relative.startswith(prefix) for prefix in _EXCLUDED_PREFIXES):
        return "transient_runtime_state"
    filename = parts[-1].lower()
    if (
        filename in _SECRET_FILENAMES
        or filename.startswith(("credentials.", "secrets.", "secret."))
        or filename.startswith(".env.")
        or filename.endswith((".pem", ".key", ".p12", ".pfx"))
    ):
        return "secret_bearing_file_class"
    if relative == "instance.yaml" or relative.startswith(("approvals/", "receipts/", "history/")):
        return "private_instance_state"
    return None


def _inventory(source_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, bytes]]:
    if source_root.is_symlink() or not source_root.is_dir():
        raise DistributionError("application source must be an existing non-symlink directory")
    files: list[dict[str, Any]] = []
    exclusions: list[dict[str, str]] = []
    payloads: dict[str, bytes] = {}
    total = 0
    for path in sorted(source_root.rglob("*"), key=lambda item: item.relative_to(source_root).as_posix()):
        relative = _safe_relative(path.relative_to(source_root).as_posix())
        if path.is_symlink():
            raise DistributionError(f"application source contains a symlink: {relative}")
        reason = _is_excluded(relative)
        if reason:
            if path.is_file():
                exclusions.append({"path": relative, "reason": reason})
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            raise DistributionError(f"application source contains a non-regular file: {relative}")
        data, mode = _read_stable_source_file(path, f"application source {relative!r}")
        if len(data) > _MAX_FILE_BYTES:
            raise DistributionError(f"application file exceeds the bounded size: {relative}")
        total += len(data)
        if total > _MAX_TOTAL_BYTES or len(files) >= _MAX_FILES:
            raise DistributionError("application source exceeds bounded package limits")
        # This is a narrow machine-path guard, not a replacement for the
        # separately governed Sensitive Data Gateway.
        if b"/home/" in data or b"/Users/" in data or b"file:///" in data:
            raise DistributionError(f"application source contains an obvious machine-local path: {relative}")
        if relative.endswith((".json", ".yaml", ".yml")):
            try:
                parsed = yaml.safe_load(data.decode("utf-8"))
            except (UnicodeError, yaml.YAMLError):
                parsed = None
            if _contains_secret_classification(parsed):
                raise DistributionError(f"application source contains secret-classified fields: {relative}")
        files.append({"path": relative, "size": len(data), "digest": _digest(data), "mode": mode & 0o755})
        payloads[relative] = data
    if not files:
        raise DistributionError("application source has no distributable files")
    return files, exclusions, payloads


def _declared_schema_identities(payloads: Mapping[str, bytes]) -> set[str]:
    identities: set[str] = set()
    for relative, data in payloads.items():
        if not relative.endswith((".yaml", ".yml")):
            continue
        try:
            value = yaml.safe_load(data.decode("utf-8"))
        except (UnicodeError, yaml.YAMLError):
            continue
        if isinstance(value, dict) and isinstance(value.get("formatVersion"), str) and value["formatVersion"]:
            identities.add(value["formatVersion"])
    return identities


def preview_distribution(
    source_root: str | Path,
    *,
    kind: str = "stateport.application",
    profiles: Iterable[str] = PROFILE_IDS,
    source_identity: str | None = None,
    schema_identities: Iterable[str] = (),
    required_secrets: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Return the exact deterministic manifest without creating an archive."""

    if kind not in PACKAGE_KINDS:
        raise DistributionError(f"unsupported StatePack kind: {kind}")
    if kind != "stateport.application":
        raise DistributionError(f"{kind} export is reserved by the envelope but not implemented in this slice")
    root = Path(source_root)
    _reject_symlinked_components(root, label="application source")
    descriptor, descriptor_bytes = _descriptor(root)
    files, exclusions, payloads = _inventory(root)
    inventory_descriptor_bytes = payloads.get("application.yaml")
    if inventory_descriptor_bytes is None:
        raise DistributionError("application.yaml was not included in the source inventory")
    if descriptor_bytes != inventory_descriptor_bytes:
        raise DistributionError("application.yaml changed during source inspection")
    selected_profiles = tuple(dict.fromkeys(profiles))
    if not selected_profiles:
        raise DistributionError("at least one export profile is required")
    source = source_identity or f"{descriptor.get('sourceProfile', 'unresolved')}@{_digest(descriptor_bytes)}"
    if source.startswith("/") or "file:///" in source or "/home/" in source or "/Users/" in source:
        raise DistributionError("source identity must not contain a machine-local path")
    schemas = sorted(set(schema_identities) | _declared_schema_identities(payloads))
    if any(not isinstance(value, str) or not value or value.startswith("/") for value in schemas):
        raise DistributionError("schema identities must be non-empty portable identifiers")
    payload_digest = _digest(_canonical_json(files))
    return {
        "formatVersion": DISTRIBUTION_FORMAT,
        "kind": kind,
        "packageId": descriptor["applicationId"],
        "applicationDescriptorVersion": descriptor["formatVersion"],
        "sourceIdentity": source,
        "schemaIdentities": schemas,
        "payloadDigest": payload_digest,
        "files": files,
        "exclusions": exclusions,
        "requiredSecrets": _validate_secret_references(required_secrets),
        "profiles": [_profile(profile_id) for profile_id in selected_profiles],
        "interfaces": {
            "mcp": {"status": "not_included"},
            "a2a": {"status": "not_included"},
            "openapi": {"status": "not_included"},
        },
        "derivedArtifacts": {
            "oci": {"status": "not_built"},
            "sbom": {"status": "not_generated"},
            "provenance": {"status": "not_generated"},
        },
        "privacyBoundary": {
            "classification": "public_safe",
            "sensitiveDataGateway": "required_before_publication_not_integrated",
            "secretValuesAllowed": False,
            "privateInstanceStateAllowed": False,
        },
        "migration": {"strategy": "plan_before_apply", "includedMigrations": []},
    }


def _write_member(archive: zipfile.ZipFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    archive.writestr(info, data)


def export_distribution(source_root: str | Path, archive_path: str | Path, **kwargs: Any) -> dict[str, Any]:
    manifest = preview_distribution(source_root, **kwargs)
    root = Path(source_root)
    archive = Path(archive_path)
    _reject_symlinked_components(archive.parent, label="StatePack archive parent")
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists() or archive.is_symlink():
        raise DistributionError("StatePack export refuses to replace an existing archive")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{archive.name}.statepack-exporting-", dir=archive.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", allowZip64=True) as output:
            _write_member(output, MANIFEST_NAME, _canonical_json(manifest))
            for item in manifest["files"]:
                relative = item["path"]
                data, _mode = _read_stable_source_file(
                    root / relative,
                    f"application source {relative!r}",
                )
                if len(data) != item["size"] or _digest(data) != item["digest"]:
                    raise DistributionError(f"application source changed during export: {relative}")
                _write_member(output, FILES_PREFIX + relative, data, item["mode"])
        os.replace(temporary, archive)
    except (OSError, zipfile.BadZipFile) as exc:
        temporary.unlink(missing_ok=True)
        raise DistributionError("StatePack distribution archive could not be written") from exc
    return {
        "formatVersion": DISTRIBUTION_FORMAT,
        "archive": archive.as_posix(),
        "archiveDigest": _digest(
            _read_stable_source_file(
                archive,
                "StatePack archive",
                maximum_bytes=_MAX_TOTAL_BYTES + _MAX_FILE_BYTES,
            )[0]
        ),
        "manifest": manifest,
    }


def inspect_distribution(archive_path: str | Path) -> dict[str, Any]:
    archive_path = Path(archive_path)
    _reject_symlinked_components(archive_path, label="StatePack archive")
    if archive_path.is_symlink() or not archive_path.is_file():
        raise DistributionError("StatePack archive must be a regular file")
    if archive_path.stat().st_size > _MAX_TOTAL_BYTES + _MAX_FILE_BYTES:
        raise DistributionError("StatePack archive exceeds its bounded container size")
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = archive.infolist()
            names = [item.filename for item in members]
            if len(names) != len(set(names)) or MANIFEST_NAME not in names:
                raise DistributionError("StatePack archive has duplicate members or no manifest")
            if archive.getinfo(MANIFEST_NAME).file_size > _MAX_FILE_BYTES:
                raise DistributionError("StatePack manifest exceeds its bounded size")
            manifest = json.loads(archive.read(MANIFEST_NAME))
            if not isinstance(manifest, dict) or manifest.get("formatVersion") != DISTRIBUTION_FORMAT:
                raise DistributionError("StatePack manifest format is unsupported")
            expected_manifest_keys = {
                "formatVersion", "kind", "packageId", "applicationDescriptorVersion", "sourceIdentity",
                "schemaIdentities", "payloadDigest", "files", "exclusions", "requiredSecrets", "profiles",
                "interfaces", "derivedArtifacts", "privacyBoundary", "migration",
            }
            if set(manifest) != expected_manifest_keys:
                raise DistributionError("StatePack manifest fields are invalid")
            if manifest.get("kind") != "stateport.application" or not isinstance(manifest.get("files"), list):
                raise DistributionError("StatePack manifest kind or inventory is invalid")
            if manifest.get("requiredSecrets") != _validate_secret_references(manifest.get("requiredSecrets", [])):
                raise DistributionError("StatePack secret requirements are not normalized references")
            source_identity = manifest.get("sourceIdentity")
            if not isinstance(source_identity, str) or not source_identity or source_identity.startswith("/") or "/home/" in source_identity or "/Users/" in source_identity or "file:///" in source_identity:
                raise DistributionError("StatePack source identity is not portable")
            profile_values = manifest.get("profiles")
            if not isinstance(profile_values, list) or not profile_values:
                raise DistributionError("StatePack profiles are missing")
            profile_ids: set[str] = set()
            for profile_value in profile_values:
                if not isinstance(profile_value, dict) or profile_value != _profile(profile_value.get("id")):
                    raise DistributionError("StatePack profile declaration is unsupported or overclaims artifacts")
                if profile_value["id"] in profile_ids:
                    raise DistributionError("StatePack profile declaration is duplicated")
                profile_ids.add(profile_value["id"])
            if manifest.get("interfaces") != {
                "mcp": {"status": "not_included"},
                "a2a": {"status": "not_included"},
                "openapi": {"status": "not_included"},
            } or manifest.get("derivedArtifacts") != {
                "oci": {"status": "not_built"},
                "sbom": {"status": "not_generated"},
                "provenance": {"status": "not_generated"},
            }:
                raise DistributionError("StatePack v1 contains unsupported interface or derived-artifact claims")
            exclusions = manifest.get("exclusions")
            if not isinstance(exclusions, list):
                raise DistributionError("StatePack exclusions are invalid")
            for exclusion in exclusions:
                if not isinstance(exclusion, dict) or set(exclusion) != {"path", "reason"} or not isinstance(exclusion["reason"], str):
                    raise DistributionError("StatePack exclusion is invalid")
                _safe_relative(exclusion["path"], label="exclusion path")
            expected_names = {MANIFEST_NAME}
            total = 0
            inventory_paths: set[str] = set()
            for item in manifest["files"]:
                if not isinstance(item, dict) or set(item) != {"path", "size", "digest", "mode"}:
                    raise DistributionError("StatePack inventory item is invalid")
                relative = _safe_relative(item.get("path"), label="inventory path")
                if relative in inventory_paths:
                    raise DistributionError("StatePack inventory contains duplicate paths")
                inventory_paths.add(relative)
                member_name = FILES_PREFIX + relative
                expected_names.add(member_name)
                info = archive.getinfo(member_name)
                member_mode = info.external_attr >> 16
                if info.is_dir() or stat.S_ISLNK(member_mode) or not stat.S_ISREG(member_mode):
                    raise DistributionError(f"StatePack member is not a regular file: {relative}")
                if info.file_size > _MAX_FILE_BYTES or not isinstance(item.get("size"), int) or item["size"] < 0:
                    raise DistributionError(f"StatePack member exceeds its bounded size: {relative}")
                if not isinstance(item.get("mode"), int) or item["mode"] < 0 or item["mode"] > 0o755:
                    raise DistributionError(f"StatePack member mode is invalid: {relative}")
                data = archive.read(member_name)
                total += len(data)
                if len(data) != item.get("size") or _digest(data) != item.get("digest"):
                    raise DistributionError(f"StatePack member failed integrity validation: {relative}")
            if set(names) != expected_names or total > _MAX_TOTAL_BYTES:
                raise DistributionError("StatePack archive contains undeclared members or exceeds its limit")
            if manifest.get("payloadDigest") != _digest(_canonical_json(manifest["files"])):
                raise DistributionError("StatePack payload inventory digest is invalid")
    except (OSError, zipfile.BadZipFile, KeyError, json.JSONDecodeError, TypeError) as exc:
        if isinstance(exc, DistributionError):
            raise
        raise DistributionError("StatePack archive is invalid or unreadable") from exc
    return {
        "formatVersion": DISTRIBUTION_FORMAT,
        "archiveDigest": _digest(archive_path.read_bytes()),
        "manifest": manifest,
        "validation": "passed",
    }


def plan_distribution_import(archive_path: str | Path, destination: str | Path) -> dict[str, Any]:
    inspected = inspect_distribution(archive_path)
    target = Path(destination)
    if target.exists() or target.is_symlink():
        raise DistributionError("StatePack import destination must not already exist")
    parent = target.parent
    if not parent.exists() or not parent.is_dir() or parent.is_symlink():
        raise DistributionError("StatePack import destination parent must be an existing non-symlink directory")
    _reject_symlinked_components(parent, label="StatePack import destination parent")
    return {
        "formatVersion": IMPORT_PLAN_FORMAT,
        "archiveDigest": inspected["archiveDigest"],
        "packageId": inspected["manifest"]["packageId"],
        "kind": inspected["manifest"]["kind"],
        "destination": target.as_posix(),
        "fileCount": len(inspected["manifest"]["files"]),
        "dryRun": True,
        "migrationPlan": {
            "required": False,
            "steps": [],
            "reason": "v1 application source is imported without canonical-state migration",
        },
        "rollbackPlan": {
            "strategy": "remove_new_destination",
            "precondition": "destination did not exist before import",
        },
    }


def import_distribution(archive_path: str | Path, destination: str | Path, *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_distribution_import(archive_path, destination)
    if dry_run:
        return plan
    target = Path(destination)
    temporary = Path(tempfile.mkdtemp(prefix=f".{target.name}.statepack-import-", dir=target.parent))
    temporary_info = os.lstat(temporary)
    temporary_identity = (int(temporary_info.st_dev), int(temporary_info.st_ino))
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for item in inspect_distribution(archive_path)["manifest"]["files"]:
                relative = _safe_relative(item["path"])
                output = temporary / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(archive.read(FILES_PREFIX + relative))
                output_fd = os.open(
                    output,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    os.fchmod(output_fd, item["mode"])
                    os.fsync(output_fd)
                finally:
                    os.close(output_fd)
        temporary_fd = os.open(
            temporary,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(temporary_fd)
        finally:
            os.close(temporary_fd)
        if target.exists() or target.is_symlink():
            raise DistributionError("StatePack import destination appeared while the import was staged")
        os.replace(temporary, target)
        parent_fd = os.open(
            target.parent,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception as exc:
        if temporary.exists() or temporary.is_symlink():
            try:
                remove_owned_directory(temporary, temporary_identity)
            except Exception:
                pass
        if isinstance(exc, DistributionError):
            raise
        raise DistributionError("StatePack import failed and the temporary destination was removed") from exc
    return {
        "formatVersion": IMPORT_RECEIPT_FORMAT,
        "archiveDigest": plan["archiveDigest"],
        "packageId": plan["packageId"],
        "kind": plan["kind"],
        "destination": target.as_posix(),
        "fileCount": plan["fileCount"],
        "dryRun": False,
        "migrationPlan": plan["migrationPlan"],
        "rollbackPlan": plan["rollbackPlan"],
    }
