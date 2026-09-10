"""Fixed control-account endpoint for operator updater commands."""

from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Iterator, Mapping, Sequence

from stateport_release import (
    canonical_digest,
    canonical_json_bytes,
    embedded_predecessor_index,
    load_release_index,
    signature_bundle_name,
)

from . import cli
from .bootstrap import CONTROL_GID, CONTROL_UID, _stage_inputs
from .control_plane import build as build_control_plane
from .installed import AUTHORIZATION_BUNDLE_SCHEMA
from .safe_io import MAX_DOCUMENT_BYTES, SafeIOError, _bounded, read_json
from .store import UpdateStore


REQUEST_SCHEMA = "stateport.control-updater-command/v1"
CONTROL_STATE_ROOT = Path("/var/lib/stateport-control/updater")
CONTROL_QUADLET_ROOT = "/var/lib/stateport-control/.config/containers/systemd"
MAX_REQUEST_BYTES = 64 * 1024 * 1024
MAX_RELEASE_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_BUNDLES = 256
MAX_MANIFESTS = 128
ALLOWED_COMMANDS = frozenset(
    {"health", "ready", "status", "check", "plan", "policy", "authorize", "apply", "rollback", "reconcile"}
)
_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")


class ControlTransportRefusal(ValueError):
    """A generic control transport refusal."""


def _refuse(message: str) -> ControlTransportRefusal:
    return ControlTransportRefusal(message)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _refuse(f"{label} is not an object")
    return dict(value)


def _operator(value: object) -> dict[str, Any]:
    operator = _mapping(value, "operator")
    if set(operator) != {"user", "uid", "gid"}:
        raise _refuse("operator has an unexpected shape")
    if (
        not isinstance(operator["user"], str)
        or _USER.fullmatch(operator["user"]) is None
        or isinstance(operator["uid"], bool)
        or not isinstance(operator["uid"], int)
        or operator["uid"] <= 0
        or isinstance(operator["gid"], bool)
        or not isinstance(operator["gid"], int)
        or operator["gid"] <= 0
        or operator["uid"] == CONTROL_UID
        or operator["gid"] == CONTROL_GID
    ):
        raise _refuse("operator identity is invalid")
    return operator


def _argv(value: object) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise _refuse("command arguments are invalid")
    result = []
    for item in value:
        if not isinstance(item, str) or len(item) > 1024:
            raise _refuse("command arguments are invalid")
        if item == "--state-root" or item.startswith("--state-root="):
            raise _refuse("state root is fixed")
        result.append(item)
    try:
        parsed = cli._parser().parse_args(["--state-root", str(CONTROL_STATE_ROOT), *result])
    except SystemExit as exc:
        raise _refuse("command arguments are invalid") from exc
    if parsed.command not in ALLOWED_COMMANDS:
        raise _refuse("command is unsupported")
    return result


def _request(raw: object) -> dict[str, Any]:
    request = _mapping(raw, "control updater command")
    if set(request) != {"schema", "argv", "release", "authorization", "operator"} or request["schema"] != REQUEST_SCHEMA:
        raise _refuse("control updater command has an unexpected shape")
    _bounded(request, label="control updater command")
    command_argv = _argv(request["argv"])
    release = _mapping(request["release"], "release transport")
    if release:
        expected = {"releaseIndex", "expectedIndexDigest", "expectedSignedPayloadDigest", "channel", "targetId", "bundles", "imageManifests"}
        if set(release) != expected or not isinstance(release["releaseIndex"], Mapping):
            raise _refuse("release transport has an unexpected shape")
        if not isinstance(release["bundles"], list) or len(release["bundles"]) > MAX_BUNDLES:
            raise _refuse("release bundle transport is invalid")
        if not isinstance(release["imageManifests"], list) or len(release["imageManifests"]) > MAX_MANIFESTS:
            raise _refuse("release image-manifest transport is invalid")
    authorization = request["authorization"]
    if authorization is not None:
        auth = _mapping(authorization, "authorization")
        if auth.get("schema") != AUTHORIZATION_BUNDLE_SCHEMA:
            raise _refuse("authorization is invalid")
    return {"argv": command_argv, "release": release, "authorization": authorization, "operator": _operator(request["operator"])}


def _decode(value: object, maximum: int, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise _refuse(f"{label} is missing")
    try:
        payload = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error) as exc:
        raise _refuse(f"{label} is malformed") from exc
    if not payload or len(payload) > maximum:
        raise _refuse(f"{label} exceeds its bound")
    return payload


def _stage_release(release: Mapping[str, Any], root: Path) -> Path | None:
    if not release:
        return None
    try:
        index = load_release_index(canonical_json_bytes(release["releaseIndex"]))
    except Exception as exc:
        raise _refuse("release index is invalid") from exc
    if (
        index.index_digest != release["expectedIndexDigest"]
        or index.signed_digest != release["expectedSignedPayloadDigest"]
        or index.channel != release["channel"]
    ):
        raise _refuse("release transport does not bind the exact index")
    targets = [
        target for target in index.document["signed"]["targets"]
        if str(target.get("targetId")) == str(release["targetId"])
    ]
    if len(targets) != 1:
        raise _refuse("release transport target is absent or duplicated")
    index_path = root / "release-index.json"
    index_path.write_bytes(canonical_json_bytes(release["releaseIndex"]) + b"\n")
    index_path.chmod(0o600)
    predecessor = embedded_predecessor_index(index)
    try:
        transport, _payloads, _expected = _stage_inputs(
            release, index, predecessor, root
        )
    except Exception as exc:
        raise _refuse("release transport bytes are invalid") from exc
    predecessor_descriptors = (
        {
            canonical_digest(signature)
            for signature in predecessor.document["signatures"]
        }
        if predecessor is not None
        else set()
    )
    for item in release["bundles"]:
        signature = _mapping(item.get("signature"), "signature bundle descriptor")
        digest = _mapping(signature.get("bundle"), "signature bundle descriptor").get("digest")
        if not isinstance(digest, str):
            raise _refuse("signature bundle digest is invalid")
        if canonical_digest(signature) in predecessor_descriptors:
            continue
        source = transport / f"bundle-{digest.removeprefix('sha256:')}.sigstore.json"
        try:
            from stateport_release.cosign import retain_bundle
            retain_bundle(root, source, signature)
        except Exception as exc:
            raise _refuse("signature bundle retention failed") from exc
    if predecessor is not None:
        predecessor_root = root / "predecessor-bundle"
        predecessor_root.mkdir(mode=0o700, exist_ok=True)
        for item in release["bundles"]:
            signature = _mapping(item.get("signature"), "signature bundle descriptor")
            bundle = _mapping(signature.get("bundle"), "signature bundle descriptor")
            if canonical_digest(signature) not in predecessor_descriptors:
                continue
            source = transport / f"bundle-{str(bundle['digest']).removeprefix('sha256:')}.sigstore.json"
            try:
                from stateport_release.cosign import retain_bundle
                retain_bundle(root, source, signature)
            except Exception as exc:
                raise _refuse("predecessor bundle retention failed") from exc
            destination = predecessor_root / signature_bundle_name(signature)
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o600)
    (transport / "image-manifests").rename(root / "image-manifests")
    return index_path


def _replace(argv: list[str], option: str, value: str) -> list[str]:
    result: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == option:
            if index + 1 >= len(argv):
                raise _refuse(f"{option} has no value")
            result.extend((option, value))
            index += 2
        elif token.startswith(option + "="):
            result.append(option + "=" + value)
            index += 1
        else:
            result.append(token)
            index += 1
    return result


def _validate_operator_record(operator: Mapping[str, Any]) -> None:
    try:
        record = read_json(CONTROL_STATE_ROOT / "trust" / "operator.json", "control updater operator")
    except SafeIOError as exc:
        raise _refuse("control updater operator record is unavailable") from exc
    expected = {"schema": "stateport.control-updater-operator/v1", "operator": dict(operator), "actorId": record.get("actorId")}
    if record.get("schema") != expected["schema"] or record.get("operator") != expected["operator"] or not isinstance(expected["actorId"], str):
        raise _refuse("control updater operator record conflicts")


@contextmanager
def _redirect_stdin(stream: Any) -> Iterator[None]:
    previous = sys.stdin
    sys.stdin = stream
    try:
        yield
    finally:
        sys.stdin = previous


def _validate_environment() -> None:
    """Accept only root-helper supplied fixed control-plane overrides."""
    expected = {
        "STATEPORT_COSIGN": "/usr/local/lib/stateport/tools/cosign",
        "STATEPORT_UPDATER_CONTROL_PLANE": "stateport_updater.control_plane:build",
        "STATEPORT_UPDATER_BUNDLE_ROOT": str(CONTROL_STATE_ROOT / "bundles"),
        "STATEPORT_QUADLET_ROOT": CONTROL_QUADLET_ROOT,
    }
    forbidden = {"STATEPORT_ACTOR_ID", "STATEPORT_UPDATER_STATE_ROOT"}
    for key, value in os.environ.items():
        if key in forbidden:
            raise _refuse("caller actor or state environment is not accepted")
        if key in expected and value != expected[key]:
            raise _refuse("control-plane environment is not root-bound")


def main() -> int:
    invoked = False
    try:
        if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (CONTROL_UID, CONTROL_UID, CONTROL_GID, CONTROL_GID):
            raise _refuse("control updater command requires the fixed account")
        _validate_environment()
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise _refuse("control updater command exceeds its byte bound")
        try:
            parsed = _request(json.loads(raw))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise _refuse("control updater command is malformed") from exc
        try:
            parsed_cli = cli._parser().parse_args(
                ["--state-root", str(CONTROL_STATE_ROOT), *parsed["argv"]]
            )
        except SystemExit as exc:
            raise _refuse("command arguments are invalid") from exc
        if (
            parsed_cli.command == "check"
            or (parsed_cli.command == "plan" and not parsed_cli.rollback)
        ) and not parsed["release"]:
            raise _refuse("release transport is required for this command")
        _validate_operator_record(parsed["operator"])
        with tempfile.TemporaryDirectory(prefix="stateport-control-command-") as temporary:
            temporary_root = Path(temporary)
            staged = _stage_release(parsed["release"], temporary_root)
            command_argv = list(parsed["argv"])
            if staged is not None:
                command_argv = _replace(command_argv, "--release-index", str(staged))
            if "--authorization" in command_argv or any(item.startswith("--authorization=") for item in command_argv):
                if parsed["authorization"] is None:
                    raise _refuse("authorization transport is missing")
                command_argv = _replace(command_argv, "--authorization", "-")
            cli_argv = ["--state-root", str(CONTROL_STATE_ROOT), *command_argv]
            try:
                command = cli._parser().parse_args(
                    ["--state-root", str(CONTROL_STATE_ROOT), *command_argv]
                ).command
            except SystemExit as exc:
                raise _refuse("command arguments are invalid") from exc
            if command == "authorize":
                command_argv = _replace(command_argv, "--output", "-")
                cli_argv = ["--state-root", str(CONTROL_STATE_ROOT), *command_argv]
            binding = None
            if command in {"check", "plan", "apply", "rollback", "reconcile"}:
                binding = build_control_plane(CONTROL_STATE_ROOT)
            if parsed["authorization"] is not None:
                stdin = io.TextIOWrapper(io.BytesIO(canonical_json_bytes(parsed["authorization"])))
            else:
                stdin = None
            invoked = True
            if stdin is None:
                return cli.main(cli_argv, control_plane=binding)
            with _redirect_stdin(stdin):
                return cli.main(cli_argv, control_plane=binding)
    except Exception:
        sys.stdout.buffer.write(canonical_json_bytes({
            "schema": "stateport.control-updater-error/v1",
            "code": "control_updater_refused",
            "status": "outcome_unknown" if invoked else "not_executed",
        }) + b"\n")
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
