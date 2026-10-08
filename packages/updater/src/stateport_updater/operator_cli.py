"""Operator-side transport for the root-owned control updater command.

The operator account owns candidate release files and authorization bundles.
Only bounded public bytes cross the root boundary; the root helper receives no
caller-controlled filesystem path or arbitrary command argument.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence

from stateport_release import (
    canonical_json_bytes,
    embedded_predecessor_index,
    load_release_index,
    signature_bundle_name,
)

from . import cli
from .installed import AUTHORIZATION_BUNDLE_SCHEMA
from .safe_io import MAX_DOCUMENT_BYTES, _bounded, create_json


REQUEST_SCHEMA = "stateport.control-updater-command/v1"
OPERATOR_STATE_ROOT = Path("/var/lib/stateport-updater")
ROOT_COMMAND = (
    "/usr/bin/sudo",
    "-n",
    "/usr/local/libexec/stateport-execution-host-provision",
    "update",
)
MAX_REQUEST_BYTES = 64 * 1024 * 1024
MAX_RELEASE_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_BUNDLES = 256
MAX_MANIFESTS = 128
ALLOWED_COMMANDS = frozenset(
    {"health", "ready", "status", "check", "plan", "policy", "authorize", "apply", "rollback", "reconcile"}
)


class OperatorTransportRefusal(ValueError):
    """A non-disclosing operator transport refusal."""


def _refuse(message: str) -> OperatorTransportRefusal:
    return OperatorTransportRefusal(message)


def _bounded_json(path: Path) -> Any:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise _refuse("transport input is unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) & 0o077
        or observed.st_size > MAX_DOCUMENT_BYTES
    ):
        raise _refuse("transport input is not an operator-private file")
    try:
        value = json.loads(path.read_bytes())
        _bounded(value, label="operator transport input")
        return value
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise _refuse("transport input is malformed or oversized") from exc


def _file_bytes(path: Path, maximum: int, *, private: bool = False) -> bytes:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise _refuse("release transport file is unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or (private and stat.S_IMODE(observed.st_mode) & 0o077)
        or observed.st_size > maximum
    ):
        raise _refuse("release transport file is not operator-private")
    try:
        parent = path.parent.stat()
    except OSError as exc:
        raise _refuse("release transport directory is unavailable") from exc
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise _refuse("release transport directory is not operator-private")
    try:
        with path.open("rb") as stream:
            content = stream.read(maximum + 1)
        if len(content) > maximum:
            raise _refuse("release transport file exceeds its byte bound")
        return content
    except OSError as exc:
        raise _refuse("release transport file is unreadable") from exc


def _decode(value: object, maximum: int, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise _refuse(f"{label} is missing")
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error) as exc:
        raise _refuse(f"{label} is malformed") from exc
    if not result or len(result) > maximum:
        raise _refuse(f"{label} exceeds its bound")
    return result


def _replace_path(argv: list[str], option: str, value: str) -> list[str]:
    result: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == option:
            if index + 1 >= len(argv):
                raise _refuse(f"{option} has no value")
            result.extend((option, value))
            index += 2
            continue
        if token.startswith(option + "="):
            result.append(option + "=" + value)
        else:
            result.append(token)
        index += 1
    return result


def _parse_argv(raw: Sequence[str]) -> list[str]:
    argv = list(raw)
    if not argv or len(argv) > 64 or any(not isinstance(item, str) or len(item) > 1024 for item in argv):
        raise _refuse("updater command arguments are invalid")
    if any(item == "--state-root" or item.startswith("--state-root=") for item in argv):
        raise _refuse("state root is fixed by the operator transport")
    # Parse once locally to preserve the existing CLI's flags and semantics;
    # the fixed root is injected after this validation.
    try:
        parsed = cli._parser().parse_args(["--state-root", str(OPERATOR_STATE_ROOT), *argv])
    except SystemExit as exc:
        raise _refuse("updater command arguments are invalid") from exc
    if parsed.command not in ALLOWED_COMMANDS:
        raise _refuse("updater command is unsupported")
    return argv


def _release_transport(release_index: Path) -> dict[str, Any]:
    content = _file_bytes(release_index, MAX_RELEASE_BYTES)
    try:
        index = load_release_index(content)
    except Exception as exc:
        raise _refuse("release index is invalid") from exc
    source_root = release_index.parent
    signatures: list[tuple[Mapping[str, Any], bool]] = [
        (signature, False) for signature in index.document["signatures"]
    ]
    for image in index.document["signed"]["images"]:
        if isinstance(image.get("signature"), Mapping):
            signatures.append((image["signature"], False))
    predecessor = embedded_predecessor_index(index)
    if predecessor is not None:
        signatures.extend((signature, True) for signature in predecessor.document["signatures"])
    if len(signatures) > MAX_BUNDLES:
        raise _refuse("release signature transport exceeds its count bound")
    release = {
        "releaseIndex": json.loads(content),
        "expectedIndexDigest": index.index_digest,
        "expectedSignedPayloadDigest": index.signed_digest,
        "channel": index.channel,
        "targetId": str(index.document["signed"]["targets"][0]["targetId"]),
        "bundles": [],
        "imageManifests": [],
    }
    transport_bytes = len(canonical_json_bytes(release))

    def reserve(metadata: dict[str, Any], payload_size: int) -> None:
        nonlocal transport_bytes
        # Include base64 expansion, item metadata and a conservative comma.
        transport_bytes += len(canonical_json_bytes({**metadata, "contentBase64": ""})) + 4 * ((payload_size + 2) // 3) + 1
        if transport_bytes > MAX_REQUEST_BYTES // 2:
            raise _refuse("release transport exceeds its byte bound")

    if transport_bytes > MAX_REQUEST_BYTES // 2:
        raise _refuse("release transport exceeds its byte bound")
    bundles: list[dict[str, Any]] = []
    for signature, is_predecessor in signatures:
        name = signature_bundle_name(signature)
        if is_predecessor:
            candidates = (
                source_root / "predecessor-bundle" / name,
                source_root / "signatures" / name,
                source_root / name,
            )
        else:
            candidates = (
                source_root / name,
                source_root / "signatures" / name,
                source_root / "image-bundles" / name,
                source_root / "predecessor-bundle" / name,
            )
        source = next((item for item in candidates if item.is_file() and not item.is_symlink()), candidates[0])
        bundle = _file_bytes(source, MAX_BUNDLE_BYTES)
        reserve({"signature": dict(signature)}, len(bundle))
        bundles.append({"signature": dict(signature), "contentBase64": base64.b64encode(bundle).decode("ascii")})
    manifests: list[dict[str, Any]] = []
    for image in index.document["signed"]["images"]:
        signature = image.get("signature")
        if not isinstance(signature, Mapping) or signature.get("subjectKind") != "oci-manifest-blob":
            continue
        if len(manifests) >= MAX_MANIFESTS:
            raise _refuse("release image-manifest transport exceeds its count bound")
        digest = str(signature.get("subjectDigest"))
        source = source_root / "image-manifests" / f"{digest.removeprefix('sha256:')}.json"
        payload = _file_bytes(source, MAX_MANIFEST_BYTES)
        reserve({"imageId": str(image["imageId"]), "digest": digest}, len(payload))
        manifests.append({"imageId": str(image["imageId"]), "digest": digest, "contentBase64": base64.b64encode(payload).decode("ascii")})
    release["bundles"] = bundles
    release["imageManifests"] = manifests
    if len(canonical_json_bytes(release)) > MAX_REQUEST_BYTES // 2:
        raise _refuse("release transport exceeds its byte bound")
    return release


def _authorization(path: Path) -> dict[str, Any]:
    if path == Path("-"):
        raw = sys.stdin.buffer.read(MAX_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise _refuse("authorization exceeds its byte bound")
        try:
            value = json.loads(raw)
            _bounded(value, label="authorization")
        except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise _refuse("authorization is malformed") from exc
    else:
        value = _bounded_json(path)
    if not isinstance(value, Mapping) or value.get("schema") != AUTHORIZATION_BUNDLE_SCHEMA:
        raise _refuse("authorization is not an update bundle")
    return dict(value)


def _root_request(argv: list[str], release: Mapping[str, Any], authorization: Mapping[str, Any] | None) -> dict[str, Any]:
    return {
        "schema": REQUEST_SCHEMA,
        "argv": argv,
        "release": dict(release),
        "authorization": None if authorization is None else dict(authorization),
    }


def _invoke(request: Mapping[str, Any]) -> tuple[int, bytes]:
    payload = canonical_json_bytes(request)
    if len(payload) > MAX_REQUEST_BYTES:
        raise _refuse("control updater request exceeds its byte bound")
    try:
        completed = subprocess.run(
            list(ROOT_COMMAND), input=payload, capture_output=True, cwd="/", env={"PATH": "/usr/bin:/bin"}, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _refuse("root updater helper is unavailable") from exc
    if completed.returncode not in {0, 1, 3, 77} or len(completed.stdout) > MAX_DOCUMENT_BYTES:
        raise _refuse("root updater helper returned no bounded command result")
    if not completed.stdout:
        raise _refuse("root updater helper returned no command result")
    try:
        value = json.loads(completed.stdout)
    except (ValueError, UnicodeError) as exc:
        raise _refuse("root updater helper returned an invalid command result") from exc
    if not isinstance(value, Mapping):
        raise _refuse("root updater helper returned an invalid command result")
    return completed.returncode, completed.stdout


def main(argv: Sequence[str] | None = None) -> int:
    submitted = False
    try:
        command_argv = _parse_argv(sys.argv[1:] if argv is None else argv)
        parsed = cli._parser().parse_args(["--state-root", str(OPERATOR_STATE_ROOT), *command_argv])
        transformed = list(command_argv)
        release: dict[str, Any] = {}
        if parsed.command in {"check", "plan"} and not getattr(parsed, "rollback", False):
            release_path = parsed.release_index
            release = _release_transport(release_path)
            transformed = _replace_path(transformed, "--release-index", "/run/stateport-control-candidate/release-index.json")
        authorization: dict[str, Any] | None = None
        if parsed.command in {"apply", "rollback"}:
            authorization = _authorization(parsed.authorization)
            transformed = _replace_path(transformed, "--authorization", "-")
        if parsed.command == "authorize":
            output = parsed.output
            transformed = _replace_path(transformed, "--output", "-")
        else:
            output = None
        submitted = True
        code, response = _invoke(_root_request(transformed, release, authorization))
        if code:
            sys.stdout.buffer.write(response)
            return code
        if output is not None:
            try:
                value = json.loads(response)
                if not isinstance(value, Mapping) or value.get("schema") != AUTHORIZATION_BUNDLE_SCHEMA:
                    raise ValueError("root response is not an authorization bundle")
                if output == Path("-"):
                    sys.stdout.buffer.write(canonical_json_bytes(dict(value)) + b"\n")
                else:
                    create_json(output, dict(value), "update authorization bundle")
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise _refuse("root authorization response is invalid") from exc
            if output != Path("-"):
                sys.stdout.buffer.write(canonical_json_bytes({"schema": "stateport.updater-result/v1", "result": "authorization_reserved", "planId": parsed.plan_id}) + b"\n")
        else:
            sys.stdout.buffer.write(response)
        return 0
    except Exception:
        sys.stdout.buffer.write(canonical_json_bytes({
            "schema": "stateport.updater-error/v1", "code": "operator_transport_refused",
            "status": "outcome_unknown" if submitted else "not_executed",
        }) + b"\n")
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
