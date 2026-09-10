"""Authenticated root-to-control transport for fresh updater initialization.

The root-owned helper verifies its code manifest before importing this module.
Only public, signed release inputs cross stdin; the control process creates its
own private state and independently verifies those inputs before genesis.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import signal
import subprocess
from typing import Any, Mapping

from . import canonical_json_bytes, embedded_predecessor_index
from . import execution_host_provisioning as host
from .cosign import MAX_BUNDLE_BYTES, CosignVerifier, _check_bundle_bytes, bundle_slot, signature_bundle_name

MAX_REQUEST_BYTES = 64 * 1024 * 1024
CONTROL_UPDATER_ROOT = host.CONTROL_HOME + "/updater"
_CONTROL_PROGRAM = (
    'import runpy,sys; '
    'sys.path.insert(0,"/usr/local/lib/stateport/provisioning"); '
    'runpy.run_module("stateport_updater.bootstrap",run_name="__main__")'
)


def operator_context(*, accounts: host.Accounts, layout: host.HostLayout, require_accepted_unit: bool = True) -> dict[str, Any]:
    """Bind authenticated sudo identity to the durable accepted installation."""
    operator = host._workspace_operator(accounts)
    context, _ = host._workspace_json(layout, host.WORKSPACE_CONTEXT_PATH, uid=0, private=True)
    if (
        context.get("formatVersion") not in {
            host.WORKSPACE_CONTEXT_FORMAT, host.WORKSPACE_TERMINAL_CONTEXT_FORMAT,
            host.WORKSPACE_SOURCE_CONTEXT_FORMAT,
        }
        or context.get("contextDigest") != host.canonical_digest({
            key: value for key, value in context.items() if key != "contextDigest"
        })
        or context.get("operator") != operator
        or context.get("codeIdentity") != host._workspace_code_identity(layout)
        or context.get("controlUid") != host.CONTROL_UID
        or context.get("executionUid") != host.EXEC_UID
    ):
        raise host.ProvisioningRefusal("updater initialization requires current installed operator authority; migration or reprovision is required")
    control = accounts.user(host.CONTROL_USER)
    if control is None or (control.uid, control.gid, control.home) != (
        host.CONTROL_UID, host.CONTROL_GID, host.CONTROL_HOME,
    ):
        raise host.ProvisioningRefusal("installed control account identity changed")
    if not require_accepted_unit:
        # Subsequent accepted revisions intentionally change units. Operator
        # authority remains the root-owned immutable operator/code binding;
        # installed updater identity authenticates the current release.
        return context
    unit = context.get("webUnit")
    if not isinstance(unit, dict) or str(Path(str(unit.get("path", ""))).parent) != host.CONTROL_QUADLET_DIR:
        raise host.ProvisioningRefusal("accepted updater unit identity is unavailable")
    content, observed = host._read_regular_file(layout, unit["path"], step="updater-authority", maximum_bytes=1024 * 1024)
    if (observed is None or observed.st_uid != host.CONTROL_UID or observed.st_gid != host.CONTROL_GID
            or observed.st_nlink != 1 or observed.st_mode & 0o022
            or host.canonical_digest(content.decode()) != unit.get("contentDigest")):
        raise host.ProvisioningRefusal("accepted updater unit changed; trusted reprovision is required")
    fields = host._workspace_unit_fields(content.decode())
    if fields.get("releaseId") != context.get("releaseId") or fields.get("signedPayloadDigest") != context.get("signedPayloadDigest"):
        raise host.ProvisioningRefusal("accepted unit and installed release identity differ")
    return context


def bootstrap_request(args: Any, verified: Any, context: Mapping[str, Any]) -> dict[str, Any]:
    """Collect bounded public data; no caller paths become child authority."""
    index = verified.index
    if (context.get("releaseId") != str(index.release_id)
            or context.get("signedPayloadDigest") != index.signed_digest):
        raise host.ProvisioningRefusal("updater genesis differs from the accepted installed release")
    actor_id = getattr(args, "actor_id", None)
    if actor_id is None:
        actor_id = "local-owner-" + context["operator"]["user"]
    if not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 128:
        raise host.ProvisioningRefusal("updater installer actor identity is invalid")
    transport = Path(args.bundle_root)
    source = Path(args.release_index)
    if not transport.is_absolute() or not source.is_absolute():
        raise host.ProvisioningRefusal("updater release transport paths must be absolute")
    signatures = [(entry, "") for entry in index.document["signatures"]]
    signatures += [(image["signature"], "image-bundles") for image in index.document["signed"]["images"]]
    predecessor = embedded_predecessor_index(index)
    if predecessor is not None:
        signatures += [(entry, "predecessor-bundle") for entry in predecessor.document["signatures"]]
    if len(signatures) > 32:
        raise host.ProvisioningRefusal("updater signature transport exceeds its count bound")
    bundles = []
    total = 0
    for signature, subdirectory in signatures:
        name = signature_bundle_name(signature)
        candidates = [source.parent / subdirectory / name, transport / subdirectory / name,
                      source.parent / name, transport / name, bundle_slot(transport, signature)]
        candidate = next((path for path in candidates if path.is_file() and not path.is_symlink()), candidates[0])
        content, _ = host._read_regular_file(host.HostLayout(), str(candidate), step="updater-bundle", maximum_bytes=MAX_BUNDLE_BYTES)
        _check_bundle_bytes(content, signature)
        total += len(content)
        if total > MAX_REQUEST_BYTES // 2:
            raise host.ProvisioningRefusal("updater signature transport exceeds its byte bound")
        bundles.append({"signature": signature, "contentBase64": base64.b64encode(content).decode("ascii")})
    resolver = CosignVerifier(
        cosign=Path(host.ROOT_COSIGN_PATH), public_key=Path(host.ROOT_PUBLIC_KEY_PATH),
        identity=host.PinnedPublicKeyIdentity(host.ROOT_TRUST_KEY_FINGERPRINT, host.ROOT_TRUST_KEY_ID),
        bundle_root=transport,
    )
    manifests = []
    for image in index.document["signed"]["images"]:
        signature = image["signature"]
        if signature.get("subjectKind") != "oci-manifest-blob":
            continue
        content = resolver.resolve_local_image_manifest(image["imageId"], image["digest"])
        if content is None or len(content) > MAX_BUNDLE_BYTES:
            raise host.ProvisioningRefusal("exact updater image manifest is unavailable")
        total += len(content)
        if total > MAX_REQUEST_BYTES // 2:
            raise host.ProvisioningRefusal("updater public input transport exceeds its byte bound")
        manifests.append({"imageId": image["imageId"], "digest": image["digest"],
                          "contentBase64": base64.b64encode(content).decode("ascii")})
    request = {"schema": "stateport.control-updater-bootstrap/v1", "releaseIndex": index.document,
               "expectedIndexDigest": index.index_digest, "expectedSignedPayloadDigest": index.signed_digest,
               "channel": args.channel, "targetId": verified.target["targetId"], "operator": context["operator"], "actorId": actor_id,
               "bundles": bundles, "imageManifests": manifests}
    encoded = canonical_json_bytes(request)
    if len(encoded) > MAX_REQUEST_BYTES:
        raise host.ProvisioningRefusal("updater bootstrap request exceeds its byte bound")
    return json.loads(encoded)


def initialize(args: Any) -> dict[str, Any]:
    if os.geteuid() != 0 or os.environ.get("STATEPORT_ROOT_HELPER") != "1":
        raise host.ProvisioningRefusal("updater initialization requires the root-owned helper")
    accounts = host.SystemAccounts()
    context = operator_context(accounts=accounts, layout=host.HostLayout())
    verified = host._verify_cli(args)
    request = bootstrap_request(args, verified, context)
    # Re-read durable authority after source verification, immediately before
    # allowing the control account to create state. No inherited env or cwd.
    if operator_context(accounts=accounts, layout=host.HostLayout()) != context:
        raise host.ProvisioningRefusal("installed updater authority changed during verification")
    command = host._user_argv(host.CONTROL_USER, host.CONTROL_UID, host.CONTROL_HOME,
                              "/usr/sbin/nologin", ["/usr/bin/python3", "-I", "-c", _CONTROL_PROGRAM])
    result = _run_control_command(command, json.dumps(request).encode(), timeout=900)
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise host.ProvisioningRefusal("control-account updater genesis refused; retained state requires inspection")
    response = json.loads(result.stdout)
    if (not isinstance(response, dict) or response.get("schema") != "stateport.control-updater-genesis/v1"
            or response.get("status") != "initialized"
            or response.get("releaseId") != str(verified.index.release_id)
            or response.get("releaseIndexDigest") != verified.index.index_digest
            or response.get("signedPayloadDigest") != verified.index.signed_digest
            or any(re.fullmatch(r"sha256:[0-9a-f]{64}", str(response.get(name, ""))) is None
                   for name in ("installedIdentityDigest", "admissionDigest"))):
        raise host.ProvisioningRefusal("control-account updater genesis returned contradictory identity")
    return response


_CONTROL_COMMAND_PROGRAM = (
    'import runpy,sys; '
    'sys.path.insert(0,"/usr/local/lib/stateport/provisioning"); '
    'runpy.run_module("stateport_updater.control_cli",run_name="__main__")'
)


def _run_control_command(command: list[str], payload: bytes, *, timeout: int) -> subprocess.CompletedProcess:
    """Own a separate process group so timeout cannot abandon the control CLI."""
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=host._ROOT_COMMAND_ENV, cwd="/", start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(payload, timeout=timeout)
    except BaseException:
        # This process group was created by this call. Never signal the owner
        # session or a shared group, and reap the group leader before returning.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def execute_update(raw: bytes) -> tuple[int, bytes]:
    """Authenticate one operator command, then execute only as control."""
    if os.geteuid() != 0 or os.environ.get("STATEPORT_ROOT_HELPER") != "1":
        raise host.ProvisioningRefusal("updater command requires the root-owned helper")
    if len(raw) > MAX_REQUEST_BYTES:
        raise host.ProvisioningRefusal("updater command exceeds its byte bound")
    request = json.loads(raw)
    if (not isinstance(request, dict)
            or set(request) != {"schema", "argv", "release", "authorization"}
            or request["schema"] != "stateport.control-updater-command/v1"
            or not isinstance(request["argv"], list)
            or not 1 <= len(request["argv"]) <= 64
            or any(not isinstance(value, str) or len(value) > 4096 for value in request["argv"])):
        raise host.ProvisioningRefusal("updater command transport is malformed")
    accounts = host.SystemAccounts()
    context = operator_context(accounts=accounts, layout=host.HostLayout(), require_accepted_unit=False)
    request["operator"] = context["operator"]
    command = host._user_argv(host.CONTROL_USER, host.CONTROL_UID, host.CONTROL_HOME,
                             "/usr/sbin/nologin", ["/usr/bin/python3", "-I", "-c", _CONTROL_COMMAND_PROGRAM],
                             extra_environment={
                                 "STATEPORT_COSIGN": host.ROOT_COSIGN_PATH,
                                 "STATEPORT_QUADLET_ROOT": host.CONTROL_QUADLET_DIR,
                                 "STATEPORT_UPDATER_CONTROL_PLANE": "stateport_updater.control_plane:build",
                             })
    if operator_context(accounts=accounts, layout=host.HostLayout(), require_accepted_unit=False) != context:
        raise host.ProvisioningRefusal("installed operator authority changed during admission")
    result = _run_control_command(command, json.dumps(request).encode(), timeout=3600)
    if result.returncode not in {0, 1, 3, 77} or len(result.stdout) > 8 * 1024 * 1024:
        raise host.ProvisioningRefusal("control updater command failed without a bounded result")
    return result.returncode, result.stdout
