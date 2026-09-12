#!/usr/bin/env python3
"""Build StatePort OCI images twice through an exact committed source context.

The proof registry is task-owned, loopback-only, HTTP-explicit, and removed at
the end of the run. Every digest is observed from Podman output under an
external create-only evidence root; no digest file or materialized context may
be written into the checkout.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from typing import Any, Mapping, Sequence
from urllib.error import URLError
from urllib.request import urlopen

import yaml

from release_safe_io import (
    directory_identity,
    prepare_output_root,
    remove_tree_exact,
    safe_path,
    sha256_file,
    write_bytes_create_only,
    write_json_create_only,
)
from release_guard import require_guard


ROOT = Path(__file__).resolve().parents[1]
IMAGE_SET = ROOT / "images/image-set.v1.yaml"
BASE_IMAGES = ROOT / "config/container-base-images.yaml"
BUILD_INPUTS = ROOT / "config/container-build-inputs.yaml"
PODMAN = Path(os.environ.get("STATEPORT_PODMAN_PATH", shutil.which("podman") or "podman"))
BUILDER_DESCRIPTOR_ENV = "STATEPORT_RELEASE_BUILDER_DESCRIPTOR"
PROVIDER_MODE_ENV = "STATEPORT_PROVIDER_MODE"
PROVIDER_INPUTS = ROOT / "config/provider-runtime-inputs.yaml"
REGISTRY_IMAGE = (
    "docker.io/library/registry:2@"
    "sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DIGEST_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_LOOPBACK_REGISTRY = re.compile(r"^127\.0\.0\.1:([0-9]{1,5})$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
_PROVIDER_VERSION = re.compile(r"^codex-cli [0-9]+\.[0-9]+\.[0-9]+\+[0-9A-Za-z.-]+$")


class ReleaseBuildError(RuntimeError):
    pass


def load_provider_oci_input() -> dict[str, Any]:
    """Resolve the locked provider mode before builder or registry admission."""

    mode = os.environ.get(PROVIDER_MODE_ENV, "official-npm")
    if mode == "official-npm":
        return {"mode": mode, "image": "stateport-provider-empty"}
    if mode != "custom-oci":
        raise ReleaseBuildError(f"{PROVIDER_MODE_ENV} must be official-npm or custom-oci")
    try:
        codex = _load_yaml(PROVIDER_INPUTS)["codex"]
        oci = codex["oci"]
        if oci.get("enabled") is not True:
            raise ValueError("custom provider OCI input is not admitted")
        image = oci["image"]
        if not isinstance(image, str) or _DIGEST_REFERENCE.fullmatch(image) is None:
            raise ValueError("custom provider image must be an exact digest reference")
        fields = {
            "manifestDigest": oci["manifestDigest"],
            "platformManifestDigest": oci["platformManifestDigest"],
            "version": oci["version"],
            "bubblewrapVersion": oci["bubblewrapVersion"],
            "ripgrepVersion": oci["ripgrepVersion"],
            "sourceCommit": oci["sourceCommit"],
            "sourceArchiveDigest": oci["sourceArchiveDigest"],
            "buildContextDigest": oci["buildContextDigest"],
        }
        for key, value in fields.items():
            if not isinstance(value, str) or not value:
                raise ValueError(f"custom provider input lacks {key}")
        if _DIGEST.fullmatch(fields["manifestDigest"]) is None:
            raise ValueError("custom provider manifest digest is invalid")
        if _DIGEST.fullmatch(fields["platformManifestDigest"]) is None:
            raise ValueError("custom provider platform manifest digest is invalid")
        if _PROVIDER_VERSION.fullmatch(fields["version"]) is None:
            raise ValueError("custom provider version is invalid")
        for key in ("sourceArchiveDigest", "buildContextDigest"):
            if _DIGEST.fullmatch(fields[key]) is None:
                raise ValueError(f"custom provider {key} is invalid")
        if re.fullmatch(r"[0-9a-f]{40}", fields["sourceCommit"]) is None:
            raise ValueError("custom provider source commit is invalid")
        if fields["sourceCommit"] != str(codex["source"]["commit"]):
            raise ValueError("custom provider source commit differs from pinned upstream")
        if image.rsplit("@", 1)[1] != fields["manifestDigest"]:
            raise ValueError("custom provider image digest differs from manifestDigest")
        artifacts = oci["artifacts"]
        if not isinstance(artifacts, Mapping):
            raise ValueError("custom provider artifact pins are missing")
        artifact_args = {
            "codexDigest": artifacts["codexDigest"],
            "bubblewrapDigest": artifacts["bubblewrapDigest"],
            "ripgrepDigest": artifacts["ripgrepDigest"],
        }
        for key, value in artifact_args.items():
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                raise ValueError(f"custom provider artifact digest is invalid: {key}")
        licenses = oci["licenses"]
        if not isinstance(licenses, list):
            raise ValueError("custom provider license contract is missing")
        if tuple(licenses) != ("LICENSE", "NOTICE", "BUBBLEWRAP-LICENSE", "BUBBLEWRAP-NOTICE"):
            raise ValueError("custom provider license contract is incomplete")
        return {
            "mode": mode,
            "image": image,
            **fields,
            **artifact_args,
            "licenses": list(licenses),
        }
    except (KeyError, TypeError, ValueError, OSError, yaml.YAMLError) as exc:
        raise ReleaseBuildError(f"custom provider OCI input is not admissible: {exc}") from exc


def provider_build_args(provider_input: Mapping[str, Any] | None) -> list[str]:
    """Return exact build args shared by both real provider consumers."""

    selected = provider_input or {"mode": "official-npm", "image": "stateport-provider-empty"}
    args = [
        "--build-arg", f"STATEPORT_PROVIDER_MODE={selected['mode']}",
        "--build-arg", f"STATEPORT_PROVIDER_IMAGE={selected['image']}",
    ]
    if selected["mode"] == "custom-oci":
        names = {
            "manifestDigest": "MANIFEST_DIGEST",
            "platformManifestDigest": "PLATFORM_MANIFEST_DIGEST",
            "version": "VERSION",
            "bubblewrapVersion": "BUBBLEWRAP_VERSION",
            "ripgrepVersion": "RIPGREP_VERSION",
            "sourceCommit": "SOURCE_COMMIT",
            "sourceArchiveDigest": "SOURCE_ARCHIVE_DIGEST",
            "buildContextDigest": "BUILD_CONTEXT_DIGEST",
            "codexDigest": "CODEX_DIGEST",
            "bubblewrapDigest": "BUBBLEWRAP_DIGEST",
            "ripgrepDigest": "RIPGREP_DIGEST",
        }
        for key, name in names.items():
            args.extend(["--build-arg", f"STATEPORT_PROVIDER_{name}={selected[key]}"])
    return args


@dataclass(frozen=True)
class SourceIdentity:
    commit: str
    tree: str
    version: str
    created: str
    source_date_epoch: int


@dataclass(frozen=True)
class ControllerIdentity:
    commit: str
    tree: str
    payloadRelationship: str


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path = ROOT,
    capture: bool = False,
    stdout: Any | None = None,
    timeout: int = 7200,
) -> str:
    completed = subprocess.run(
        list(arguments),
        cwd=cwd,
        check=False,
        capture_output=capture and stdout is None,
        stdout=stdout,
        stderr=subprocess.PIPE if stdout is not None else None,
        text=stdout is None,
        timeout=timeout,
        shell=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() if isinstance(completed.stderr, str) else ""
        detail = f": {stderr}" if stderr else ""
        raise ReleaseBuildError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}{detail}"
        )
    if capture and isinstance(completed.stdout, str):
        return completed.stdout.strip()
    return ""


def _load_yaml(path: Path) -> Mapping[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ReleaseBuildError(f"manifest is not a mapping: {path}")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _release_identities(
    version: str,
    source_commit: str | None = None,
    *,
    repository: Path = ROOT,
) -> tuple[SourceIdentity, ControllerIdentity]:
    if _VERSION.fullmatch(version) is None:
        raise ReleaseBuildError("release image version is not a bounded semantic version")
    dirty = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
        capture=True,
    )
    if dirty:
        raise ReleaseBuildError(
            "release image build requires an exact clean committed tree, including untracked paths"
        )
    controller_commit = _run(["git", "rev-parse", "HEAD"], cwd=repository, capture=True)
    controller_tree = _run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=repository, capture=True
    )
    if (
        re.fullmatch(r"[0-9a-f]{40}", controller_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", controller_tree) is None
    ):
        raise ReleaseBuildError("Git source identity is not an exact SHA-1 commit and tree")
    commit = controller_commit if source_commit is None else source_commit
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ReleaseBuildError("frozen release payload must name one exact full commit")
    observed_commit = _run(
        ["git", "rev-parse", "--verify", f"{commit}^{{commit}}"],
        cwd=repository,
        capture=True,
    )
    if observed_commit != commit:
        raise ReleaseBuildError("frozen release payload commit did not resolve exactly")
    try:
        _run(
            ["git", "merge-base", "--is-ancestor", commit, controller_commit],
            cwd=repository,
        )
    except ReleaseBuildError as exc:
        raise ReleaseBuildError(
            "frozen release payload commit must be an ancestor of current controller HEAD"
        ) from exc
    tree = _run(
        ["git", "rev-parse", "--verify", f"{commit}^{{tree}}"],
        cwd=repository,
        capture=True,
    )
    if re.fullmatch(r"[0-9a-f]{40}", tree) is None:
        raise ReleaseBuildError("frozen release payload tree is not an exact SHA-1 tree")
    epoch = int(
        _run(
            ["git", "show", "-s", "--format=%ct", commit],
            cwd=repository,
            capture=True,
        )
    )
    created = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        SourceIdentity(commit, tree, version, created, epoch),
        ControllerIdentity(
            controller_commit,
            controller_tree,
            "equal" if commit == controller_commit else "payload-is-ancestor",
        ),
    )


def source_identity(
    version: str,
    source_commit: str | None = None,
    *,
    repository: Path = ROOT,
) -> SourceIdentity:
    return _release_identities(version, source_commit, repository=repository)[0]


def _controller_attestation(controller: ControllerIdentity) -> dict[str, Any]:
    return {
        **asdict(controller),
        "buildTool": {
            "path": "scripts/build_release_images.py",
            "digest": sha256_file(Path(__file__).resolve()),
        },
        "buildInputs": {
            "path": BUILD_INPUTS.relative_to(ROOT).as_posix(),
            "digest": sha256_file(BUILD_INPUTS),
        },
    }


def _load_builder_descriptor() -> tuple[Mapping[str, Any], str]:
    descriptor_name = os.environ.get(BUILDER_DESCRIPTOR_ENV)
    if not descriptor_name:
        raise ReleaseBuildError(
            f"release image build requires {BUILDER_DESCRIPTOR_ENV} with an exact builder artifact"
        )
    descriptor_path = Path(descriptor_name)
    if descriptor_path.is_symlink() or not descriptor_path.is_file():
        raise ReleaseBuildError("release builder descriptor is unavailable or symlinked")
    raw = descriptor_path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseBuildError("release builder descriptor is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReleaseBuildError("release builder descriptor is not an object")
    if value.get("formatVersion") != "stateport.release-builder-descriptor/v1":
        raise ReleaseBuildError("release builder descriptor has an unsupported format")
    return value, "sha256:" + hashlib.sha256(raw).hexdigest()


def verify_podman_builder() -> dict[str, Any]:
    inputs = _load_yaml(BUILD_INPUTS)
    expected = inputs["builder"]
    descriptor, descriptor_digest = _load_builder_descriptor()
    executable = Path(str(descriptor.get("executablePath", PODMAN)))
    if os.environ.get("STATEPORT_PODMAN_PATH") and executable != PODMAN:
        raise ReleaseBuildError("builder descriptor executable does not match STATEPORT_PODMAN_PATH")
    if executable.is_symlink() or not executable.is_file():
        raise ReleaseBuildError("pinned Podman builder path is unavailable or symlinked")
    digest = sha256_file(executable)
    if digest != str(descriptor.get("executableDigest")):
        raise ReleaseBuildError("Podman builder executable does not match its descriptor")
    artifact = descriptor.get("artifact")
    if not isinstance(artifact, Mapping):
        raise ReleaseBuildError("Podman builder descriptor has no artifact provenance")
    if not isinstance(artifact.get("uri"), str) or not str(artifact.get("uri")):
        raise ReleaseBuildError("Podman builder artifact has no immutable URI")
    if artifact.get("digest") != digest:
        raise ReleaseBuildError("Podman builder artifact digest does not match its executable")
    if descriptor.get("name") != str(expected["name"]):
        raise ReleaseBuildError("Podman builder name does not match container build inputs")
    value = json.loads(_run([str(executable), "version", "--format", "json"], capture=True))
    version = str(value["Client"]["Version"])
    if version != str(descriptor.get("version")):
        raise ReleaseBuildError("Podman builder version does not match container build inputs")
    if version != str(expected["observedVersion"]):
        raise ReleaseBuildError("Podman builder version does not match container build inputs")
    info = json.loads(_run([str(executable), "info", "--format", "json"], capture=True))
    if not isinstance(info, Mapping):
        raise ReleaseBuildError("Podman builder returned an invalid host observation")
    host = info.get("host")
    store = info.get("store")
    if not isinstance(host, Mapping) or not isinstance(store, Mapping):
        raise ReleaseBuildError("Podman builder omitted host or storage observations")
    security = host.get("security")
    if not isinstance(security, Mapping):
        raise ReleaseBuildError("Podman builder omitted its security observation")
    observed_platform = f"{host.get('os')}/{host.get('arch')}"
    if (
        security.get("rootless") is not True
        or host.get("cgroupVersion") != "v2"
        or observed_platform != "linux/amd64"
        or not isinstance(store.get("graphDriverName"), str)
    ):
        raise ReleaseBuildError(
            "release builder requires rootless Podman, cgroup v2, linux/amd64, and an observed storage driver"
        )
    return {
        "name": "podman",
        "version": version,
        "executablePath": str(executable),
        "executableDigest": digest,
        "descriptorDigest": descriptor_digest,
        "artifact": {
            "uri": str(artifact["uri"]),
            "digest": digest,
        },
        "compatibilityFloor": str(expected["compatibilityFloor"]),
        "rootless": True,
        "cgroupVersion": "v2",
        "platform": observed_platform,
        "graphDriver": str(store["graphDriverName"]),
        "network": {
            "mode": "private",
            "enforcedBy": "podman-build---network=private",
            "hostNetwork": False,
            "outboundDependencyFetch": True,
        },
    }


def validate_registry_endpoint(registry: str) -> int:
    match = _LOOPBACK_REGISTRY.fullmatch(registry)
    if match is None:
        raise ReleaseBuildError("proof registry must be an explicit IPv4 loopback host and port")
    port = int(match.group(1))
    if not 1024 <= port <= 65535:
        raise ReleaseBuildError("proof registry port must be in the unprivileged range")
    return port


def validate_definitions() -> Mapping[str, Any]:
    image_set = _load_yaml(IMAGE_SET)
    base_manifest = _load_yaml(BASE_IMAGES)
    allowed_bases = {base["reference"] for base in base_manifest["images"].values()}
    for reference in allowed_bases:
        if not _DIGEST_REFERENCE.fullmatch(str(reference)):
            raise ReleaseBuildError(f"base image is not digest-pinned: {reference}")
    for image_id, image in image_set["images"].items():
        containerfile = ROOT / image["containerfile"]
        if not containerfile.is_file():
            raise ReleaseBuildError(f"missing Containerfile for {image_id}")
        text = containerfile.read_text(encoding="utf-8")
        stages: set[str] = set()
        for line in text.splitlines():
            if not line.startswith("FROM "):
                continue
            parts = line.split()
            reference = parts[1]
            if reference == "${STATEPORT_PROVIDER_IMAGE}" and (
                image_id not in {"stateport-web", "stateport-dev-workspace"}
                or parts != ["FROM", reference, "AS", "stateport-provider"]
                or "stateport-provider-empty" not in stages
                or not text.startswith("ARG STATEPORT_PROVIDER_IMAGE=stateport-provider-empty\n")
            ):
                raise ReleaseBuildError(f"{image_id} contains an invalid provider stage: {line}")
            if reference not in allowed_bases and reference not in stages and reference != "${STATEPORT_PROVIDER_IMAGE}":
                raise ReleaseBuildError(f"{image_id} contains an unapproved FROM: {line}")
            if len(parts) >= 4 and parts[2].upper() == "AS":
                stages.add(parts[3])
        if "USER " + str(image["runtimeUser"]) not in text:
            raise ReleaseBuildError(f"{image_id} does not declare its runtime user")
        if image_id in {"stateport-api", "stateport-worker"} and re.search(
            r"\bpodman\b|podman\.sock", text, re.I
        ):
            raise ReleaseBuildError(f"{image_id} must not contain Podman or a socket reference")
    placements = image_set.get("componentPlacements")
    if not isinstance(placements, Mapping) or set(placements) != {
        "stateport-preview-gateway",
        "stateport-updater",
    }:
        raise ReleaseBuildError("release image set lacks the exact safe co-location contract")
    expected_placements = {
        "stateport-preview-gateway": {
            "imageId": "stateport-web",
            "trustDomain": "control",
            "processModel": "same-origin-web-process",
            "engineSocketAccess": "none",
            "networkAuthority": "authenticated-stateport-route-only",
            "readiness": "packaging-boundary-only-runtime-delivered-by-slice-c",
        },
        "stateport-updater": {
            "imageId": "stateport-worker",
            "trustDomain": "maintenance",
            "processModel": "separate-maintenance-service-shared-immutable-image",
            "engineSocketAccess": "none",
            "mutationAuthority": "typed-signed-update-plan-only",
            "readiness": "packaging-boundary-only-runtime-delivered-by-updater-slice",
        },
    }
    if placements != expected_placements:
        raise ReleaseBuildError(
            "preview/updater image placement crosses its approved trust boundary"
        )
    for component, placement in placements.items():
        image_id = placement["imageId"]
        if image_id not in image_set["images"]:
            raise ReleaseBuildError(f"{component} names an unavailable shared image")
        containerfile = (ROOT / image_set["images"][image_id]["containerfile"]).read_text(
            encoding="utf-8"
        )
        if re.search(r"podman\.sock|/var/run/docker\.sock", containerfile, re.I):
            raise ReleaseBuildError(f"{component} shared image exposes a container-engine socket")
    blocked = image_set.get("blockedComponents") or {}
    if "stateport-execution-host" in blocked:
        raise ReleaseBuildError(
            "execution host block must be lifted by a real typed daemon entrypoint"
        )
    host = image_set["images"].get("stateport-execution-host")
    if not isinstance(host, Mapping) or host.get("role") != "stable-host-service":
        raise ReleaseBuildError(
            "execution host must ship as a dedicated stable-host-service image"
        )
    host_containerfile = (ROOT / host["containerfile"]).read_text(encoding="utf-8")
    if 'CMD ["python3", "-m", "stateport_execution_host"]' not in host_containerfile:
        raise ReleaseBuildError(
            "execution host image lacks its typed daemon entrypoint"
        )
    if re.search(r"/run/podman/podman\.sock|/var/run/docker\.sock|/run/docker\.sock", host_containerfile):
        raise ReleaseBuildError(
            "execution host image references a control-plane engine socket"
        )
    engine_sockets = set(
        re.findall(r"/[A-Za-z0-9._/-]*(?:podman|docker)\.sock", host_containerfile)
    )
    if engine_sockets - {"/run/stateport-engine/podman.sock"}:
        raise ReleaseBuildError(
            "execution host engine access must be confined to the exec-user socket: "
            f"{sorted(engine_sockets)}"
        )
    return image_set


def verify_locked_build_inputs() -> Mapping[str, Any]:
    """Refuse a governed build whose recorded input digests drifted.

    ``container-build-inputs.yaml`` is the byte-exact reproducibility lock.
    A stale recorded digest previously survived into a governed build, so
    this cheap source-only preflight runs before any registry, context,
    base-image pull, or image work.
    """
    inputs = _load_yaml(BUILD_INPUTS)
    locks = inputs.get("locks")
    if not isinstance(locks, Mapping) or not locks:
        raise ReleaseBuildError("container build inputs have no exact source locks")
    for name, lock in sorted(locks.items()):
        if not isinstance(lock, Mapping):
            raise ReleaseBuildError(f"build-input lock {name} is not a mapping")
        rel = str(lock.get("path", ""))
        digest = lock.get("digest")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ReleaseBuildError(f"build-input lock {name} has no exact sha256 digest")
        path = ROOT / rel
        if not path.is_file():
            raise ReleaseBuildError(f"build-input lock {name} is missing {rel}")
        actual = sha256_file(path)
        if actual != digest:
            raise ReleaseBuildError(
                f"build-input lock {name} drifted: {rel} is {actual}, locked {digest}"
            )
    definitions = inputs.get("definitions")
    if not isinstance(definitions, Mapping) or not definitions:
        raise ReleaseBuildError("container build inputs define no locked definitions")
    for rel, digest in sorted(definitions.items()):
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ReleaseBuildError(f"locked definition {rel} has no exact sha256 digest")
        path = ROOT / str(rel)
        if not path.is_file():
            raise ReleaseBuildError(f"locked definition is missing: {rel}")
        actual = sha256_file(path)
        if actual != digest:
            raise ReleaseBuildError(
                f"locked definition drifted: {rel} is {actual}, locked {digest}"
            )
    return inputs


def verify_frozen_payload_build_contract(
    source_commit: str, inputs: Mapping[str, Any]
) -> None:
    """Keep controller-only commits from changing frozen image inputs.

    The build tool itself may advance after ``source_commit`` and is attested
    separately. Every file that defines or locks image bytes must still match
    the selected payload commit exactly; otherwise choosing an ancestor could
    accidentally validate one definition while archiving another.
    """

    paths = {
        BUILD_INPUTS.relative_to(ROOT).as_posix(),
        IMAGE_SET.relative_to(ROOT).as_posix(),
        BASE_IMAGES.relative_to(ROOT).as_posix(),
    }
    locks = inputs.get("locks")
    definitions = inputs.get("definitions")
    if not isinstance(locks, Mapping) or not isinstance(definitions, Mapping):
        raise ReleaseBuildError("container build inputs lack frozen contract paths")
    paths.update(str(item.get("path", "")) for item in locks.values() if isinstance(item, Mapping))
    paths.update(str(path) for path in definitions)
    for relative in sorted(paths):
        path = PurePosixPath(relative)
        if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise ReleaseBuildError(f"frozen build contract contains an unsafe path: {relative!r}")
        try:
            frozen_blob = _run(
                ["git", "rev-parse", "--verify", f"{source_commit}:{relative}"],
                capture=True,
            )
        except ReleaseBuildError as exc:
            raise ReleaseBuildError(
                f"frozen release payload is missing build contract path: {relative}"
            ) from exc
        current_blob = _run(["git", "hash-object", "--", relative], capture=True)
        if frozen_blob != current_blob:
            raise ReleaseBuildError(
                f"current build contract drifted from frozen payload: {relative}"
            )


def governor_cgroup_parent(
    *, proc_cgroup: Path = Path("/proc/self/cgroup"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> str:
    """Bind container children to the actual bounded governor service, not a slice."""
    try:
        lines = proc_cgroup.read_text().splitlines()
        if len(lines) != 1 or not lines[0].startswith("0::/"):
            raise ValueError("not a unified cgroup v2 membership")
        membership = lines[0][3:]
        match = re.fullmatch(
            r"(/user\.slice/user-[0-9]+\.slice/user@[0-9]+\.service/"
            r"stateport\.slice/stateport-heavy\.slice/stateport-heavy-[0-9]+-[0-9]+\.service)(/[^.][^:]*)?",
            membership,
        )
        if match is None or ".." in PurePosixPath(membership).parts:
            raise ValueError("not inside a governor service")
        parent = match.group(1)
        controls = cgroup_root / parent.lstrip("/")
        memory = controls.joinpath("memory.max").read_text().strip()
        quota, period = controls.joinpath("cpu.max").read_text().split()
        if int(memory) <= 0 or int(quota) <= 0 or int(period) <= 0:
            raise ValueError("unbounded governor controls")
        return parent
    except (OSError, ValueError) as exc:
        raise ReleaseBuildError(
            "release image execution requires a governor service with finite memory.max and cpu.max"
        ) from exc


def build_cgroup_path(parent: str, *, digest_file: Path) -> str:
    """Buildah passes this directly to OCI; never target the occupied service.

    The create-only evidence root plus image/build digest filename gives every
    RUN build its own path while keeping the recorded plan and execution equal.
    Podman run instead creates its own child below its supplied parent.
    """
    key = hashlib.sha256(str(digest_file).encode("utf-8")).hexdigest()[:24]
    return f"{parent}/stateport-build-{key}"


def base_pull_commands(provider_input: Mapping[str, Any] | None = None) -> list[list[str]]:
    base_manifest = _load_yaml(BASE_IMAGES)
    commands = [
        [str(PODMAN), "pull", "--platform", "linux/amd64", str(base["reference"])]
        for _, base in sorted(base_manifest["images"].items())
    ]
    if provider_input and provider_input.get("mode") == "custom-oci":
        commands.append([
            str(PODMAN), "pull", "--platform", "linux/amd64", str(provider_input["image"])
        ])
    return commands


def build_commands(
    image_set: Mapping[str, Any],
    identity: SourceIdentity,
    *,
    registry: str,
    context_root: Path,
    digest_root: Path,
    cgroup_parent: str | None = None,
    provider_input: Mapping[str, Any] | None = None,
) -> list[list[str]]:
    validate_registry_endpoint(registry)
    if not context_root.is_absolute() or not digest_root.is_absolute():
        raise ReleaseBuildError(
            "committed context and digest roots must be absolute external paths"
        )
    if (
        ROOT == context_root
        or ROOT in context_root.parents
        or ROOT == digest_root
        or ROOT in digest_root.parents
    ):
        raise ReleaseBuildError(
            "release context and digest files must remain outside the repository"
        )
    commands: list[list[str]] = []
    github_token = os.environ.get("STATEPORT_GITHUB_TOKEN")
    for image_id, image in image_set["images"].items():
        for build_number in (1, 2):
            tag = f"{registry}/stateport-alpha/{image_id}:{identity.version}-build{build_number}"
            digest_file = digest_root / f"{image_id}-build{build_number}.digest"
            command = [
                str(PODMAN),
                *(["--cgroup-manager=cgroupfs"] if cgroup_parent else []),
                "build",
                *(["--cgroup-parent", build_cgroup_path(cgroup_parent, digest_file=digest_file), "--isolation=oci"] if cgroup_parent else []),
                "--no-cache",
                "--pull=never",
                "--network=private",
            ]
            if github_token:
                command.extend(["--secret", "id=github_token,env=STATEPORT_GITHUB_TOKEN"])
            command.extend([
                # Docker manifest format: the OCI image spec has no
                # Healthcheck field, and buildah silently discards
                # HEALTHCHECK instructions in the default OCI format.
                # Release images must carry their declared healthchecks.
                "--format",
                "docker",
                "--platform",
                "linux/amd64",
                "--timestamp",
                str(identity.source_date_epoch),
                "--build-arg",
                f"STATEPORT_BUILD_SOURCE_COMMIT={identity.commit}",
                "--build-arg",
                f"STATEPORT_BUILD_SOURCE_TREE={identity.tree}",
                "--build-arg",
                "STATEPORT_BUILD_SOURCE_REF=detached-release-context",
                "--build-arg",
                "STATEPORT_BUILD_SOURCE_DIRTY=false",
                "--build-arg",
                f"STATEPORT_BUILD_SOURCE_DATE_EPOCH={identity.source_date_epoch}",
                "--build-arg",
                f"STATEPORT_BUILD_VERSION={identity.version}",
                "--build-arg",
                f"STATEPORT_BUILD_CREATED={identity.created}",
                "--build-arg",
                "STATEPORT_BUILD_ADAPTER=podman-rootless-release-build",
                *provider_build_args(provider_input),
                "-f",
                str(context_root / image["containerfile"]),
                "-t",
                tag,
                str(context_root),
            ])
            commands.append(command)
            commands.append(
                [
                    str(PODMAN),
                    "push",
                    "--tls-verify=false",
                    "--digestfile",
                    str(digest_file),
                    # Pin docker manifest format so the accepted registry
                    # digest is independent of the source store's manifest
                    # type and matches the retained OCI archive below.
                    # Podman re-serializes manifest and config on every
                    # push; only the same target format yields the same
                    # digest.
                    "--format",
                    "docker",
                    tag,
                    f"docker://{tag}",
                ]
            )
    return commands


def _safe_extract_git_archive(archive: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, mode="r:") as bundle:
        members = bundle.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or any(part in {"", ".", ".."} for part in path.parts)
                or not (member.isdir() or member.isfile())
            ):
                raise ReleaseBuildError(f"Git archive contains an unsafe entry: {member.name!r}")
        bundle.extractall(destination, members=members, filter="data")


def materialize_committed_context(
    output: Path, identity: SourceIdentity
) -> tuple[Path, dict[str, str]]:
    archive = safe_path(output, "source-context.tar")
    with archive.open("xb") as stream:
        _run(["git", "archive", "--format=tar", identity.commit], stdout=stream)
        stream.flush()
        os.fsync(stream.fileno())
    context = safe_path(output, "source-context")
    if context.exists() or context.is_symlink():
        raise ReleaseBuildError("materialized source context already exists")
    _safe_extract_git_archive(archive, context)
    return context, {
        "materialization": "git-archive-exact-commit",
        "commit": identity.commit,
        "tree": identity.tree,
        "archiveDigest": sha256_file(archive),
    }


def _image_observation(reference: str) -> dict[str, Any]:
    values = json.loads(_run([str(PODMAN), "image", "inspect", reference], capture=True))
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], Mapping):
        raise ReleaseBuildError(f"Podman returned an invalid image observation for {reference}")
    value = values[0]
    digests: set[str] = set()
    primary_digest = value.get("Digest")
    if isinstance(primary_digest, str) and _DIGEST.fullmatch(primary_digest):
        digests.add(primary_digest)
    for item in value.get("RepoDigests") or []:
        if isinstance(item, str) and "@" in item:
            digest = item.rsplit("@", 1)[-1]
            if _DIGEST.fullmatch(digest):
                digests.add(digest)
    image_id = str(value.get("Id", ""))
    if not image_id:
        raise ReleaseBuildError(f"Podman image observation has no image ID: {reference}")
    return {
        "imageId": image_id,
        "digest": primary_digest,
        "observedDigests": sorted(digests),
        "os": value.get("Os"),
        "architecture": value.get("Architecture"),
        "variant": value.get("Variant"),
    }


def pull_and_verify_base_images(
    provider_input: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    manifest = _load_yaml(BASE_IMAGES)
    observed: list[dict[str, Any]] = []
    for base_id, base in sorted(manifest["images"].items()):
        reference = str(base["reference"])
        _run([str(PODMAN), "pull", "--platform", "linux/amd64", reference])
        index_digest = str(base["indexDigest"])
        platform_digest = str(base["platformManifestDigest"])
        platform_reference = reference.rsplit("@", 1)[0] + "@" + platform_digest
        index_observation = _image_observation(reference)
        platform_observation = _image_observation(platform_reference)
        required_digests = {index_digest, platform_digest}
        if (
            reference.rsplit("@", 1)[-1] != index_digest
            or index_observation["digest"] != index_digest
            or platform_observation["digest"] != platform_digest
            or not required_digests.issubset(index_observation["observedDigests"])
            or not required_digests.issubset(platform_observation["observedDigests"])
            or index_observation["imageId"] != platform_observation["imageId"]
            or (index_observation["os"], index_observation["architecture"]) != ("linux", "amd64")
            or (platform_observation["os"], platform_observation["architecture"])
            != ("linux", "amd64")
        ):
            raise ReleaseBuildError(
                f"pulled base image does not bind its exact linux/amd64 index and platform manifests: {base_id}"
            )
        observed.append(
            {
                "baseId": base_id,
                "reference": reference,
                "indexDigest": index_digest,
                "platformReference": platform_reference,
                "platformManifestDigest": platform_digest,
                "platform": "linux/amd64",
                "imageId": index_observation["imageId"],
                "indexObservation": index_observation,
                "platformObservation": platform_observation,
                "verification": "exact-index-and-platform-manifest",
            }
        )
    if provider_input and provider_input.get("mode") == "custom-oci":
        reference = str(provider_input["image"])
        _run([str(PODMAN), "pull", "--platform", "linux/amd64", reference])
        provider_observation = _image_observation(reference)
        expected = str(provider_input["manifestDigest"])
        platform_digest = str(provider_input["platformManifestDigest"])
        if expected not in provider_observation["observedDigests"]:
            raise ReleaseBuildError("custom provider index digest was not observed after pull")
        platform_reference = reference.rsplit("@", 1)[0] + "@" + platform_digest
        platform_observation = _image_observation(platform_reference)
        if (
            platform_observation["digest"] != platform_digest
            or provider_observation["digest"] != expected
            or provider_observation["imageId"] != platform_observation["imageId"]
            or not {expected, platform_digest}.issubset(provider_observation["observedDigests"])
            or not {expected, platform_digest}.issubset(platform_observation["observedDigests"])
            or (provider_observation["os"], provider_observation["architecture"]) != ("linux", "amd64")
            or platform_observation["os"] != "linux"
            or platform_observation["architecture"] != "amd64"
        ):
            raise ReleaseBuildError("custom provider lacks the reviewed linux/amd64 platform manifest")
        observed.append({
            "baseId": "stateport-provider",
            "reference": reference,
            "indexDigest": expected,
            "platformManifestDigest": platform_digest,
            "imageId": provider_observation["imageId"],
            "verification": "exact-reviewed-provider-manifest-digest",
        })
    return observed


def _container_exists(name: str) -> bool:
    completed = subprocess.run(
        [str(PODMAN), "container", "exists", name],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    if completed.returncode not in {0, 1}:
        raise ReleaseBuildError("Podman could not classify the proof registry container")
    return completed.returncode == 0


def start_local_registry(
    registry: str,
    identity: SourceIdentity,
    *,
    storage: Path,
    registry_base: Mapping[str, Any],
    cgroup_parent: str | None = None,
) -> dict[str, Any]:
    port = validate_registry_endpoint(registry)
    name = f"stateport-release-registry-{identity.commit[:12]}-{os.getpid()}"
    if _container_exists(name):
        raise ReleaseBuildError(f"task-owned registry container already exists: {name}")
    if storage.exists() or storage.is_symlink():
        raise ReleaseBuildError("task-owned registry storage must be create-only")
    storage.mkdir(mode=0o700)
    storage_identity = directory_identity(storage)
    live_registry_image = _image_observation(REGISTRY_IMAGE)
    if (
        registry_base.get("baseId") != "registry-2"
        or registry_base.get("reference") != REGISTRY_IMAGE
        or registry_base.get("verification") != "exact-index-and-platform-manifest"
        or registry_base.get("imageId") != live_registry_image["imageId"]
        or registry_base.get("indexDigest") not in live_registry_image["observedDigests"]
        or registry_base.get("platformManifestDigest") not in live_registry_image["observedDigests"]
        or (live_registry_image["os"], live_registry_image["architecture"]) != ("linux", "amd64")
    ):
        raise ReleaseBuildError("proof registry image is not the pre-pulled qualified base")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ReleaseBuildError(f"proof registry port is already in use: {registry}") from exc
    container_id = _run(
        [
            str(PODMAN),
            *(["--cgroup-manager=cgroupfs"] if cgroup_parent else []),
            "run",
            *(["--cgroup-parent", cgroup_parent] if cgroup_parent else []),
            "--pull=never",
            "--detach",
            "--name",
            name,
            "--label",
            "io.stateport.managed=true",
            "--label",
            "io.stateport.purpose=release-local-registry",
            "--publish",
            f"{registry}:5000",
            "--volume",
            f"{storage}:/var/lib/registry:Z",
            REGISTRY_IMAGE,
        ],
        capture=True,
    )
    deadline = time.monotonic() + 20
    healthy = False
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://{registry}/v2/", timeout=2) as response:
                healthy = response.status == 200
        except (OSError, URLError):
            healthy = False
        if healthy:
            break
        time.sleep(0.2)
    if not healthy:
        try:
            _run([str(PODMAN), "rm", "--force", name], timeout=60)
        finally:
            raise ReleaseBuildError("task-owned local registry did not become healthy")
    return {
        "name": name,
        "containerId": container_id,
        "image": REGISTRY_IMAGE,
        "endpoint": registry,
        "transport": "insecure-http-loopback-only",
        "healthEndpoint": f"http://{registry}/v2/",
        "healthy": True,
        "storage": "registry-data",
        "storageIdentity": storage_identity,
        "imageObservation": live_registry_image,
        "imagePullPolicy": "never-after-exact-prequalification",
        "retention": "running-until-explicit-proof-cleanup",
        "startedAt": _utc_now(),
    }


def stop_local_registry(record: dict[str, Any]) -> dict[str, Any]:
    name = str(record["name"])
    _run([str(PODMAN), "stop", "--time", "10", name], timeout=60)
    _run([str(PODMAN), "rm", name], timeout=60)
    if _container_exists(name):
        raise ReleaseBuildError("task-owned proof registry remained after cleanup")
    return {**record, "stoppedAt": _utc_now(), "cleanup": "container-removed"}


def _read_observed_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128:
        raise ReleaseBuildError(f"Podman digest output is unsafe: {path}")
    digest = path.read_text(encoding="ascii").strip()
    if _DIGEST.fullmatch(digest) is None:
        raise ReleaseBuildError(f"Podman returned an invalid pushed digest: {digest!r}")
    os.chmod(path, 0o400)
    return digest


def _archive_member_bytes(
    bundle: tarfile.TarFile, members: Mapping[str, tarfile.TarInfo], name: str, *, limit: int
) -> bytes:
    member = members.get(name)
    if member is None or not member.isfile() or member.size > limit:
        raise ReleaseBuildError(f"OCI archive member is missing or oversized: {name}")
    stream = bundle.extractfile(member)
    if stream is None:
        raise ReleaseBuildError(f"OCI archive member is unreadable: {name}")
    content = stream.read(limit + 1)
    if len(content) != member.size or len(content) > limit:
        raise ReleaseBuildError(f"OCI archive member size changed while reading: {name}")
    return content


def _verify_archive_blob(
    bundle: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    descriptor: Mapping[str, Any],
) -> bytes:
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise ReleaseBuildError("OCI archive descriptor lacks an exact sha256 digest")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ReleaseBuildError("OCI archive descriptor lacks an exact non-negative size")
    name = "blobs/sha256/" + digest.removeprefix("sha256:")
    member = members.get(name)
    if member is None or not member.isfile() or member.size != size:
        raise ReleaseBuildError(f"OCI archive blob size disagrees with descriptor: {name}")
    stream = bundle.extractfile(member)
    if stream is None:
        raise ReleaseBuildError(f"OCI archive blob is unreadable: {name}")
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    retain = size <= 16 * 1024 * 1024
    observed_size = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        observed_size += len(chunk)
        hasher.update(chunk)
        if retain:
            chunks.append(chunk)
    if observed_size != size or "sha256:" + hasher.hexdigest() != digest:
        raise ReleaseBuildError(f"OCI archive blob content disagrees with descriptor: {name}")
    return b"".join(chunks) if retain else b""


def verify_oci_archive(archive: Path, *, expected_manifest_digest: str) -> dict[str, Any]:
    if archive.is_symlink() or not archive.is_file():
        raise ReleaseBuildError("OCI archive is unavailable or unsafe")
    try:
        with tarfile.open(archive, mode="r:*") as bundle:
            member_list = bundle.getmembers()
            members: dict[str, tarfile.TarInfo] = {}
            for member in member_list:
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or not (member.isdir() or member.isfile())
                    or member.name in members
                ):
                    raise ReleaseBuildError(
                        f"OCI archive contains an unsafe or duplicate entry: {member.name!r}"
                    )
                members[member.name] = member
            index = json.loads(
                _archive_member_bytes(bundle, members, "index.json", limit=1024 * 1024)
            )
            if (
                not isinstance(index, Mapping)
                or index.get("schemaVersion") != 2
                or not isinstance(index.get("manifests"), list)
                or len(index["manifests"]) != 1
                or not isinstance(index["manifests"][0], Mapping)
            ):
                raise ReleaseBuildError("OCI archive index does not contain one exact manifest")
            manifest_descriptor = index["manifests"][0]
            if manifest_descriptor.get("digest") != expected_manifest_digest:
                raise ReleaseBuildError(
                    "OCI archive index does not retain the accepted registry manifest digest"
                )
            manifest_bytes = _verify_archive_blob(bundle, members, manifest_descriptor)
            if not manifest_bytes:
                raise ReleaseBuildError("OCI image manifest exceeds the bounded verification size")
            manifest = json.loads(manifest_bytes)
            if (
                not isinstance(manifest, Mapping)
                or manifest.get("schemaVersion") != 2
                or not isinstance(manifest.get("config"), Mapping)
                or not isinstance(manifest.get("layers"), list)
            ):
                raise ReleaseBuildError("OCI archive manifest is malformed")
            config_bytes = _verify_archive_blob(bundle, members, manifest["config"])
            if not config_bytes:
                raise ReleaseBuildError(
                    "OCI image configuration exceeds the bounded verification size"
                )
            config = json.loads(config_bytes)
            if not isinstance(config, Mapping) or (
                config.get("os"),
                config.get("architecture"),
            ) != ("linux", "amd64"):
                raise ReleaseBuildError("OCI archive configuration is not linux/amd64")
            layer_digests: list[str] = []
            for descriptor in manifest["layers"]:
                if not isinstance(descriptor, Mapping):
                    raise ReleaseBuildError("OCI archive layer descriptor is malformed")
                _verify_archive_blob(bundle, members, descriptor)
                layer_digests.append(str(descriptor["digest"]))
    except (json.JSONDecodeError, tarfile.TarError) as exc:
        raise ReleaseBuildError(f"OCI archive verification failed: {exc}") from exc
    return {
        "archiveDigest": sha256_file(archive),
        "manifestDigest": expected_manifest_digest,
        "configDigest": str(manifest["config"]["digest"]),
        "layerDigests": layer_digests,
        "platform": "linux/amd64",
        "verification": "oci-layout-index-manifest-config-and-layer-digests",
    }


def oci_archive_manifest_bytes(archive: Path, *, expected_manifest_digest: str) -> bytes:
    """Return the exact manifest blob bytes retained in a local OCI archive."""

    if archive.is_symlink() or not archive.is_file():
        raise ReleaseBuildError("OCI archive is unavailable or unsafe")
    try:
        with tarfile.open(archive, mode="r:*") as bundle:
            members: dict[str, tarfile.TarInfo] = {}
            for member in bundle.getmembers():
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or not (member.isdir() or member.isfile())
                    or member.name in members
                ):
                    raise ReleaseBuildError(
                        f"OCI archive contains an unsafe or duplicate entry: {member.name!r}"
                    )
                members[member.name] = member
            index = json.loads(_archive_member_bytes(bundle, members, "index.json", limit=1024 * 1024))
            if (
                not isinstance(index, Mapping)
                or index.get("schemaVersion") != 2
                or not isinstance(index.get("manifests"), list)
                or len(index["manifests"]) != 1
                or not isinstance(index["manifests"][0], Mapping)
                or index["manifests"][0].get("digest") != expected_manifest_digest
            ):
                raise ReleaseBuildError("OCI archive index does not contain the expected manifest")
            manifest_descriptor = index["manifests"][0]
            manifest_bytes = _verify_archive_blob(bundle, members, manifest_descriptor)
            if not manifest_bytes:
                raise ReleaseBuildError("OCI image manifest exceeds the bounded verification size")
            if "sha256:" + hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_digest:
                raise ReleaseBuildError("OCI image manifest bytes do not match the expected digest")
            return manifest_bytes
    except (json.JSONDecodeError, tarfile.TarError) as exc:
        raise ReleaseBuildError(f"OCI archive manifest extraction failed: {exc}") from exc


def _verify_declared_healthcheck(tag: str, containerfile: Path) -> None:
    declared = any(
        line.lstrip().upper().startswith("HEALTHCHECK ")
        for line in containerfile.read_text(encoding="utf-8").splitlines()
    )
    if not declared:
        return
    observed = json.loads(
        _run(
            [
                str(PODMAN),
                "image",
                "inspect",
                tag,
                "--format",
                "{{json .Config.Healthcheck}}",
            ],
            capture=True,
        )
    )
    if observed is None:
        raise ReleaseBuildError(
            f"built image lost its declared HEALTHCHECK: {tag} (containerfile {containerfile.name})"
        )


def _execute_image_builds(
    image_set: Mapping[str, Any],
    identity: SourceIdentity,
    *,
    registry: str,
    context: Path,
    output: Path,
    cgroup_parent: str | None = None,
    provider_input: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    digest_root = safe_path(output, "digests")
    digest_root.mkdir(mode=0o700)
    archive_root = safe_path(output, "oci-archives")
    archive_root.mkdir(mode=0o700)
    commands = build_commands(
        image_set,
        identity,
        registry=registry,
        context_root=context,
        digest_root=digest_root,
        cgroup_parent=cgroup_parent,
        provider_input=provider_input,
    )
    command_iterator = iter(commands)
    images: dict[str, Any] = {}
    accepted_references: dict[str, str] = {}
    for image_id, image in image_set["images"].items():
        observations: list[dict[str, Any]] = []
        repository = f"{registry}/stateport-alpha/{image_id}"
        for build_number in (1, 2):
            build_command = next(command_iterator)
            push_command = next(command_iterator)
            tag = f"{repository}:{identity.version}-build{build_number}"
            digest_file = digest_root / f"{image_id}-build{build_number}.digest"
            if digest_file.exists() or digest_file.is_symlink():
                raise ReleaseBuildError(f"digest output already exists: {digest_file.name}")
            started = _utc_now()
            _run(build_command)
            _verify_declared_healthcheck(tag, context / image["containerfile"])
            local = _image_observation(tag)
            _run(push_command)
            pushed_digest = _read_observed_digest(digest_file)
            digest_reference = f"{repository}@{pushed_digest}"
            _run(
                [
                    str(PODMAN),
                    "pull",
                    "--tls-verify=false",
                    "--platform",
                    "linux/amd64",
                    digest_reference,
                ]
            )
            remote = _image_observation(digest_reference)
            if pushed_digest not in remote["observedDigests"]:
                raise ReleaseBuildError(
                    f"pulled registry observation disagrees with pushed digest for {image_id}"
                )
            observations.append(
                {
                    "ordinal": build_number,
                    "localTag": tag,
                    "localImageId": local["imageId"],
                    "digestFile": f"digests/{digest_file.name}",
                    "digestFileDigest": sha256_file(digest_file),
                    "pushedDigest": pushed_digest,
                    "digestReference": digest_reference,
                    "pulledImageId": remote["imageId"],
                    "observedRemoteDigests": remote["observedDigests"],
                    "startedAt": started,
                    "finishedAt": _utc_now(),
                }
            )
        reproducible = observations[0]["pushedDigest"] == observations[1]["pushedDigest"]
        if not reproducible:
            raise ReleaseBuildError(f"double build is not OCI-digest reproducible: {image_id}")
        proof_reference = observations[1]["digestReference"]
        archive = archive_root / f"{image_id}.oci.tar"
        archive_digest_file = digest_root / f"{image_id}-oci-archive.digest"
        if archive.exists() or archive.is_symlink():
            raise ReleaseBuildError(f"OCI archive output already exists: {archive.name}")
        if archive_digest_file.exists() or archive_digest_file.is_symlink():
            raise ReleaseBuildError(
                f"OCI archive digest output already exists: {archive_digest_file.name}"
            )
        _run(
            [
                str(PODMAN),
                "push",
                "--digestfile",
                str(archive_digest_file),
                # Docker manifest format: pushing re-serializes manifest and
                # config, so only the registry push format yields a retained
                # archive whose manifest digest equals the accepted digest.
                "--format",
                "docker",
                observations[1]["localTag"],
                f"oci-archive:{archive}:{image_id}:{identity.version}",
            ]
        )
        if not archive.is_file() or archive.is_symlink():
            raise ReleaseBuildError(f"Podman did not create a safe OCI archive for {image_id}")
        archive_manifest_digest = _read_observed_digest(archive_digest_file)
        if archive_manifest_digest != observations[1]["pushedDigest"]:
            raise ReleaseBuildError(
                f"retained OCI archive changed the accepted manifest digest for {image_id}"
            )
        archive_observation = verify_oci_archive(
            archive, expected_manifest_digest=archive_manifest_digest
        )
        accepted_references[image_id] = proof_reference
        images[image_id] = {
            "containerfile": image["containerfile"],
            "containerfileDigest": sha256_file(context / image["containerfile"]),
            "builds": observations,
            "reproducible": True,
            "acceptedReference": proof_reference,
            "proofRegistryReference": proof_reference,
            "proofRegistryReferenceRetention": "ephemeral-until-receipted-registry-cleanup",
            "releaseAuthority": {
                "kind": "retained-oci-archive",
                "path": f"oci-archives/{archive.name}",
                "digest": archive_observation["archiveDigest"],
                "sizeBytes": archive.stat().st_size,
                "manifestDigest": archive_observation["manifestDigest"],
                "digestObservation": f"digests/{archive_digest_file.name}",
                "digestObservationDigest": sha256_file(archive_digest_file),
                "platform": archive_observation["platform"],
                "configDigest": archive_observation["configDigest"],
                "layerDigests": archive_observation["layerDigests"],
                "verification": archive_observation["verification"],
                "restorationRequiredBeforeUse": True,
            },
        }
    return images, accepted_references


def render_pull_compose(references: Mapping[str, str]) -> str:
    image_set = validate_definitions()
    enabled = {
        image_id: image
        for image_id, image in image_set["images"].items()
        if isinstance(image.get("pullCompose"), Mapping) and image["pullCompose"].get("enabled")
    }
    if set(references) != set(enabled) or any(
        not _DIGEST_REFERENCE.fullmatch(value) for value in references.values()
    ):
        raise ReleaseBuildError(
            "pull Compose requires every and only the digest-pinned installed runtime images"
        )
    services: dict[str, Any] = {}
    volume_names: set[str] = set()
    for image_id, image in enabled.items():
        compose = image["pullCompose"]
        service: dict[str, Any] = {
            "image": references[image_id],
            "init": True,
            "read_only": True,
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "tmpfs": ["/tmp"],
            "networks": ["stateport"],
            "logging": {
                "driver": "json-file",
                "options": {"max-size": "1m", "max-file": "3"},
            },
        }
        health = image.get("health")
        if isinstance(health, Mapping):
            service["healthcheck"] = {
                "test": [
                    "CMD",
                    "/usr/local/bin/stateport-healthcheck",
                    "--kind",
                    "http",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(health["port"]),
                    "--path",
                    str(health["path"]),
                ],
                "interval": "10s",
                "timeout": "3s",
                "retries": 3,
            }
        if compose.get("ports"):
            service["ports"] = list(compose["ports"])
        if compose.get("volumes"):
            service["volumes"] = list(compose["volumes"])
            volume_names.update(str(item).split(":", 1)[0] for item in compose["volumes"])
        services[image_id] = service
    document = {
        "services": services,
        "networks": {"stateport": {"driver": "bridge"}},
        "volumes": {name: {} for name in sorted(volume_names)},
    }
    return yaml.safe_dump(document, sort_keys=False, width=1000)


def build_release(
    *,
    version: str,
    registry: str,
    output_root: Path,
    source_commit: str | None = None,
) -> dict[str, Any]:
    # Refuse drifted reproducibility locks before any registry, context,
    # base-image pull, or Podman work.
    inputs = verify_locked_build_inputs()
    # Reject a non-local proof registry before Podman inspection, context
    # materialization, or any digest-pinned base-image pull.
    validate_registry_endpoint(registry)
    cgroup_parent = governor_cgroup_parent()
    identity, controller_identity = _release_identities(version, source_commit)
    verify_frozen_payload_build_contract(identity.commit, inputs)
    controller = _controller_attestation(controller_identity)
    provider_input = load_provider_oci_input()
    image_set = validate_definitions()
    builder = verify_podman_builder()
    builder["containerCgroup"] = {"manager": "cgroupfs", "parent": cgroup_parent}
    output = prepare_output_root(output_root, repository=ROOT)
    output_identity = directory_identity(output)
    context, context_receipt = materialize_committed_context(output, identity)
    base_images = pull_and_verify_base_images(provider_input)
    digest_root = output / "digests"
    plan = {
        "formatVersion": "stateport.release-image-build-plan/v1",
        "identity": asdict(identity),
        "controller": controller,
        "registry": registry,
        "registryImage": REGISTRY_IMAGE,
        "context": context_receipt,
        "providerInput": provider_input,
        "basePullCommands": base_pull_commands(provider_input),
        "imageCommands": build_commands(
            image_set,
            identity,
            registry=registry,
            context_root=context,
            digest_root=digest_root,
            cgroup_parent=cgroup_parent,
            provider_input=provider_input,
        ),
        "compatibilityFloor": "podman-5.0.0",
        "outputRootIdentity": output_identity,
    }
    write_json_create_only(output, "build-plan.json", plan)
    registry_record: dict[str, Any] | None = None
    images: dict[str, Any] = {}
    references: dict[str, str] = {}
    started = _utc_now()
    try:
        registry_base = next(
            (item for item in base_images if item.get("baseId") == "registry-2"), None
        )
        if registry_base is None:
            raise ReleaseBuildError("qualified registry base observation is unavailable")
        registry_record = start_local_registry(
            registry,
            identity,
            storage=safe_path(output, "registry-data"),
            registry_base=registry_base,
            cgroup_parent=cgroup_parent,
        )
        images, references = _execute_image_builds(
            image_set,
            identity,
            registry=registry,
            context=context,
            output=output,
            cgroup_parent=cgroup_parent,
            provider_input=provider_input,
        )
    except BaseException as failure:
        if registry_record is not None:
            try:
                registry_record = stop_local_registry(registry_record)
            except BaseException as cleanup_exc:
                registry_record = {
                    **registry_record,
                    "cleanup": "failed",
                    "cleanupError": type(cleanup_exc).__name__,
                }
        if registry_record is not None:
            write_json_create_only(output, "registry-lifecycle.json", registry_record)
        write_json_create_only(
            output,
            "build-failure.json",
            {
                "formatVersion": "stateport.release-image-build-failure/v1",
                "identity": asdict(identity),
                "controller": controller,
                "failedAt": _utc_now(),
                "errorType": type(failure).__name__,
                "message": str(failure)[:1000],
                "registryCleanup": None
                if registry_record is None
                else registry_record.get("cleanup"),
            },
        )
        raise failure
    if registry_record is None:
        raise ReleaseBuildError("proof registry lifecycle was not observed")
    registry_record = {
        **registry_record,
        "buildCompletedAt": _utc_now(),
        "cleanup": "pending-explicit-proof-cleanup",
    }
    write_json_create_only(output, "registry-lifecycle.json", registry_record)
    compose = render_pull_compose(
        {
            image_id: reference
            for image_id, reference in references.items()
            if image_id
            in {
                key
                for key, value in image_set["images"].items()
                if isinstance(value.get("pullCompose"), Mapping)
                and value["pullCompose"].get("enabled")
            }
        }
    )
    compose_path = write_bytes_create_only(output, "compose.pull.yaml", compose.encode("utf-8"))
    receipt = {
        "formatVersion": "stateport.release-image-build-receipt/v1",
        "identity": asdict(identity),
        "controller": controller,
        "outputRootIdentity": output_identity,
        "builder": builder,
        "context": context_receipt,
        "providerInput": provider_input,
        "registry": registry_record,
        "baseImages": base_images,
        "images": images,
        "pullCompose": {
            "path": "compose.pull.yaml",
            "digest": sha256_file(compose_path),
            "authority": "ephemeral-loopback-proof-only",
            "validUntil": "receipted-proof-registry-cleanup",
            "publicationRequirement": (
                "rewrite every reference to an exact digest in a retained authenticated registry"
            ),
            "imageReferences": {
                key: references[key]
                for key, value in image_set["images"].items()
                if isinstance(value.get("pullCompose"), Mapping)
                and value["pullCompose"].get("enabled")
            },
        },
        "startedAt": started,
        "finishedAt": _utc_now(),
        "result": "succeeded",
    }
    write_json_create_only(output, "build-receipt.json", receipt)
    return receipt


def cleanup_release_registry(*, build_receipt: Path) -> dict[str, Any]:
    if build_receipt.is_symlink() or not build_receipt.is_file():
        raise ReleaseBuildError("build receipt is unavailable or unsafe")
    receipt = json.loads(build_receipt.read_text(encoding="utf-8"))
    if not isinstance(receipt, Mapping) or receipt.get("formatVersion") != (
        "stateport.release-image-build-receipt/v1"
    ):
        raise ReleaseBuildError("cleanup requires an exact release image build receipt")
    registry = receipt.get("registry")
    if not isinstance(registry, Mapping):
        raise ReleaseBuildError("build receipt has no proof registry identity")
    name = str(registry.get("name", ""))
    container_id = str(registry.get("containerId", ""))
    if re.fullmatch(r"stateport-release-registry-[0-9a-f]{12}-[0-9]+", name) is None:
        raise ReleaseBuildError("proof registry name is not task-owned")
    output_identity = receipt.get("outputRootIdentity")
    if not isinstance(output_identity, Mapping) or directory_identity(build_receipt.parent) != dict(
        output_identity
    ):
        raise ReleaseBuildError("build receipt does not bind the exact private evidence root")
    if registry.get("storage") != "registry-data" or not isinstance(
        registry.get("storageIdentity"), Mapping
    ):
        raise ReleaseBuildError("build receipt does not bind the exact registry storage identity")
    images = receipt.get("images")
    if not isinstance(images, Mapping) or not images:
        raise ReleaseBuildError("build receipt has no retained image authority")
    for image_id, image in images.items():
        if not isinstance(image, Mapping):
            raise ReleaseBuildError(f"retained image authority is malformed: {image_id}")
        authority = image.get("releaseAuthority")
        if not isinstance(authority, Mapping) or authority.get("kind") != "retained-oci-archive":
            raise ReleaseBuildError(f"image lacks retained OCI authority: {image_id}")
        archive = safe_path(build_receipt.parent, str(authority.get("path", "")))
        observation = verify_oci_archive(
            archive, expected_manifest_digest=str(authority.get("manifestDigest", ""))
        )
        if (
            observation["archiveDigest"] != authority.get("digest")
            or observation["configDigest"] != authority.get("configDigest")
            or observation["layerDigests"] != authority.get("layerDigests")
        ):
            raise ReleaseBuildError(f"retained OCI authority drifted before cleanup: {image_id}")
    if not _container_exists(name):
        raise ReleaseBuildError("proof registry disappeared before receipted cleanup")
    inspected = json.loads(_run([str(PODMAN), "container", "inspect", name], capture=True))
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ReleaseBuildError("proof registry inspection is ambiguous")
    observed = inspected[0]
    labels = observed.get("Config", {}).get("Labels", {})
    if (
        not str(observed.get("Id", "")).startswith(container_id)
        or labels.get("io.stateport.managed") != "true"
        or labels.get("io.stateport.purpose") != "release-local-registry"
    ):
        raise ReleaseBuildError("proof registry identity or task ownership changed")
    stopped = stop_local_registry(dict(registry))
    remove_tree_exact(
        build_receipt.parent,
        "registry-data",
        expected_identity=registry["storageIdentity"],
    )
    cleanup = {
        "formatVersion": "stateport.release-registry-cleanup-receipt/v1",
        "buildReceiptDigest": sha256_file(build_receipt),
        "registry": stopped,
        "storage": "registry-data",
        "storageResult": "removed",
        "recoverability": "retained-verified-oci-archives",
        "retainedImageAuthority": {
            image_id: image["releaseAuthority"] for image_id, image in images.items()
        },
        "finishedAt": _utc_now(),
        "result": "succeeded",
    }
    write_json_create_only(build_receipt.parent, "registry-cleanup.json", cleanup)
    return cleanup


def plan_release(
    *, version: str, registry: str, source_commit: str | None = None
) -> dict[str, Any]:
    inputs = verify_locked_build_inputs()
    identity, controller_identity = _release_identities(version, source_commit)
    verify_frozen_payload_build_contract(identity.commit, inputs)
    controller = _controller_attestation(controller_identity)
    provider_input = load_provider_oci_input()
    image_set = validate_definitions()
    placeholder = Path("/EXTERNAL_STATEPORT_RELEASE_OUTPUT")
    return {
        "formatVersion": "stateport.release-image-build-plan/v1",
        "identity": asdict(identity),
        "controller": controller,
        "registry": registry,
        "registryImage": REGISTRY_IMAGE,
        "context": {"materialization": "git-archive-exact-commit", "commit": identity.commit},
        "basePullCommands": base_pull_commands(provider_input),
        "providerInput": provider_input,
        "imageCommands": build_commands(
            image_set,
            identity,
            registry=registry,
            context_root=placeholder / "source-context",
            digest_root=placeholder / "digests",
            provider_input=provider_input,
        ),
        "compatibilityFloor": "podman-5.0.0",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("plan", "build", "cleanup"))
    parser.add_argument("--version")
    parser.add_argument("--registry", default="127.0.0.1:5000")
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument(
        "--source-commit",
        help="exact frozen payload commit (must be an ancestor of clean current HEAD)",
    )
    args = parser.parse_args(argv)
    if args.command != "plan":
        require_guard(
            "image_build",
            sys.argv if argv is None else [str(Path(__file__)), *argv],
        )
    if args.command == "cleanup":
        if args.build_receipt is None:
            raise ReleaseBuildError("cleanup requires --build-receipt")
        print(
            json.dumps(cleanup_release_registry(build_receipt=args.build_receipt), sort_keys=True)
        )
        return 0
    if args.version is None:
        raise ReleaseBuildError(f"{args.command} requires --version")
    if args.command == "plan":
        print(
            json.dumps(
                plan_release(
                    version=args.version,
                    registry=args.registry,
                    source_commit=args.source_commit,
                ),
                sort_keys=True,
            )
        )
        return 0
    if args.output_root is None:
        raise ReleaseBuildError("build requires an explicit external --output-root")
    print(
        json.dumps(
            build_release(
                version=args.version,
                registry=args.registry,
                output_root=args.output_root,
                source_commit=args.source_commit,
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReleaseBuildError, ValueError, yaml.YAMLError) as exc:
        print(f"release build refused: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
