#!/usr/bin/env python3
"""Shared runtime for integrated-qualification journey drivers (J2/J3/J4/J6).

Every receipt binds to one exact candidate identity.  Retained rehearsal VMs
are reused through ``infra.qualification.wsl2_rehearsal.VM`` so journeys never
reinstall or rebuild anything.  Both shipped control-plane dialects are spoken
from the host across the guest SSH funnel: the persistent-app web surface
(cookie + CSRF + strict bodies) and the governed API JSON envelope.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "infra" / "qualification") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "infra" / "qualification"))

from wsl2_rehearsal import QEMU_ROOTFS_IDENTITY, QUALIFICATION_VM_MEMORY_MIB, SSH_PORT, VM, WSL_ROOTFS_IDENTITY  # noqa: E402

def log(msg: str) -> None:
    print(f"[journey] {msg}", flush=True)


def load_release_facts(candidate_dir: Path) -> dict[str, object]:
    """Read the exact identity a journey receipt must bind to."""
    index_path = candidate_dir / "release-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    signed = index["signed"]
    signature = index["signatures"][0]
    facts = {
        "releaseId": signed["release"]["releaseId"],
        "version": signed["release"]["version"],
        "channel": signed["release"]["channel"],
        "targetId": signed["targets"][0]["targetId"],
        "signedPayloadDigest": signature["subjectDigest"],
        "sourceCommit": signed["source"]["commit"],
        "sourceTree": signed["source"]["tree"],
        "installerDigest": signed["artifacts"]["installer"]["digest"],
        "images": {
            image["imageId"]: image["digest"] for image in signed["images"]
        },
        "imageReferences": {
            image["imageId"]: image["reference"] for image in signed["images"]
            if isinstance(image.get("reference"), str)
        },
        "releaseIndexSha256": "sha256:"
        + hashlib.sha256(index_path.read_bytes()).hexdigest(),
        "candidateDir": str(candidate_dir),
    }
    package_bundle = signed["artifacts"].get("podmanPackageBundle")
    if isinstance(package_bundle, dict):
        facts["podmanPackageBundleDigest"] = package_bundle["digest"]
    return facts


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _exact_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} is unavailable: {path}") from exc
    if resolved != path or path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} must be one exact non-symlink directory: {path}")
    return resolved


def _exact_file(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} is unavailable: {path}") from exc
    if resolved != path or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be one exact regular file: {path}")
    return resolved


def _json_object(path: Path, label: str) -> dict[str, object]:
    _exact_file(path, label)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unreadable: {path}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return document


def _validate_simulation_build_receipt(candidate_dir: Path, build_receipt: Path, facts: dict) -> dict:
    """Check production build observations against signed candidate comparison bytes."""
    from assemble_release_index import AssemblyError, _load_receipt

    _exact_file(build_receipt, "candidate build receipt")
    try:
        receipt = _load_receipt(build_receipt, expected_version=str(facts["version"]))
    except AssemblyError as exc:
        raise ValueError("candidate build receipt fails the production receipt contract") from exc
    if (receipt["identity"]["commit"] != facts["sourceCommit"]
            or receipt["identity"]["tree"] != facts["sourceTree"]
            or set(receipt["images"]) != set(facts["images"])):
        raise ValueError("production build receipt source or image set mismatch")
    index = _json_object(candidate_dir / "release-index.json", "candidate release index")
    proof_ref = index["signed"].get("supplyChain", {}).get("doubleBuildComparison")
    proof_path = candidate_dir / "supply-chain" / "double-build-comparison.json"
    proof = _json_object(proof_path, "signed double-build comparison")
    if (not isinstance(proof_ref, dict)
            or proof_ref.get("uri") != "operator://release/supply-chain/double-build-comparison.json"
            or proof_ref.get("digest") != _sha256_file(proof_path)
            or proof_ref.get("size") != proof_path.stat().st_size
            or proof_ref.get("mediaType") != "application/json"
            or proof.get("formatVersion") != "stateport.release-double-build-comparison/v1"
            or not isinstance(proof.get("images"), dict)
            or set(proof["images"]) != set(facts["images"])):
        raise ValueError("candidate signed double-build comparison binding mismatch")
    for image_id, digest in facts["images"].items():
        image = receipt["images"][image_id]
        comparison = proof["images"][image_id]
        builds = image.get("builds")
        if (image.get("reproducible") is not True
                or image["acceptedReference"].rsplit("@", 1)[-1] != digest
                or not isinstance(builds, list) or len(builds) != 2
                or any(not isinstance(build, dict) for build in builds)
                or [build.get("ordinal") for build in builds] != [1, 2]
                or not isinstance(comparison, dict)
                or comparison.get("formatVersion") != "stateport.double-build-comparison/v1"
                or comparison.get("imageId") != image_id
                or comparison.get("reproducible") is not True):
            raise ValueError("production build reproducibility proof mismatch")
        for build, name in zip(builds, ("first", "second")):
            observed = comparison.get(name)
            if (build.get("pushedDigest") != digest
                    or not isinstance(observed, dict)
                    or observed.get("digest") != digest
                    or not isinstance(build.get("digestFileDigest"), str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", build["digestFileDigest"]) is None
                    or observed.get("digestObservationDigest") != build["digestFileDigest"]
                    or not isinstance(build.get("localImageId"), str)
                    or not build["localImageId"]
                    or observed.get("localImageId") != build["localImageId"]):
                raise ValueError("production build observation differs from signed comparison")
    return dict(receipt)


def validate_retained_candidate_inputs(
    candidate_dir: Path,
    vm_dir: Path,
    site_root: Path,
    archive_root: Path | None,
    *,
    retained_simulation: bool = False,
    build_receipt: Path | None = None,
    native_distro_name: str | None = None,
    qualification_build_receipt: Path | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    """Bind retained inputs to passing J1; explicitly opted-in simulation is not qualification."""

    candidate_dir = _exact_directory(candidate_dir, "candidate directory")
    vm_dir = _exact_directory(vm_dir, "retained VM directory")
    site_root = _exact_directory(site_root, "candidate site root")
    if native_distro_name is None:
        archive_root = _exact_directory(archive_root, "candidate archive root")
        _exact_file(vm_dir / "vm.qcow2", "retained VM disk")
    elif retained_simulation or not re.fullmatch(r"StatePort-Rehearsal-[A-Za-z0-9._-]{3,64}", native_distro_name):
        raise ValueError("native follow-on requires a valid non-simulation distro name")

    facts = load_release_facts(candidate_dir)
    production_build = None
    qualification_evidence = {}
    if build_receipt is not None:
        if not retained_simulation:
            raise ValueError("explicit build receipt is supported only for retained simulation")
        build_receipt_path = _exact_file(build_receipt, "candidate build receipt")
        production_build = _validate_simulation_build_receipt(candidate_dir, build_receipt_path, facts)
    else:
        qualification_path = candidate_dir / "qualification-receipt.json"
        qualification = _json_object(qualification_path, "candidate qualification receipt")
        required_qualification = {
            "candidateSourceCommit": facts["sourceCommit"],
            "candidateSourceTree": facts["sourceTree"],
            "releaseIndexSha256": facts["releaseIndexSha256"],
            "signedPayloadDigest": facts["signedPayloadDigest"],
        }
        if any(qualification.get(key) != value for key, value in required_qualification.items()):
            raise ValueError("candidate qualification identity does not match the release index")
        recorded_build_receipt = Path(str(qualification.get("buildReceipt") or ""))
        build_receipt_path = qualification_build_receipt or recorded_build_receipt
        if qualification_build_receipt is not None and native_distro_name is None:
            raise ValueError("qualification build receipt override requires native follow-on")
        if qualification_build_receipt is None and not build_receipt_path.is_absolute():
            raise ValueError("candidate build receipt path must be absolute")
        _exact_file(build_receipt_path, "candidate build receipt")
        if qualification.get("buildReceiptSha256") != _sha256_file(build_receipt_path):
            raise ValueError("candidate build receipt digest mismatch")
        qualification_evidence = {
            "candidateQualificationReceipt": str(qualification_path),
            "candidateQualificationReceiptSha256": _sha256_file(qualification_path),
        }

    full_j1_path = vm_dir / "receipt.json" if native_distro_name else vm_dir.parent / "receipt.json"
    full_j1 = _json_object(full_j1_path, "retained full-J1 receipt")
    if full_j1.get("result") != "passed" or full_j1.get("version") != facts["version"]:
        raise ValueError("retained full-J1 receipt is not a pass for this candidate version")
    binding = full_j1.get("binding")
    if not isinstance(binding, dict):
        raise ValueError("retained full-J1 receipt has no candidate binding")
    if (
        binding.get("releaseIndexDigest") != facts["releaseIndexSha256"]
        or binding.get("signedPayloadDigest") != facts["signedPayloadDigest"]
        or binding.get("images") != facts["images"]
    ):
        raise ValueError("retained full-J1 receipt identity does not match the candidate")
    baseline = full_j1.get("rehearsalBaseline")
    if retained_simulation:
        if (
            full_j1.get("evidenceClass") != "simulation_only"
            or full_j1.get("mode") != "j1"
            or "diagnostic" in full_j1
            or not isinstance(baseline, dict)
            or baseline.get("evidenceClass") != "simulation_only"
            or baseline.get("substrate") != "qemu-wsl-identity-simulation"
            or baseline.get("rootfsIdentity") != QEMU_ROOTFS_IDENTITY
            or baseline.get("identityShims") != [
                "wsl_kernel_identity_only", "windows_interop_identity_only"
            ]
        ):
            raise ValueError("retained simulation requires an explicit pinned QEMU full-J1 receipt")
        site_transport = full_j1.get("siteTransport")
        registry_transport = full_j1.get("guestRegistryTransport")
        if (
            not isinstance(site_transport, dict)
            or site_transport.get("mode") != "guest-local-staged-pages"
            or site_transport.get("guestLocalServer") is not True
            or not isinstance(registry_transport, dict)
            or registry_transport.get("mode") != "digest-only-prepublication-mirror"
            or registry_transport.get("digestOnly") is not True
            or registry_transport.get("guestLocalMirror") is not True
            or registry_transport.get("retainedArchiveTransport") is not True
        ):
            raise ValueError("retained simulation requires explicit staged site and archive transport")
    elif (
        full_j1.get("evidenceClass") != "owner_path_qualification"
        or not isinstance(baseline, dict)
        or baseline.get("substrate") != "native-wsl2"
        or baseline.get("rootfsIdentity") != WSL_ROOTFS_IDENTITY
        or baseline.get("distroName") != native_distro_name
        or not isinstance(baseline.get("windowsIdentity"), str)
    ):
        raise ValueError("retained full-J1 receipt is not genuine native WSL2 owner-path evidence for this distro")
    if native_distro_name is not None:
        if (not isinstance(baseline.get("machineId"), str)
                or re.fullmatch(r"[0-9a-fA-F]{32}", baseline["machineId"]) is None
                or not isinstance(baseline.get("windowsIdentity"), str)
                or not baseline["windowsIdentity"].strip()
                or baseline.get("distroName") != native_distro_name):
            raise ValueError("native J1 receipt has incomplete identity binding")
    phases = full_j1.get("phases")
    required_phases = {
        "bootstrap-fetch",
        "public-transport-boundary",
        "transport-probe",
        "materialization-preflight",
        "install",
        "post-bootstrap-runtime-smoke",
        "install-rerun",
        "guest-runtime-smoke",
    }
    if retained_simulation:
        required_phases.remove("public-transport-boundary")
        required_phases.update({"guest-swap", "install-services", "install-rerun-services"})
        if binding.get("images") != facts["images"]:
            raise ValueError("retained simulation service-smoke image binding mismatch")
    if (
        not isinstance(phases, dict)
        or set(phases) != required_phases
        or any(not isinstance(phases[name], dict) or phases[name].get("ok") is not True
               for name in required_phases)
    ):
        raise ValueError("retained full-J1 receipt does not contain every passing phase")

    version = str(facts["version"])
    bootstrap_digest = binding.get("bootstrapDigest")
    if not isinstance(bootstrap_digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", bootstrap_digest) is None:
        raise ValueError("retained full-J1 bootstrap digest is invalid")
    candidate_bootstrap = _exact_file(candidate_dir / "bootstrap.sh", "candidate bootstrap")
    staged_bootstrap = _exact_file(site_root / "download" / "install.sh", "staged bootstrap")
    staged_version_bootstrap = _exact_file(
        site_root / "download" / version / "bootstrap.sh", "staged version bootstrap"
    )
    bootstrap_paths = (candidate_bootstrap, staged_bootstrap, staged_version_bootstrap)
    if any(_sha256_file(path) != bootstrap_digest for path in bootstrap_paths):
        raise ValueError("candidate and staged bootstrap bytes do not match full-J1")

    installer_digest = facts.get("installerDigest")
    if not isinstance(installer_digest, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", installer_digest
    ) is None:
        raise ValueError("candidate installer digest is invalid")
    candidate_installer = _exact_file(
        candidate_dir / "artifacts" / "installer", "candidate installer"
    )
    staged_installer = _exact_file(
        site_root / "download" / version / "stateport-installer", "staged installer"
    )
    if any(_sha256_file(path) != installer_digest for path in (candidate_installer, staged_installer)):
        raise ValueError("candidate and staged installer bytes do not match the signed index")

    package_bundle_digest = facts.get("podmanPackageBundleDigest")
    if package_bundle_digest is not None:
        if not isinstance(package_bundle_digest, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", package_bundle_digest
        ) is None:
            raise ValueError("candidate Podman package bundle digest is invalid")
        candidate_package_bundle = _exact_file(
            candidate_dir / "artifacts" / "podmanPackageBundle",
            "candidate Podman package bundle",
        )
        staged_package_bundle = _exact_file(
            site_root
            / "download"
            / version
            / "stateport-podman-package-bundle.tar",
            "staged Podman package bundle",
        )
        if any(
            _sha256_file(path) != package_bundle_digest
            for path in (candidate_package_bundle, staged_package_bundle)
        ):
            raise ValueError(
                "candidate and staged Podman package bundle bytes do not match the signed index"
            )

    candidate_index = _exact_file(candidate_dir / "release-index.json", "candidate release index")
    staged_index = _exact_file(
        site_root / "download" / version / "release-index.json", "staged release index"
    )
    if any(_sha256_file(path) != facts["releaseIndexSha256"] for path in (candidate_index, staged_index)):
        raise ValueError("candidate and staged release-index bytes do not match")

    images = facts.get("images")
    bound_archives = binding.get("archives")
    if not isinstance(images, dict):
        raise ValueError("candidate image binding is missing")
    if native_distro_name is None:
        if not isinstance(bound_archives, dict) or set(images) != set(bound_archives):
            raise ValueError("candidate or full-J1 image binding is missing")
        observed_names = {path.name.removesuffix(".oci.tar") for path in archive_root.glob("*.oci.tar")}
        if observed_names != set(images):
            raise ValueError("candidate archive root does not contain exactly the signed image set")
    archive_digests: dict[str, str] = {}
    for image_id, manifest_digest in sorted(images.items()):
        if native_distro_name is not None:
            continue
        archive_binding = bound_archives.get(image_id)
        if (
            not isinstance(archive_binding, dict)
            or archive_binding.get("manifestDigest") != manifest_digest
        ):
            raise ValueError(f"full-J1 manifest binding mismatch for {image_id}")
        archive = _exact_file(archive_root / f"{image_id}.oci.tar", f"{image_id} archive")
        archive_digest = _sha256_file(archive)
        if archive_binding.get("archiveDigest") != archive_digest:
            raise ValueError(f"full-J1 archive digest mismatch for {image_id}")
        if production_build is not None:
            authority = production_build["images"][image_id].get("releaseAuthority")
            if (not isinstance(authority, dict)
                    or authority.get("kind") != "retained-oci-archive"
                    or authority.get("manifestDigest") != manifest_digest
                    or authority.get("digest") != archive_digest
                    or authority.get("sizeBytes") != archive.stat().st_size):
                raise ValueError("production build archive authority does not match retained J1")
        archive_digests[str(image_id)] = archive_digest

    return facts, {
        **({
            "evidenceClass": "simulation_only",
            "lane": "retained-installed-simulation",
            "admissibleForQualification": False,
            "freshInstallEvidence": False,
            "rehearsalBaseline": baseline,
            "siteTransport": site_transport,
            "guestRegistryTransport": registry_transport,
        } if retained_simulation else {}),
        **qualification_evidence,
        "buildReceipt": str(build_receipt_path),
        "buildReceiptSha256": _sha256_file(build_receipt_path),
        "fullJ1Receipt": str(full_j1_path),
        "fullJ1ReceiptSha256": _sha256_file(full_j1_path),
        **({"nativeIdentity": {
            "machineId": baseline["machineId"],
            "windowsIdentity": baseline["windowsIdentity"],
        }} if native_distro_name is not None else {}),
        "siteRoot": str(site_root),
        "archiveRoot": str(archive_root) if archive_root is not None else None,
        "bootstrapPath": str(candidate_bootstrap),
        "bootstrapDigest": bootstrap_digest,
        "installerPath": str(candidate_installer),
        "installerDigest": installer_digest,
        **(
            {
                "podmanPackageBundlePath": str(candidate_package_bundle),
                "podmanPackageBundleDigest": package_bundle_digest,
            }
            if package_bundle_digest is not None
            else {}
        ),
        "archiveDigests": archive_digests,
        "rehearsalBaseline": baseline,
        **({"bootstrapUrl": binding["bootstrapUrl"]}
           if isinstance(binding.get("bootstrapUrl"), str) else {}),
    }


class Refusal(RuntimeError):
    def __init__(self, code: str, message: str, status: int | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status


class JourneyReceipt:
    def __init__(self, journey_id: str, binding: dict[str, object]):
        self.document: dict[str, object] = {
            "formatVersion": "stateport.journey-receipt/v1",
            "journeyId": journey_id,
            "lane": "integratedQualification",
            "binding": binding,
            "steps": [],
            "result": "running",
        }
        self.out_path: Path | None = None

    def record(self, name: str, ok: bool, **detail: object) -> None:
        entry = {"name": name, "ok": bool(ok)}
        entry.update(detail)
        self.document["steps"].append(entry)
        log(f"step {name}: {'ok' if ok else 'FAILED'}")
        if self.out_path is not None:
            self.write(self.out_path)

    def write(self, out: Path) -> None:
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(out.suffix + ".part")
        tmp.write_text(json.dumps(self.document, indent=2, sort_keys=True))
        tmp.rename(out)


def discover_services(vm: VM) -> dict[str, dict[str, str]]:
    """Map shipped service ids to their accepted unit and published port."""
    script = r"""
for f in /var/lib/stateport-control/.config/containers/systemd/*.container; do
  [ -f "$f" ] || continue
  grep -q '^Label=io.stateport.profile=accepted$' "$f" || continue
  sid=$(sed -n 's/^Label=io.stateport.service.id=//p' "$f" | head -n 1)
  port=$(sed -n 's/^PublishPort=127\.0\.0\.1:\([0-9][0-9]*\):.*/\1/p' "$f" | head -n 1)
  container=$(sed -n 's/^ContainerName=//p' "$f" | head -n 1)
  printf '%s\t%s\t%s\t%s\n' "$sid" "$(basename "$f" .container).service" "$port" "$container"
done
"""
    result = vm.ssh(f"sudo sh -c {shlex.quote(script)}")
    if result.returncode != 0:
        raise SystemExit(f"service discovery failed: {result.stderr[-500:]}")
    expected_services = {"stateport-web", "stateport-api", "stateport-worker"}
    services: dict[str, dict[str, str]] = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split("\t")
        if (
            len(parts) != 4
            or parts[0] not in expected_services
            or parts[0] in services
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", parts[3]) is None
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,254}\.service", parts[1])
            is None
            or not parts[2].isdigit()
            or not 1 <= int(parts[2]) <= 65535
        ):
            raise SystemExit(f"unsafe or duplicate control plane discovery row: {line!r}")
        services[parts[0]] = {
            "unit": parts[1],
            "port": parts[2],
            "container": parts[3],
        }
    if set(services) != expected_services:
        raise SystemExit(f"incomplete control plane discovery: {services}")
    return services


def control_user_env() -> str:
    return (
        "uid=$(id -u stateport-control); "
        "run_control() { cd /; env -i HOME=/var/lib/stateport-control "
        "LANG=C.UTF-8 LC_ALL=C.UTF-8 LOGNAME=stateport-control "
        "PATH=/usr/bin:/bin USER=stateport-control "
        "XDG_CONFIG_HOME=/var/lib/stateport-control/.config "
        "XDG_DATA_HOME=/var/lib/stateport-control/.local/share "
        "XDG_STATE_HOME=/var/lib/stateport-control/.local/state "
        "XDG_RUNTIME_DIR=/run/user/$uid \"$@\"; }"
    )


def transport_artifact(vm: VM, source: str | Path, destination: str, *,
                       public_url: str | None = None,
                       expected_digest: str | None = None) -> None:
    """Move a candidate artifact into a guest using its qualified transport.

    Retained QEMU journeys use the reviewed host-side copy. Native public
    journeys must fetch anonymously from the candidate URL; accepting a local
    path there would silently turn native proof into staged-host proof.
    """
    if getattr(vm, "native_wsl", False):
        if not public_url or not expected_digest:
            raise ValueError("native artifact transport requires public URL and digest")
        fetch = getattr(vm, "fetch_public_artifact", None)
        if fetch is None:
            raise ValueError("native guest does not provide public artifact transport")
        fetch(public_url, destination, expected_digest)
        return
    vm.scp_in(str(source), destination)


def candidate_artifact_urls(version: str, bootstrap_url: str) -> tuple[str, str]:
    """Return the exact bootstrap and sibling installer URLs for a candidate."""
    if not re.fullmatch(r"https://[^\s]+", bootstrap_url):
        raise ValueError("candidate bootstrap URL must use HTTPS")
    if bootstrap_url.endswith("/bootstrap.sh"):
        root = bootstrap_url.removesuffix("/bootstrap.sh")
    elif bootstrap_url == "https://lennertvhoy.github.io/StatePort-Site/download/install.sh":
        root = f"https://lennertvhoy.github.io/StatePort-Site/download/{version}"
    else:
        raise ValueError("candidate bootstrap URL is not a supported Site artifact")
    return bootstrap_url, root + "/stateport-installer"


def restart_service(vm: VM, unit: str) -> None:
    cmd = (
        f"sudo runuser -u stateport-control -- bash -c "
        f"{shlex.quote(control_user_env() + f'; run_control systemctl --user restart {unit}')}"
    )
    result = vm.ssh(cmd, timeout=300)
    if result.returncode != 0:
        raise SystemExit(f"restart {unit} failed: {result.stderr[-500:]}")


def wait_service_healthy(vm: VM, services: dict[str, dict[str, str]],
                         service_id: str, deadline_s: int = 240) -> None:
    port = services[service_id]["port"]
    path = "/session" if service_id == "stateport-web" else "/readyz"
    deadline = time.time() + deadline_s
    last = ""
    while time.time() < deadline:
        probe = vm.ssh(
            f"curl -fsS -m 5 http://127.0.0.1:{port}{path} >/dev/null 2>&1",
            check=False,
        )
        if probe.returncode == 0:
            log(f"{service_id} healthy on :{port}")
            return
        last = probe.stderr[-200:]
        time.sleep(5)
    raise SystemExit(f"{service_id} not healthy within {deadline_s}s: {last}")


class GuestJsonClient:
    """HTTP client for a service published on the guest loopback."""

    def __init__(self, vm: VM, port: int | str):
        self.vm = vm
        self.port = str(port)
        self.jar = f"/tmp/journey-cookies-{self.port}.txt"
        self.body_file = f"/tmp/journey-body-{self.port}.json"
        self.csrf: str | None = None
        self.last_status: int | None = None

    def request(self, method: str, path: str, body: dict | None = None,
                headers: dict[str, str] | None = None,
                csrf: bool = False, timeout: int = 90) -> dict:
        argv = [
            "curl", "-sS", "-m", str(timeout),
            "-o", "/tmp/journey-resp.json",
            "-w", "%{http_code}",
            "--cookie-jar", self.jar, "--cookie", self.jar,
            "-X", method,
            "-H", "Content-Type: application/json",
            "-H", f"Origin: http://127.0.0.1:{self.port}",
        ]
        if csrf:
            if not self.csrf:
                raise Refusal("csrf_missing", "handshake before mutating requests")
            argv += ["-H", f"X-StatePort-CSRF: {self.csrf}"]
        for key, value in (headers or {}).items():
            argv += ["-H", f"{key}: {value}"]
        if body is not None:
            encoded = base64.b64encode(json.dumps(body).encode()).decode()
            staged = self.vm.ssh(
                f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(self.body_file)}",
                timeout=30,
            )
            if staged.returncode != 0:
                raise Refusal("body_stage_failed", staged.stderr[-200:])
            argv += ["-d", f"@{self.body_file}"]
        argv.append(f"http://127.0.0.1:{self.port}{path}")
        remote = " ".join(shlex.quote(a) for a in argv)
        result = self.vm.ssh(remote, check=False, timeout=timeout + 30)
        if result.returncode != 0:
            raise Refusal("curl_failed",
                          f"exit={result.returncode} {result.stderr[-300:]}", None)
        raw = result.stdout.strip()
        status = int(raw[-3:]) if raw[-3:].isdigit() else 0
        self.last_status = status
        payload_result = self.vm.ssh("cat /tmp/journey-resp.json", timeout=30)
        text = payload_result.stdout.strip()
        try:
            document = json.loads(text) if text else {}
        except json.JSONDecodeError:
            raise Refusal("non_json_response", text[:300], status)
        if isinstance(document, dict) and document.get("ok") is True:
            return document.get("result", {})
        error = document.get("error") if isinstance(document, dict) else None
        if isinstance(error, dict):
            raise Refusal(str(error.get("code")), str(error.get("message")), status)
        raise Refusal("unexpected_envelope", text[:300], status)

    def handshake(self) -> str:
        result = self.request("GET", "/session")
        token = result.get("csrfToken") if isinstance(result, dict) else None
        if not token:
            raise Refusal("csrf_unavailable", json.dumps(result)[:200])
        self.csrf = str(token)
        return self.csrf


def boot_retained_vm(
    work_dir: Path,
    *,
    site_root: Path,
    archive_root: Path,
    memory_mib: int = QUALIFICATION_VM_MEMORY_MIB,
) -> VM:
    work_dir = _exact_directory(work_dir, "retained VM directory")
    site_root = _exact_directory(site_root, "candidate site root")
    archive_root = _exact_directory(archive_root, "candidate archive root")
    _exact_file(work_dir / "vm.qcow2", "retained VM disk")
    vm = VM(work_dir, site_root, archive_root,
            phase_gates=True, diagnostic_reuse=True, memory_mib=memory_mib)
    try:
        vm.phase_gate("journey-boot")
        vm.prepare(reuse=True)
        vm.boot()
    except BaseException:
        try:
            vm.teardown()
        except Exception as cleanup_error:  # noqa: BLE001 - preserve the boot failure
            log(f"retained VM cleanup after boot failure also failed: {cleanup_error}")
        raise
    return vm


def boot_native_follow_on(work_dir: Path, *, site_root: Path, distro_name: str,
                         expected_identity: dict[str, str],
                         expected_baseline: dict[str, object]) -> VM:
    """Attach J2/J4 to the exact native distro proven by that run's J1 receipt."""
    from wsl2_rehearsal import NativeWSL
    work_dir = _exact_directory(work_dir, "native qualification work directory")
    site_root = _exact_directory(site_root, "candidate site root")
    if (not isinstance(expected_identity, dict)
            or set(expected_identity) != {"machineId", "windowsIdentity"}
            or not isinstance(expected_identity.get("machineId"), str)
            or re.fullmatch(r"[0-9a-fA-F]{32}", expected_identity["machineId"]) is None
            or not isinstance(expected_identity.get("windowsIdentity"), str)
            or not expected_identity["windowsIdentity"].strip()
            or not isinstance(expected_baseline, dict)
            or expected_baseline.get("distroName") != distro_name
            or any(expected_baseline.get(key) != value for key, value in expected_identity.items())):
        raise ValueError("native follow-on identity binding is incomplete")
    vm = NativeWSL(work_dir, site_root, None, distro_name=distro_name,
                   phase_gates=True, public_transport=True, attach_existing=True)
    vm.expected_native_identity = expected_identity
    vm.expected_native_baseline = expected_baseline
    vm.phase_gate("journey-boot")
    vm.prepare(reuse=True)
    vm.boot()
    return vm


def verify_installed_image_digests(vm: VM, expected: dict[str, str]) -> dict[str, object]:
    """Check declared units and independently inspect running accepted containers.

    Unit text is deployment intent, not evidence of the executing image. Only
    narrow inspect fields leave the guest; raw inspect/environment/auth data is
    never returned or included in a refusal.
    """
    services = ("stateport-web", "stateport-api", "stateport-worker")
    digest_pattern = r"sha256:[0-9a-f]{64}"
    if any(not isinstance(expected.get(sid), str) or re.fullmatch(digest_pattern, expected[sid]) is None for sid in services):
        raise ValueError("candidate must identify every control-service image by digest")
    expected = {sid: expected[sid] for sid in services}
    unit_script = r"""
set -eu
for f in /var/lib/stateport-control/.config/containers/systemd/*.container; do
  [ -f "$f" ] || continue
  grep -q '^Label=io.stateport.profile=accepted$' "$f" || continue
  sid=$(sed -n 's/^Label=io.stateport.service.id=//p' "$f")
  img=$(sed -n 's/^Image=//p' "$f")
  name=$(sed -n 's/^ContainerName=//p' "$f")
  case "$img" in *@sha256:*) dig=${img##*@};; *) dig="invalid";; esac
  printf '%s\t%s\t%s\n' "$sid" "$dig" "$name"
done
"""
    unit_result = vm.ssh(f"sudo sh -c {shlex.quote(unit_script)}", check=False, timeout=60)
    unit_rows: dict[str, list[tuple[str, str]]] = {sid: [] for sid in services}
    bad_units = unit_result.returncode != 0
    for line in unit_result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] not in unit_rows or re.fullmatch(digest_pattern, parts[1]) is None or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", parts[2]) is None:
            bad_units = True
            continue
        unit_rows[parts[0]].append((parts[1], parts[2]))
    declared = {sid: rows[0][0] for sid, rows in unit_rows.items() if len(rows) == 1}
    declared_mismatches = {
        sid: {"expected": expected[sid], "observed": declared.get(sid),
              "reason": "unit-read-failed-or-malformed" if bad_units else "unit-count-or-digest-mismatch"}
        for sid in services if bad_units or len(unit_rows[sid]) != 1 or declared.get(sid) != expected[sid]
    }
    # Select by service/profile labels, then inspect immutable container IDs and
    # recheck labels/running state: a stopped or replaced container cannot pass
    # merely because a unit or an earlier ps snapshot looked correct.
    live_script = control_user_env() + r"""
set -eu
for sid in stateport-web stateport-api stateport-worker; do
  ids=$(run_control podman ps --no-trunc --filter status=running --filter "label=io.stateport.service.id=$sid" --filter label=io.stateport.profile=accepted --format '{{.ID}}')
  set -- $ids
  if [ "$#" -ne 1 ]; then
    printf '%s\tinvalid-running-count\n' "$sid"
    continue
  fi
  for id in $ids; do
    case "$id" in *[!0-9a-f]*|"") exit 3;; esac
    [ "${#id}" -eq 64 ] || exit 3
    printf '%s\t' "$sid"
    run_control podman container inspect --format '{{.Id}}\t{{.ImageDigest}}\t{{.State.Running}}\t{{index .Config.Labels "io.stateport.service.id"}}\t{{index .Config.Labels "io.stateport.profile"}}\t{{.Name}}' "$id" 2>/dev/null
done
done
"""
    live_script = live_script.replace(r"\t", "\t")
    live_result = vm.ssh(
        "sudo runuser -u stateport-control -- bash -c " + shlex.quote(live_script),
        check=False, timeout=60,
    )
    live_rows: dict[str, list[dict[str, str]]] = {sid: [] for sid in services}
    bad_live = live_result.returncode != 0
    for line in live_result.stdout.splitlines():
        # The bounded Go template contains actual tab separators.
        parts = line.split("\t")
        if (len(parts) != 7 or parts[0] not in live_rows
                or re.fullmatch(r"[0-9a-f]{64}", parts[1]) is None
                or re.fullmatch(digest_pattern, parts[2]) is None
                or parts[3] != "true" or parts[4] != parts[0] or parts[5] != "accepted"
                or re.fullmatch(r"/?[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", parts[6]) is None):
            bad_live = True
            continue
        live_rows[parts[0]].append({"containerId": parts[1], "imageDigest": parts[2], "name": parts[6].lstrip("/")})
    containers = {sid: rows[0] for sid, rows in live_rows.items() if len(rows) == 1}
    observed = {sid: row["imageDigest"] for sid, row in containers.items()}
    mismatches = dict(declared_mismatches)
    for sid in services:
        if (bad_live or len(live_rows[sid]) != 1 or observed.get(sid) != expected[sid]
                or len(unit_rows[sid]) != 1 or containers.get(sid, {}).get("name") != unit_rows[sid][0][1]):
            mismatches[sid] = {"expected": expected[sid], "observed": observed.get(sid),
                              "reason": "live-inspection-failed-or-malformed" if bad_live else "running-container-count-identity-or-digest-mismatch"}
    return {"observed": observed, "declared": declared, "containers": containers,
            "declaredMismatches": declared_mismatches, "mismatches": mismatches}
