#!/usr/bin/env python3
"""Run the StatePort clean-host qualification matrix.

This module is deliberately an evidence collector, not a host simulator.  A
normal run uses SSH with strict host-key checking and executes a real guest
probe followed by operator-supplied, receipt-producing stage commands.  The
commands are argv arrays; no local or remote shell is inserted by this tool.

Every stage receipt is bound to the exact candidate in the input config.  A
distribution label is only a requested matrix coordinate.  Eligibility comes
from observed capability facts, and ``validated_baseline`` comes only from an
exact accepted receipt digest.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Mapping, Protocol, Sequence


FORMAT = "stateport.qualification-receipt-manifest/v1"
CONFIG_FORMAT = "stateport.qualification-config/v1"
STAGE_FORMAT = "stateport.qualification-stage-receipt/v1"
OBSERVATION_FORMAT = "stateport.qualification-guest-observation/v1"
HARNESS_VERSION = "0.1.0"
TARGET_ID = "linux-amd64-rootless-podman-quadlet"
PODMAN_MINIMUM = (5, 0, 0)
REQUIRED_DISTRIBUTIONS = frozenset({"ubuntu", "debian", "fedora", "rolling"})
REQUIRED_STAGES = (
    "guest_identity",
    "capability_facts",
    "release_verification",
    "provisioning",
    "install",
    "protocol_health",
    "representative_app",
    "backup_export",
    "restart_reread",
    "update_rollback",
    "uninstall_purge",
    "final_durable_state",
)
CANDIDATE_FIELDS = (
    "releaseId",
    "version",
    "targetId",
    "releaseIndexUri",
    "releaseIndexDigest",
    "signedPayloadDigest",
    "sourceCommit",
    "sourceTree",
    "imageDigests",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_ID = re.compile(r"^[a-z][a-z0-9._-]{2,127}$")
_STAGE_FACTS: dict[str, tuple[str, ...]] = {
    "release_verification": (
        "releaseIndexDigest",
        "signedPayloadDigest",
        "sourceCommit",
        "sourceTree",
        "imageDigests",
        "indexVerified",
        "imagesVerified",
    ),
    "provisioning": ("provisioningReceiptDigest",),
    "install": ("installReceiptDigest",),
    "protocol_health": ("protocolReceiptDigest",),
    "representative_app": ("appReceiptDigest",),
    "backup_export": ("backupReceiptDigest", "exportReceiptDigest"),
    "restart_reread": ("restartReceiptDigest", "rereadReceiptDigest"),
    "update_rollback": ("updateReceiptDigest", "rollbackReceiptDigest", "inducedFailure"),
    "uninstall_purge": ("uninstallReceiptDigest", "purgeReceiptDigest"),
    "final_durable_state": ("finalStateDigest",),
}


class QualificationError(ValueError):
    """The qualification input or observed evidence is invalid."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise QualificationError(f"value is not canonical JSON: {exc}") from exc


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise QualificationError(f"{label} must be an object")
    return value


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise QualificationError(f"{label} must be a non-empty string")
    return value


def _require_digest(value: object, label: str) -> str:
    result = _require_string(value, label)
    if _DIGEST.fullmatch(result) is None:
        raise QualificationError(f"{label} must be a sha256 digest")
    return result


def _require_argv(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise QualificationError(f"{label} must be a non-empty argv list")
    return list(value)


def _validate_candidate(value: object) -> dict[str, Any]:
    raw = _require_mapping(value, "candidate")
    if set(raw) != set(CANDIDATE_FIELDS):
        raise QualificationError("candidate fields are incomplete or unexpected")
    candidate = dict(raw)
    for field in ("releaseId", "version", "releaseIndexUri"):
        _require_string(candidate[field], f"candidate.{field}")
    if candidate["targetId"] != TARGET_ID:
        raise QualificationError("candidate.targetId is not the portable target")
    _require_digest(candidate["releaseIndexDigest"], "candidate.releaseIndexDigest")
    _require_digest(candidate["signedPayloadDigest"], "candidate.signedPayloadDigest")
    for field in ("sourceCommit", "sourceTree"):
        if not isinstance(candidate[field], str) or _SHA1.fullmatch(candidate[field]) is None:
            raise QualificationError(f"candidate.{field} must be a 40-character SHA-1")
    images = candidate["imageDigests"]
    if (
        not isinstance(images, list)
        or not images
        or any(not isinstance(item, str) for item in images)
        or len(images) != len(set(images))
        or any(_DIGEST.fullmatch(item) is None for item in images)
    ):
        raise QualificationError("candidate.imageDigests must contain unique sha256 digests")
    return candidate


def _validate_stage_commands(value: object) -> dict[str, dict[str, Any]]:
    raw = _require_mapping(value, "stageCommands")
    if set(raw) != set(REQUIRED_STAGES[2:]):
        raise QualificationError("stageCommands must cover every post-probe stage exactly")
    result: dict[str, dict[str, Any]] = {}
    for stage in REQUIRED_STAGES[2:]:
        item = _require_mapping(raw[stage], f"stageCommands.{stage}")
        if set(item) != {"command", "timeoutSeconds"}:
            raise QualificationError(f"stageCommands.{stage} has unexpected fields")
        command = _require_argv(item["command"], f"stageCommands.{stage}.command")
        timeout = item["timeoutSeconds"]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 86400:
            raise QualificationError(f"stageCommands.{stage}.timeoutSeconds is invalid")
        result[stage] = {"command": command, "timeoutSeconds": timeout}
    return result


def load_config(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QualificationError(f"qualification config could not be loaded: {exc}") from exc
    raw = _require_mapping(document, "qualification config")
    if raw.get("schema") != CONFIG_FORMAT:
        raise QualificationError("qualification config schema is unsupported")
    if set(raw) != {"schema", "candidate", "acceptedReceiptDigests", "guests"}:
        raise QualificationError("qualification config has unexpected fields")
    candidate = _validate_candidate(raw["candidate"])
    accepted = raw["acceptedReceiptDigests"]
    if (
        not isinstance(accepted, list)
        or any(not isinstance(item, str) or _DIGEST.fullmatch(item) is None for item in accepted)
        or len(accepted) != len(set(accepted))
    ):
        raise QualificationError("acceptedReceiptDigests must contain unique sha256 digests")
    guests = raw["guests"]
    if not isinstance(guests, list) or len(guests) != 4:
        raise QualificationError("guests must contain exactly four matrix coordinates")
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_distributions: set[str] = set()
    for index, guest_value in enumerate(guests):
        guest = _require_mapping(guest_value, f"guests[{index}]")
        if set(guest) != {"guestId", "distribution", "version", "transport", "stageCommands"}:
            raise QualificationError(f"guests[{index}] has unexpected fields")
        guest_id = _require_string(guest["guestId"], f"guests[{index}].guestId")
        if _ID.fullmatch(guest_id) is None or guest_id in seen_ids:
            raise QualificationError(f"guests[{index}].guestId is invalid or duplicated")
        distribution = _require_string(guest["distribution"], f"guests[{index}].distribution")
        if distribution not in REQUIRED_DISTRIBUTIONS or distribution in seen_distributions:
            raise QualificationError(f"guests[{index}].distribution must cover the four required coordinates")
        if distribution == "ubuntu" and guest["version"] != "24.04":
            raise QualificationError("the Ubuntu qualification coordinate must be 24.04")
        if distribution == "fedora" and guest["version"] != "44":
            raise QualificationError("the Fedora qualification coordinate must be 44")
        version = _require_string(guest["version"], f"guests[{index}].version")
        transport = _require_mapping(guest["transport"], f"guests[{index}].transport")
        if transport.get("kind") != "ssh":
            raise QualificationError("production qualification requires SSH transport")
        if set(transport) != {"kind", "host", "user", "port", "knownHosts"}:
            raise QualificationError(f"guests[{index}].transport has unexpected fields")
        _require_string(transport["host"], f"guests[{index}].transport.host")
        _require_string(transport["user"], f"guests[{index}].transport.user")
        port = transport["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise QualificationError(f"guests[{index}].transport.port is invalid")
        known_hosts = Path(_require_string(transport["knownHosts"], f"guests[{index}].transport.knownHosts"))
        if not known_hosts.is_file():
            raise QualificationError(f"known-hosts file is unavailable: {known_hosts}")
        normalized.append(
            {
                "guestId": guest_id,
                "distribution": distribution,
                "version": version,
                "transport": dict(transport),
                "stageCommands": _validate_stage_commands(guest["stageCommands"]),
            }
        )
        seen_ids.add(guest_id)
        seen_distributions.add(distribution)
    if seen_distributions != REQUIRED_DISTRIBUTIONS:
        raise QualificationError("guests must include Ubuntu 24.04, Debian, Fedora 44, and one rolling coordinate")
    return {
        "schema": CONFIG_FORMAT,
        "candidate": candidate,
        "acceptedReceiptDigests": list(accepted),
        "guests": normalized,
    }


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int


class GuestTransport(Protocol):
    evidence_class: str

    def run(self, argv: Sequence[str], *, timeout: int, stdin: bytes | None = None) -> CommandResult:
        """Run argv on the guest without inserting a shell."""


class SSHTransport:
    evidence_class = "real_guest"

    def __init__(self, transport: Mapping[str, Any]) -> None:
        self.host = str(transport["host"])
        self.user = str(transport["user"])
        self.port = int(transport["port"])
        self.known_hosts = str(transport["knownHosts"])

    def run(self, argv: Sequence[str], *, timeout: int, stdin: bytes | None = None) -> CommandResult:
        destination = f"{self.user}@{self.host}"
        command = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-p",
            str(self.port),
            "--",
            destination,
            *[str(item) for item in argv],
        ]
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                input=stdin,
                timeout=timeout,
                shell=False,
                text=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            detail = str(exc).encode("utf-8", errors="replace")
            return CommandResult(255, "", detail.decode("utf-8"), int((time.monotonic() - started) * 1000))
        return CommandResult(
            completed.returncode,
            completed.stdout.decode("utf-8", errors="replace"),
            completed.stderr.decode("utf-8", errors="replace"),
            int((time.monotonic() - started) * 1000),
        )


def _probe_script() -> str:
    return r'''import hashlib,json,os,re,subprocess,sys
from datetime import datetime,timezone

def run(argv):
    try:
        process=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=20)
        return {"returncode":process.returncode,"stdout":process.stdout,"stderr":process.stderr}
    except (OSError,subprocess.TimeoutExpired) as error:
        return {"returncode":255,"stdout":"","stderr":str(error)}
def digest(value): return "sha256:"+hashlib.sha256(value.encode()).hexdigest()
def file_text(path):
    try: return open(path,encoding="utf-8").read()
    except (OSError,UnicodeError): return ""
def os_release():
    result={}
    for line in file_text("/etc/os-release").splitlines():
        if "=" in line:
            key,value=line.split("=",1); result[key]=value.strip().strip('"')
    return result
def present(path): return os.path.exists(path) and not os.path.islink(path)
def mapping(path,user):
    return any(line.split(":",1)[0]==user for line in file_text(path).splitlines() if ":" in line)
def version(raw):
    match=re.search(r"(\d+)\.(\d+)\.(\d+)",raw)
    return tuple(int(item) for item in match.groups()) if match else None
guest_id=sys.argv[1]
osr=os_release(); podman=run(["podman","--version"]); info=run(["podman","info","--format","json"])
info_value={}
try: info_value=json.loads(info["stdout"])
except (TypeError,json.JSONDecodeError): pass
rootless=bool(info_value.get("host",{}).get("rootless"))
if "rootless" in info_value: rootless=bool(info_value["rootless"])
quadlet=any(present(path) for path in ("/usr/libexec/podman/quadlet","/usr/lib/podman/quadlet","/usr/lib/systemd/user-generators/podman-user-generator"))
systemd=run(["systemctl","--user","is-system-running"]); current_user=run(["id","-un"])["stdout"].strip()
kernel=run(["uname","-s"]); release=run(["uname","-r"]); arch=run(["uname","-m"]); cgroup=run(["stat","-fc","%T","/sys/fs/cgroup"])
machine=file_text("/etc/machine-id").strip(); boot=file_text("/proc/sys/kernel/random/boot_id").strip()
podman_version=podman["stdout"].replace("podman version ","").strip()
facts={"linuxKernel":kernel["stdout"].strip().lower()=="linux","wslDetected":"microsoft" in release["stdout"].strip().lower(),"architecture":arch["stdout"].strip(),"cgroupVersion":"v2" if cgroup["stdout"].strip()=="cgroup2fs" else cgroup["stdout"].strip(),"podmanVersion":podman_version,"podmanVersionMeetsFloor":version(podman_version) is not None and version(podman_version)>=(4,9,3),"rootlessPodman":rootless,"quadlet":quadlet,"systemdUserServices":systemd["returncode"]==0,"subuidMapping":mapping("/etc/subuid",current_user),"subgidMapping":mapping("/etc/subgid",current_user)}
facts["eligible"]=all((facts["linuxKernel"],not facts["wslDetected"],facts["architecture"] in ("x86_64","amd64"),facts["cgroupVersion"]=="v2",facts["podmanVersionMeetsFloor"],facts["rootlessPodman"],facts["quadlet"],facts["systemdUserServices"],facts["subuidMapping"],facts["subgidMapping"]))
print(json.dumps({"schema":"stateport.qualification-guest-observation/v1","guestId":guest_id,"observedAt":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),"machineIdDigest":digest(machine) if machine else None,"bootIdDigest":digest(boot) if boot else None,"osRelease":{"id":osr.get("ID"),"versionId":osr.get("VERSION_ID"),"prettyName":osr.get("PRETTY_NAME")},"kernel":{"name":kernel["stdout"].strip(),"release":release["stdout"].strip()},"architecture":arch["stdout"].strip(),"capabilities":facts,"commandObservations":{"podmanVersion":podman,"podmanInfo":{"returncode":info["returncode"],"stdoutDigest":digest(info["stdout"]),"stderrDigest":digest(info["stderr"])},"systemdUser":systemd,"cgroup":cgroup}},sort_keys=True))
'''


def _parse_json_output(output: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise QualificationError(f"{label} did not emit one JSON object: {exc}") from exc
    if not isinstance(value, Mapping):
        raise QualificationError(f"{label} did not emit a JSON object")
    return dict(value)


def _stage_receipt(
    *,
    guest_id: str,
    stage_id: str,
    candidate: Mapping[str, Any],
    evidence_class: str,
    result: str,
    facts: Mapping[str, Any],
    observed_at: str,
) -> dict[str, Any]:
    receipt = {
        "schema": STAGE_FORMAT,
        "guestId": guest_id,
        "stageId": stage_id,
        "candidate": dict(candidate),
        "evidenceClass": evidence_class,
        "observedAt": observed_at,
        "result": result,
        "facts": dict(facts),
    }
    return receipt


def _validate_stage_receipt(
    receipt: Mapping[str, Any], *, guest_id: str, stage_id: str, candidate: Mapping[str, Any]
) -> dict[str, Any]:
    expected = {"schema", "guestId", "stageId", "candidate", "evidenceClass", "observedAt", "result", "facts"}
    if set(receipt) != expected or receipt.get("schema") != STAGE_FORMAT:
        raise QualificationError(f"{stage_id} receipt shape is invalid")
    if receipt.get("guestId") != guest_id or receipt.get("stageId") != stage_id:
        raise QualificationError(f"{stage_id} receipt is bound to the wrong guest or stage")
    if receipt.get("candidate") != dict(candidate):
        raise QualificationError(f"{stage_id} receipt is bound to a different candidate")
    if receipt.get("evidenceClass") != "real_guest":
        raise QualificationError(f"{stage_id} receipt is not real guest evidence")
    if receipt.get("result") not in {"passed", "failed", "not_executed"}:
        raise QualificationError(f"{stage_id} receipt result is invalid")
    facts = receipt.get("facts")
    if not isinstance(facts, Mapping):
        raise QualificationError(f"{stage_id} receipt facts are invalid")
    missing = set(_STAGE_FACTS.get(stage_id, ())) - set(facts)
    if missing:
        raise QualificationError(f"{stage_id} receipt is missing facts: {sorted(missing)}")
    for key, value in facts.items():
        if key.endswith("Digest") and value is not None:
            _require_digest(value, f"{stage_id}.facts.{key}")
    if stage_id == "release_verification":
        if facts.get("releaseIndexDigest") != candidate["releaseIndexDigest"]:
            raise QualificationError("release verification is bound to a different index")
        if facts.get("signedPayloadDigest") != candidate["signedPayloadDigest"]:
            raise QualificationError("release verification is bound to a different signed payload")
        if facts.get("sourceCommit") != candidate["sourceCommit"] or facts.get("sourceTree") != candidate["sourceTree"]:
            raise QualificationError("release verification is bound to a different source identity")
        if facts.get("imageDigests") != candidate["imageDigests"]:
            raise QualificationError("release verification image inventory differs from the candidate")
        if facts.get("indexVerified") is not True or facts.get("imagesVerified") is not True:
            raise QualificationError("release verification did not independently verify the index and images")
    if stage_id == "update_rollback" and facts.get("inducedFailure") is not True:
        raise QualificationError("update_rollback must include an induced failure")
    return dict(receipt)


def _format_command(command: Sequence[str], *, guest_id: str, stage_id: str, candidate: Mapping[str, Any]) -> list[str]:
    values = {
        "guest_id": guest_id,
        "stage_id": stage_id,
        "candidate_digest": canonical_digest(candidate),
        "release_index_digest": candidate["releaseIndexDigest"],
        "signed_payload_digest": candidate["signedPayloadDigest"],
        "source_commit": candidate["sourceCommit"],
        "source_tree": candidate["sourceTree"],
    }
    return [item.format(**values) for item in command]


def _capability_facts(observation: Mapping[str, Any]) -> dict[str, Any]:
    facts = _require_mapping(observation.get("capabilities"), "guest probe capabilities")
    required = {"linuxKernel", "wslDetected", "architecture", "cgroupVersion", "podmanVersion", "podmanVersionMeetsFloor", "rootlessPodman", "quadlet", "systemdUserServices", "subuidMapping", "subgidMapping", "eligible"}
    if set(facts) != required:
        raise QualificationError("guest probe capability facts are incomplete")
    if not isinstance(facts["eligible"], bool):
        raise QualificationError("guest probe eligibility is not boolean")
    expected = all(
        (
            facts["linuxKernel"] is True,
            facts["wslDetected"] is False,
            facts["architecture"] in {"x86_64", "amd64"},
            facts["cgroupVersion"] == "v2",
            facts["podmanVersionMeetsFloor"] is True,
            facts["rootlessPodman"] is True,
            facts["quadlet"] is True,
            facts["systemdUserServices"] is True,
            facts["subuidMapping"] is True,
            facts["subgidMapping"] is True,
        )
    )
    if facts["eligible"] is not expected:
        raise QualificationError("guest probe eligibility does not match its observed capability facts")
    return dict(facts)


def _support_tier(*, eligible: bool, complete: bool, receipt_digest: str | None, accepted: Sequence[str], evidence_class: str) -> str:
    if evidence_class != "real_guest":
        return "missing_real_guest_evidence"
    if not eligible:
        return "ineligible"
    if not complete:
        return "failed"
    if receipt_digest in accepted:
        return "validated_baseline"
    return "compatible_unvalidated"


def _missing_guest(config_guest: Mapping[str, Any], candidate: Mapping[str, Any], reason: str) -> dict[str, Any]:
    stages = [
        {
            "stageId": stage,
            "status": "missing",
            "evidenceClass": "missing_real_guest",
            "receiptDigest": None,
            "receiptPath": None,
            "error": reason,
        }
        for stage in REQUIRED_STAGES
    ]
    return {
        "guestId": config_guest["guestId"],
        "requestedDistribution": config_guest["distribution"],
        "requestedVersion": config_guest["version"],
        "evidenceClass": "missing_real_guest",
        "status": "missing_real_guest_evidence",
        "supportTier": "missing_real_guest_evidence",
        "observedGuestIdentityDigest": None,
        "guestIdentity": None,
        "capabilityFacts": None,
        "receiptDigest": None,
        "receiptPath": None,
        "stages": stages,
        "error": reason,
        "candidateDigest": canonical_digest(candidate),
    }


def _guest_identity(observation: Mapping[str, Any]) -> dict[str, Any]:
    os_release = _require_mapping(observation.get("osRelease"), "guest probe osRelease")
    kernel = _require_mapping(observation.get("kernel"), "guest probe kernel")
    return {
        "observedAt": observation.get("observedAt"),
        "machineIdDigest": observation.get("machineIdDigest"),
        "bootIdDigest": observation.get("bootIdDigest"),
        "osId": os_release.get("id"),
        "versionId": os_release.get("versionId"),
        "prettyName": os_release.get("prettyName"),
        "kernel": kernel.get("name"),
        "kernelRelease": kernel.get("release"),
        "architecture": observation.get("architecture"),
    }


def run_guest(config_guest: Mapping[str, Any], candidate: Mapping[str, Any], accepted: Sequence[str], output_root: Path) -> dict[str, Any]:
    guest_id = str(config_guest["guestId"])
    guest_dir = output_root / guest_id
    guest_dir.mkdir(parents=True, exist_ok=False)
    transport = SSHTransport(_require_mapping(config_guest["transport"], f"{guest_id}.transport"))
    probe = transport.run(["python3", "-c", _probe_script(), guest_id], timeout=60)
    if probe.returncode != 0:
        return _missing_guest(config_guest, candidate, f"real guest probe failed with exit {probe.returncode}: {probe.stderr[-500:]}")
    try:
        observation = _parse_json_output(probe.stdout, f"{guest_id} guest probe")
        if observation.get("schema") != OBSERVATION_FORMAT or observation.get("guestId") != guest_id:
            raise QualificationError("guest probe identity is invalid")
        if not observation.get("machineIdDigest") or not observation.get("bootIdDigest"):
            raise QualificationError("guest probe did not observe both machine and boot identity")
        capability = _capability_facts(observation)
    except QualificationError as exc:
        return _missing_guest(config_guest, candidate, str(exc))
    (guest_dir / "guest-observation.json").write_bytes(_canonical(observation) + b"\n")
    stage_records: list[dict[str, Any]] = []
    identity_receipt = _stage_receipt(
        guest_id=guest_id,
        stage_id="guest_identity",
        candidate=candidate,
        evidence_class="real_guest",
        result="passed",
        facts={"guestObservationDigest": canonical_digest(observation), "machineIdDigest": observation["machineIdDigest"], "bootIdDigest": observation["bootIdDigest"]},
        observed_at=str(observation["observedAt"]),
    )
    capability_receipt = _stage_receipt(
        guest_id=guest_id,
        stage_id="capability_facts",
        candidate=candidate,
        evidence_class="real_guest",
        result="passed" if capability["eligible"] else "failed",
        facts={"capabilityFacts": capability, "eligible": capability["eligible"]},
        observed_at=str(observation["observedAt"]),
    )
    for receipt in (identity_receipt, capability_receipt):
        stage = receipt["stageId"]
        path = guest_dir / f"{stage}.json"
        path.write_bytes(_canonical(receipt) + b"\n")
        stage_records.append({"stageId": stage, "status": receipt["result"], "evidenceClass": "real_guest", "receiptDigest": canonical_digest(receipt), "receiptPath": str(path.relative_to(output_root))})
    if not capability["eligible"]:
        for stage in REQUIRED_STAGES[2:]:
            stage_records.append({"stageId": stage, "status": "not_executed", "evidenceClass": "real_guest", "receiptDigest": None, "receiptPath": None, "error": "capability contract is ineligible"})
        return {
            "guestId": guest_id, "requestedDistribution": config_guest["distribution"], "requestedVersion": config_guest["version"], "evidenceClass": "real_guest", "status": "ineligible", "supportTier": "ineligible", "observedGuestIdentityDigest": canonical_digest(observation), "guestIdentity": _guest_identity(observation), "capabilityFacts": capability, "receiptDigest": None, "receiptPath": None, "stages": stage_records, "error": "capability contract is ineligible", "candidateDigest": canonical_digest(candidate),
        }
    for stage in REQUIRED_STAGES[2:]:
        spec = config_guest["stageCommands"][stage]
        record: dict[str, Any] = {"stageId": stage, "status": "failed", "evidenceClass": "real_guest", "receiptDigest": None, "receiptPath": None}
        try:
            command = _format_command(spec["command"], guest_id=guest_id, stage_id=stage, candidate=candidate)
            record["commandDigest"] = _sha_text(json.dumps(command, separators=(",", ":")))
            result = transport.run(command, timeout=int(spec["timeoutSeconds"]))
            record["durationMs"] = result.duration_ms
            if result.returncode != 0:
                raise QualificationError(f"stage command exited {result.returncode}: {result.stderr[-500:]}")
            receipt = _validate_stage_receipt(_parse_json_output(result.stdout, f"{guest_id}/{stage}"), guest_id=guest_id, stage_id=stage, candidate=candidate)
            path = guest_dir / f"{stage}.json"
            path.write_bytes(_canonical(receipt) + b"\n")
            record.update({"status": receipt["result"], "receiptDigest": canonical_digest(receipt), "receiptPath": str(path.relative_to(output_root))})
        except QualificationError as exc:
            record["error"] = str(exc)
        stage_records.append(record)
    passed = all(item["status"] == "passed" for item in stage_records)
    if not passed:
        status = "failed"
    else:
        status = "complete"
    receipt_body = {
        "schema": "stateport.qualification-guest-receipt/v1",
        "guestId": guest_id,
        "requestedDistribution": config_guest["distribution"],
        "requestedVersion": config_guest["version"],
        "evidenceClass": "real_guest",
        "candidate": dict(candidate),
        "guestObservationDigest": canonical_digest(observation),
        "capabilityFacts": capability,
        "stages": stage_records,
        "status": status,
    }
    receipt_digest = canonical_digest(receipt_body) if passed else None
    receipt_path: str | None = None
    if receipt_digest is not None:
        receipt = {**receipt_body, "receiptDigest": receipt_digest}
        path = guest_dir / "guest-receipt.json"
        path.write_bytes(_canonical(receipt) + b"\n")
        receipt_path = str(path.relative_to(output_root))
    return {
        "guestId": guest_id, "requestedDistribution": config_guest["distribution"], "requestedVersion": config_guest["version"], "evidenceClass": "real_guest", "status": status, "supportTier": _support_tier(eligible=True, complete=passed, receipt_digest=receipt_digest, accepted=accepted, evidence_class="real_guest"), "observedGuestIdentityDigest": canonical_digest(observation), "guestIdentity": _guest_identity(observation), "capabilityFacts": capability, "receiptDigest": receipt_digest, "receiptPath": receipt_path, "stages": stage_records, "error": None if passed else "one or more required stages failed", "candidateDigest": canonical_digest(candidate),
    }


def build_manifest(config: Mapping[str, Any], *, output: str | Path) -> dict[str, Any]:
    candidate = _validate_candidate(config.get("candidate"))
    accepted = config.get("acceptedReceiptDigests")
    if not isinstance(accepted, list):
        raise QualificationError("acceptedReceiptDigests is missing")
    output_root = Path(output)
    if output_root.exists() or output_root.is_symlink():
        raise QualificationError(f"qualification output already exists: {output_root}")
    output_root.mkdir(parents=True)
    started = _utc_now()
    guests = config.get("guests")
    if not isinstance(guests, list):
        raise QualificationError("guests is missing")
    results: list[dict[str, Any]] = []
    for guest in guests:
        results.append(run_guest(_require_mapping(guest, "guest"), candidate, accepted, output_root))
    body: dict[str, Any] = {
        "schema": FORMAT,
        "runId": "run_" + hashlib.sha256((canonical_digest(candidate) + started).encode()).hexdigest()[:32],
        "startedAt": started,
        "finishedAt": _utc_now(),
        "harness": {"version": HARNESS_VERSION, "runnerDigest": _sha_text(Path(__file__).read_text(encoding="utf-8"))},
        "candidate": candidate,
        "acceptedReceiptDigests": list(accepted),
        "guests": results,
        "claims": {"validatedBaselineGuestIds": [item["guestId"] for item in results if item["supportTier"] == "validated_baseline"], "compatibleUnvalidatedGuestIds": [item["guestId"] for item in results if item["supportTier"] == "compatible_unvalidated"], "missingEvidenceGuestIds": [item["guestId"] for item in results if item["supportTier"] == "missing_real_guest_evidence"]},
    }
    manifest = {**body, "manifestDigest": canonical_digest(body)}
    validate_manifest(manifest)
    (output_root / "qualification-receipt-manifest.json").write_bytes(_canonical(manifest) + b"\n")
    return manifest


def validate_manifest(document: Mapping[str, Any]) -> None:
    if document.get("schema") != FORMAT:
        raise QualificationError("manifest schema is unsupported")
    required = {"schema", "runId", "startedAt", "finishedAt", "harness", "candidate", "acceptedReceiptDigests", "guests", "claims", "manifestDigest"}
    if set(document) != required:
        raise QualificationError("manifest fields are incomplete or unexpected")
    candidate = _validate_candidate(document["candidate"])
    accepted = document["acceptedReceiptDigests"]
    if (
        not isinstance(accepted, list)
        or any(not isinstance(item, str) or _DIGEST.fullmatch(item) is None for item in accepted)
        or len(accepted) != len(set(accepted))
    ):
        raise QualificationError("manifest acceptedReceiptDigests is invalid")
    digest = document["manifestDigest"]
    _require_digest(digest, "manifestDigest")
    body = dict(document); body.pop("manifestDigest")
    if digest != canonical_digest(body):
        raise QualificationError("manifestDigest is stale or tampered")
    guests = document["guests"]
    if not isinstance(guests, list) or len(guests) != 4:
        raise QualificationError("manifest must contain exactly four matrix guests")
    ids: set[str] = set(); distributions: set[str] = set()
    for guest in guests:
        item = _require_mapping(guest, "manifest guest")
        for field in ("guestId", "requestedDistribution", "requestedVersion", "evidenceClass", "status", "supportTier", "candidateDigest", "stages"):
            if field not in item: raise QualificationError(f"manifest guest is missing {field}")
        if item["guestId"] in ids or item["requestedDistribution"] in distributions: raise QualificationError("manifest guest identities or coordinates are duplicated")
        ids.add(str(item["guestId"])); distributions.add(str(item["requestedDistribution"]))
        if item["candidateDigest"] != canonical_digest(candidate): raise QualificationError("manifest guest is bound to a different candidate")
        if "guestIdentity" not in item: raise QualificationError("manifest guest is missing guestIdentity")
        if item["guestIdentity"] is not None and not isinstance(item["guestIdentity"], Mapping): raise QualificationError("manifest guest identity is invalid")
        if item["supportTier"] == "validated_baseline" and item.get("receiptDigest") not in document["acceptedReceiptDigests"]: raise QualificationError("validated baseline is not bound to an accepted receipt digest")
        if item["evidenceClass"] == "missing_real_guest" and item["supportTier"] != "missing_real_guest_evidence": raise QualificationError("missing guest evidence has an unsupported tier")
        if not isinstance(item["stages"], list) or any(not isinstance(stage, Mapping) for stage in item["stages"]): raise QualificationError("manifest guest stages are invalid")
        if [stage.get("stageId") for stage in item["stages"]] != list(REQUIRED_STAGES): raise QualificationError("manifest guest stage order is incomplete")
    if distributions != REQUIRED_DISTRIBUTIONS: raise QualificationError("manifest does not cover the required matrix")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        manifest = build_manifest(config, output=args.output)
    except (QualificationError, OSError) as exc:
        print(f"qualification: refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"manifest": str(args.output / "qualification-receipt-manifest.json"), "manifestDigest": manifest["manifestDigest"], "claims": manifest["claims"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
