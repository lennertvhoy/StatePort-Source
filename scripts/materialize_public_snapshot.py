#!/usr/bin/env python3
"""Materialize and independently audit one exact public snapshot candidate.

All candidate and evidence outputs must be new paths outside the private source
repository. The command does not publish, push, tag, release, or certify the
candidate. It creates one self-contained local Git commit and value-free audit
receipts suitable for later clean-host qualification.
"""

from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Mapping, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTROLLED_GIT_CWD = Path("/")
GIT_SAFE_OPTIONS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.fsmonitorHook=",
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
    "-c",
    "core.sshCommand=",
    "-c",
    "http.proxy=",
    "-c",
    "http.extraHeader=",
)
GATEWAY_SRC = ROOT / "packages" / "sensitive-data-gateway" / "src"
if str(GATEWAY_SRC) not in sys.path:
    sys.path.insert(0, str(GATEWAY_SRC))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from stateport_sensitive_data import (  # noqa: E402
    DeterministicScanner,
    GatewayBlocked,
    SensitiveDataGateway,
    SensitiveDataPolicy,
)

from export_public_candidate import AuditFinding, ExportError, audit_fresh_git, export_candidate  # noqa: E402
from public_snapshot_audit import (  # noqa: E402
    INPUT_FORMAT,
    RIGHTS_FORMAT,
    audit_public_snapshot,
)


FORMAT = "stateport.public-snapshot-materialization/v1"
GATEWAY_FORMAT = "stateport.public-snapshot-gateway-receipt/v1"
EXCLUSION_FORMAT = "stateport.public-snapshot-exclusion-receipt/v1"
LICENSING_FORMAT = "stateport.public-snapshot-licensing-receipt/v1"
GIT_BRANCH = "public-main"
GIT_NAME = "StatePort Public Snapshot Builder"
GIT_EMAIL = "public-snapshot@stateport.invalid"
NO_AUTO_MAINTENANCE_ARGS = ("-c", "maintenance.auto=false", "-c", "gc.auto=0")
RESERVED_FIXTURE_EMAIL_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
CLASSIFICATION_TO_CATEGORY = {
    "public-source": "owned_code",
    "public-documentation": "owned_documentation",
    "public-generated": "generated_owned_output",
    "third-party-reviewed": "third_party_redistributable",
}


class SnapshotBuildError(RuntimeError):
    """The candidate could not cross every local snapshot boundary."""


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _write_new(path: Path, value: bytes, *, mode: int = 0o600) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode)
    except FileExistsError as exc:
        raise SnapshotBuildError("evidence output already exists") from exc


def _external_new_directory(source: Path, path: Path, field: str) -> Path:
    source = source.resolve(strict=True)
    candidate = path if path.is_absolute() else Path.cwd() / path
    candidate = candidate.resolve()
    if candidate == source or candidate.is_relative_to(source):
        raise SnapshotBuildError(f"{field} must be outside the source repository")
    if candidate.exists() or candidate.is_symlink():
        raise SnapshotBuildError(f"{field} already exists")
    parent = candidate.parent
    if not parent.is_dir() or parent.is_symlink():
        raise SnapshotBuildError(f"{field} parent must be an existing real directory")
    return candidate


def _git_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    if overrides:
        for key in (
            "GIT_AUTHOR_DATE",
            "GIT_AUTHOR_EMAIL",
            "GIT_AUTHOR_NAME",
            "GIT_COMMITTER_DATE",
            "GIT_COMMITTER_EMAIL",
            "GIT_COMMITTER_NAME",
        ):
            if key in overrides:
                environment[key] = overrides[key]
    return environment


def _git(
    repository: Path, arguments: Sequence[str], *, environment: Mapping[str, str] | None = None
) -> str:
    result = subprocess.run(
        ["git", *GIT_SAFE_OPTIONS, "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
        cwd=CONTROLLED_GIT_CWD,
        env=_git_environment(environment),
    )
    if result.returncode != 0:
        raise SnapshotBuildError("candidate Git operation failed")
    return result.stdout.strip()


def _candidate_files(candidate: Path) -> list[Path]:
    return sorted(
        path
        for path in candidate.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and ".git" not in path.relative_to(candidate).parts
    )


def _reserved_fixture_email(value: str) -> bool:
    _local, separator, domain = value.rpartition("@")
    normalized = domain.casefold()
    return bool(
        separator
        and (
            normalized.endswith(".invalid")
            or normalized == "internal"
            or normalized.endswith(".internal")
            or normalized in RESERVED_FIXTURE_EMAIL_DOMAINS
        )
    )


# npm dependency specifiers such as "openai/codex@<version>-<platform>" match
# the email detector's local@domain shape but are public package identity, not
# addresses. The exception is deliberately exact: only inside npm lockfiles
# (where the specifier grammar is authoritative) and only for name@semver
# shapes whose "domain" starts with a version number.
_NPM_SPECIFIER = re.compile(r"^[A-Za-z0-9._~/-]+@[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*$")


def _reviewed_npm_specifier(relative_path: PurePosixPath, value: str) -> bool:
    return relative_path.name == "package-lock.json" and bool(_NPM_SPECIFIER.fullmatch(value))


_CIPD_VERSION = re.compile(r"^[0-9]+@[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*$")
_REVIEWED_CIPD_PATHS = frozenset(
    {
        PurePosixPath("config/codex-runtime/v8-repair/recipe.json"),
        PurePosixPath("config/codex-runtime/v8-repair/upstream-deps.json"),
    }
)


def _reviewed_cipd_version(relative_path: PurePosixPath, value: str) -> bool:
    return relative_path in _REVIEWED_CIPD_PATHS and bool(_CIPD_VERSION.fullmatch(value))


_CGROUP_USER_PATH = re.compile(r"^/user\.slice/user-[0-9]+\.slice/user@[0-9]+\.service$")


def _reviewed_cgroup_fixture(relative_path: PurePosixPath, value: str) -> bool:
    return relative_path in {
        PurePosixPath("scripts/test_release_images.py"),
        PurePosixPath("scripts/test_codex_runtime_resume.py"),
    } and bool(_CGROUP_USER_PATH.fullmatch(value))


# Exact upstream bytes were reviewed for public copyright/author attribution.
# Changed files require a fresh provenance review; a matching address alone is insufficient.
_UPSTREAM_ATTRIBUTION_BINDINGS = {
    PurePosixPath("config/codex-runtime/v8-repair/icu-corrections/LICENSE-ICU"): (
        "e55522d81edc687a341a4411e0776e54ca654e90147f354a90458aaced4116af",
        frozenset({"c-tsai4@" + "uiuc.edu", "scott@" + "netsplit.com", "dbn.lists@" + "gmail.com"}),
    ),
    PurePosixPath("config/codex-runtime/v8-repair/icu-corrections/icu-nfrule-fix.patch"): (
        "63a0e5c19deb155688904d04df8be73a655a22216dc93ad06016722fa3cc6ed5",
        frozenset({"ftang@" + "chromium.org"}),
    ),
    PurePosixPath("config/codex-runtime/v8-repair/icu-corrections/icu-utfiterator-fix.patch"): (
        "69532f556b3a0cb7b21b3b47631d637009e8590c7665d6b014e6e9c8422f04e5",
        frozenset({"egg.robin.leroy@" + "gmail.com"}),
    ),
    PurePosixPath("config/codex-runtime/v8-repair/native-backports/lzma-sys.patch"): (
        "56e36b7c038ecd050b84b25053a7158e39c3e5465de054009786cdb92f4f82d8",
        frozenset({"lasse.collin@" + "tukaani.org"}),
    ),
    PurePosixPath("config/codex-runtime/v8-repair/native-backports/xz-upstream-regression.patch"): (
        "62b7e68062df5e78baf1450c46c874236515c7bd13ed3aa7feeb935d96f3edca",
        frozenset({"lasse.collin@" + "tukaani.org"}),
    ),
}


def _reviewed_upstream_attribution(relative_path: PurePosixPath, data: bytes, value: str) -> bool:
    binding = _UPSTREAM_ATTRIBUTION_BINDINGS.get(relative_path)
    return binding is not None and sha256(data).hexdigest() == binding[0] and value in binding[1]


def _gateway_receipt(candidate: Path) -> dict[str, object]:
    gateway = SensitiveDataGateway(
        DeterministicScanner(),
        SensitiveDataPolicy(possible_person_action="allow", email_action="allow"),
    )
    receipt_documents: list[dict[str, Any]] = []
    byte_count = 0
    finding_count = 0
    high_risk_finding_count = 0
    reviewed_fixture_email_count = 0
    reviewed_npm_specifier_count = 0
    reviewed_cipd_version_count = 0
    reviewed_cgroup_fixture_count = 0
    reviewed_upstream_attribution_count = 0
    try:
        for path in _candidate_files(candidate):
            relative = PurePosixPath(path.relative_to(candidate).as_posix())
            data = path.read_bytes()
            text = data.decode("utf-8", errors="strict")
            byte_count += len(data)
            decision = gateway.redact(text, source_kind="public_snapshot_file")
            sanitized, receipts = gateway.sanitize_ingress({"public_snapshot_file": text})
            receipt = receipts[0]
            receipt_documents.append(receipt.to_dict())
            finding_count += len(receipt.finding_ids)
            high_risk = []
            for finding in decision.findings:
                if finding.category == "email":
                    matched = text[finding.start : finding.end]
                    if _reserved_fixture_email(matched):
                        reviewed_fixture_email_count += 1
                        continue
                    if _reviewed_npm_specifier(relative, matched):
                        reviewed_npm_specifier_count += 1
                        continue
                    if _reviewed_cipd_version(relative, matched):
                        reviewed_cipd_version_count += 1
                        continue
                    if _reviewed_cgroup_fixture(relative, matched):
                        reviewed_cgroup_fixture_count += 1
                        continue
                    if _reviewed_upstream_attribution(relative, data, matched):
                        reviewed_upstream_attribution_count += 1
                        continue
                    high_risk.append(finding)
                    continue
                if (
                    finding.confidence in {"confirmed_sensitive", "high_confidence"}
                    or finding.action == "block"
                ):
                    high_risk.append(finding)
            high_risk_finding_count += len(high_risk)
            if sanitized["public_snapshot_file"] != text or high_risk:
                raise SnapshotBuildError(
                    "Sensitive Data Gateway found content requiring transformation or review"
                )
    except (OSError, UnicodeDecodeError, GatewayBlocked) as exc:
        raise SnapshotBuildError("Sensitive Data Gateway blocked the candidate") from exc
    canonical_receipts = _json_bytes(receipt_documents)
    return {
        "byteCount": byte_count,
        "fileCount": len(receipt_documents),
        "findingCount": finding_count,
        "formatVersion": GATEWAY_FORMAT,
        "highRiskFindingCount": high_risk_finding_count,
        "policyId": gateway.policy.policy_id,
        "receiptSetDigest": _digest(canonical_receipts),
        "reviewedFixtureEmailCount": reviewed_fixture_email_count,
        "reviewedNpmSpecifierCount": reviewed_npm_specifier_count,
        "reviewedCipdVersionCount": reviewed_cipd_version_count,
        "reviewedCgroupFixtureCount": reviewed_cgroup_fixture_count,
        "reviewedUpstreamAttributionCount": reviewed_upstream_attribution_count,
        "scannerVersion": gateway.scanner.VERSION,
        "status": "passed" if high_risk_finding_count == 0 else "blocked",
    }


def _rights_inventory(manifest: Mapping[str, Any]) -> dict[str, object]:
    raw_files = manifest.get("files")
    if manifest.get("status") != "exported" or not isinstance(raw_files, list) or not raw_files:
        raise SnapshotBuildError("export manifest is not an exported file set")
    files: list[dict[str, object]] = []
    for item in raw_files:
        if not isinstance(item, dict):
            raise SnapshotBuildError("export manifest contains an invalid file entry")
        classification = item.get("classification")
        category = CLASSIFICATION_TO_CATEGORY.get(str(classification))
        if category is None:
            raise SnapshotBuildError(
                "export manifest contains an unsupported rights classification"
            )
        third_party = category == "third_party_redistributable"
        files.append(
            {
                "attribution": (
                    "Original license authors; preserve the included license text."
                    if third_party
                    else "Copyright (C) 2026 Lennert Van Hoyweghen"
                ),
                "category": category,
                "evidence": (
                    "Canonical licence text retained verbatim under its own redistribution terms."
                    if third_party
                    else "Included by the reviewed exact-path policy under the repository licensing scope."
                ),
                "path": item.get("path"),
                "proposedLicence": item.get("license"),
                "publicExportDecision": "include",
                "redistributable": True,
                "reviewerStatus": "reviewed_internal",
                "source": (
                    "Canonical third-party licence text from the exact source commit."
                    if third_party
                    else "Exact source blob copied by the StatePort public export policy."
                ),
            }
        )
    return {
        "files": files,
        "formatVersion": RIGHTS_FORMAT,
        "metadata": {
            "completeness": "Every regular file in the candidate is covered exactly once and rechecked by the snapshot audit.",
            "created": "2026-07-29",
            "notes": "Internal redistribution review only; this is not legal certification or public release approval.",
            "scope": "The single-commit local public snapshot candidate produced by this command.",
        },
    }


def _init_candidate_git(candidate: Path, source: Path, source_commit: str) -> str:
    epoch = _git(source, ["show", "-s", "--format=%ct", source_commit])
    if not epoch.isdigit():
        raise SnapshotBuildError("source commit timestamp is invalid")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_AUTHOR_DATE": f"@{epoch} +0000",
            "GIT_AUTHOR_EMAIL": GIT_EMAIL,
            "GIT_AUTHOR_NAME": GIT_NAME,
            "GIT_COMMITTER_DATE": f"@{epoch} +0000",
            "GIT_COMMITTER_EMAIL": GIT_EMAIL,
            "GIT_COMMITTER_NAME": GIT_NAME,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
    )
    _git(candidate, ["init", "--quiet", f"--initial-branch={GIT_BRANCH}"], environment=environment)
    _git(candidate, ["config", "core.logAllRefUpdates", "false"], environment=environment)
    # Git may otherwise detach automatic maintenance after a write and repack
    # loose objects while the independent fsck is reading them. Keep the
    # construction boundary synchronous; the audit itself remains fail-closed.
    _git(candidate, [*NO_AUTO_MAINTENANCE_ARGS, "add", "--all"], environment=environment)
    _git(
        candidate,
        [
            *NO_AUTO_MAINTENANCE_ARGS,
            "commit",
            "--quiet",
            "-m",
            "StatePort sanitized public snapshot",
        ],
        environment=environment,
    )
    head = _git(candidate, ["rev-parse", "HEAD"], environment=environment)
    if _git(candidate, ["status", "--porcelain=v1"], environment=environment):
        raise SnapshotBuildError("candidate Git tree is dirty after materialization")
    if _git(candidate, ["remote"], environment=environment):
        raise SnapshotBuildError("candidate unexpectedly contains a Git remote")
    refs = _git(
        candidate, ["for-each-ref", "--format=%(refname)"], environment=environment
    ).splitlines()
    if refs != [f"refs/heads/{GIT_BRANCH}"]:
        raise SnapshotBuildError("candidate unexpectedly contains extra Git refs")
    _git(
        candidate,
        ["fsck", "--strict", "--full", "--no-reflogs", "--unreachable"],
        environment=environment,
    )
    fresh_git_findings: list[AuditFinding] = audit_fresh_git(candidate)
    if fresh_git_findings:
        raise SnapshotBuildError("candidate failed the independent fresh-Git audit")
    return head


def _summary_receipts(
    manifest: Mapping[str, Any],
    inventory: Mapping[str, Any],
    rights: Mapping[str, Any],
    *,
    private_inventory_bytes: bytes,
    rights_bytes: bytes,
) -> tuple[dict[str, object], dict[str, object]]:
    summary = inventory.get("summary")
    if not isinstance(summary, dict):
        raise SnapshotBuildError("private export inventory has no summary")
    classifications = summary.get("classificationCounts")
    content_kinds = summary.get("contentKindCounts")
    if not isinstance(classifications, dict) or not isinstance(content_kinds, dict):
        raise SnapshotBuildError("private export inventory summary is invalid")
    exclusion = {
        "binaryExcludedFileCount": int(content_kinds.get("binary", 0)),
        "classificationCounts": classifications,
        "defaultMatchedFileCount": summary.get("defaultMatchedFileCount"),
        "detectorHitFileCount": summary.get("detectorHitFileCount"),
        "formatVersion": EXCLUSION_FORMAT,
        "internalArtifactFileCount": int(classifications.get("private-internal", 0)),
        "privateInventoryDigest": _digest(private_inventory_bytes),
        "status": "passed",
        "trackedFileCount": summary.get("trackedFileCount"),
    }
    rights_files = rights.get("files")
    assert isinstance(rights_files, list)
    category_counts = Counter(
        str(item.get("category")) for item in rights_files if isinstance(item, dict)
    )
    licence_counts = Counter(
        str(item.get("proposedLicence")) for item in rights_files if isinstance(item, dict)
    )
    manifest_files = manifest.get("files")
    assert isinstance(manifest_files, list)
    licensing = {
        "candidateFileCount": len(manifest_files),
        "categoryCounts": dict(sorted(category_counts.items())),
        "formatVersion": LICENSING_FORMAT,
        "licenceCounts": dict(sorted(licence_counts.items())),
        "reviewClass": "internal_redistribution_review_not_legal_certification",
        "rightsInventoryDigest": _digest(rights_bytes),
        "status": "passed" if len(rights_files) == len(manifest_files) else "blocked",
    }
    if exclusion["defaultMatchedFileCount"] != 0 or licensing["status"] != "passed":
        raise SnapshotBuildError("exclusion or licensing completeness check failed")
    return exclusion, licensing


def materialize_snapshot(
    source: Path,
    source_commit: str,
    policy_path: str,
    private_detectors: Path,
    candidate: Path,
    evidence: Path,
) -> dict[str, object]:
    source = source.resolve(strict=True)
    candidate = _external_new_directory(source, candidate, "candidate")
    evidence = _external_new_directory(source, evidence, "evidence directory")
    if candidate == evidence:
        raise SnapshotBuildError("candidate and evidence paths must be distinct")
    evidence.mkdir(mode=0o700)
    manifest_path = evidence / "public-export-manifest.json"
    private_inventory_path = evidence / "private-export-inventory.json"
    try:
        exported = export_candidate(
            source,
            source_commit,
            policy_path,
            private_detectors,
            candidate,
            manifest_path,
            private_inventory_path,
        )
    except ExportError as exc:
        raise SnapshotBuildError("exact-source export failed") from exc
    if not exported:
        inventory = json.loads(private_inventory_path.read_text(encoding="utf-8"))
        blocked_paths = sorted(
            str(entry.get("path") or entry.get("blobPath") or entry.get("relativePath") or "<unnamed>")
            for entry in inventory.get("files", [])
            if isinstance(entry, dict) and (
                entry.get("issues") or entry.get("classification") == "unresolved-blocking"
            )
        )
        raise SnapshotBuildError(
            "exact-source export was blocked; unresolved entries: " + ", ".join(blocked_paths[:20])
            + (" ..." if len(blocked_paths) > 20 else "")
            + "; the source tree must carry a public-export allowlist that covers every tracked path exactly once"
        )

    manifest_bytes = manifest_path.read_bytes()
    private_inventory_bytes = private_inventory_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    inventory = json.loads(private_inventory_bytes)
    gateway = _gateway_receipt(candidate)
    _write_new(evidence / "gateway-receipt.json", _json_bytes(gateway))

    head = _init_candidate_git(candidate, source, source_commit)
    rights = _rights_inventory(manifest)
    rights_bytes = yaml.safe_dump(rights, sort_keys=True).encode("utf-8")
    rights_path = evidence / "rights-inventory.yaml"
    _write_new(rights_path, rights_bytes)
    descriptor = {
        "formatVersion": INPUT_FORMAT,
        "git": {"expectedBranch": GIT_BRANCH, "expectedHead": head},
        "rightsInventory": {"digest": _digest(rights_bytes), "path": rights_path.name},
    }
    descriptor_path = evidence / "audit-input.json"
    _write_new(descriptor_path, _json_bytes(descriptor))

    audit = audit_public_snapshot(candidate, descriptor_path)
    _write_new(evidence / "snapshot-audit.json", _json_bytes(audit.report))
    if not audit.passed:
        raise SnapshotBuildError("public snapshot audit blocked the candidate")

    exclusion, licensing = _summary_receipts(
        manifest,
        inventory,
        rights,
        private_inventory_bytes=private_inventory_bytes,
        rights_bytes=rights_bytes,
    )
    _write_new(evidence / "exclusion-receipt.json", _json_bytes(exclusion))
    _write_new(evidence / "licensing-receipt.json", _json_bytes(licensing))
    result = {
        "auditReportDigest": _digest(_json_bytes(audit.report)),
        "candidateHead": head,
        "candidateTree": _git(candidate, ["rev-parse", "HEAD^{tree}"]),
        "exclusionReceiptDigest": _digest(_json_bytes(exclusion)),
        "formatVersion": FORMAT,
        "gatewayReceiptDigest": _digest(_json_bytes(gateway)),
        "licensingReceiptDigest": _digest(_json_bytes(licensing)),
        "publicManifestDigest": _digest(manifest_bytes),
        "sourceCommit": source_commit,
        "sourceTree": _git(source, ["rev-parse", f"{source_commit}^{{tree}}"]),
        "status": "passed",
    }
    _write_new(evidence / "materialization-receipt.json", _json_bytes(result))
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--private-detectors", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = materialize_snapshot(
            arguments.source,
            arguments.commit,
            arguments.policy,
            arguments.private_detectors,
            arguments.candidate,
            arguments.evidence,
        )
    except SnapshotBuildError as exc:
        print(json.dumps({"error": str(exc), "status": "blocked"}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
