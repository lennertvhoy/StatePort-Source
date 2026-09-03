#!/usr/bin/env python3
"""Run the provider-free StatePort + StudyState local-alpha proof.

The demonstration owns every temporary path it creates. It resolves a local
StudyState checkout by its exact Git commit, materializes an instance through the
existing StatePort lifecycle CLI, inspects it, builds a disposable StatePack,
runs the production-ineligible synthetic executor, creates/restores a backup,
and records an upgrade conflict without applying an unapproved plan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

for relative in (
    "packages/statedd-core/src",
    "packages/diagnostics/src",
    "packages/execution-host/src",
    "packages/synthetic-executor/src",
):
    sys.path.insert(0, str(ROOT / relative))

from execution_host.contracts import AgentRunSpec, CapabilityRequest  # noqa: E402
from statedd_core import (  # noqa: E402
    BUILTIN_STUDYDD_PROFILE,
    SourceContract,
    SourceSelectionError,
    build_state_ir,
    build_state_pack,
    load_builtin_source_contract,
    load_source_contract,
    resolve_source_contract,
)
from synthetic_executor import Scenario, SyntheticExecutor, assert_production_ineligible  # noqa: E402


def _run(command: list[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr[-1200:]}")
    return result


def _json_command(command: list[str], *, cwd: Path) -> dict[str, Any]:
    result = _run(command, cwd=cwd)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"command did not emit JSON: {' '.join(command)}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"command emitted a non-object JSON value: {' '.join(command)}")
    return value


def _studydd_demo_summary(studydd_root: Path) -> dict[str, Any]:
    """Run the public StudyState replay across supported script generations.

    Older public-safe StudyState replay scripts emit a human transcript rather
    than JSON.  The StatePort proof only needs a bounded synthetic marker, so
    retain compatibility without scraping learner content or treating the
    transcript as a data contract.
    """
    script = studydd_root / "scripts/run_demo_replay.py"
    help_result = _run([sys.executable, str(script), "--help"], cwd=studydd_root, check=False)
    if "--json" in help_result.stdout:
        result = _run([sys.executable, str(script), "--json"], cwd=studydd_root)
        return json.loads(result.stdout)
    result = _run([sys.executable, str(script)], cwd=studydd_root)
    return {
        "formatVersion": "studydd.public-demo-transcript/v1",
        "syntheticOnly": True,
        "transcriptCompleted": result.returncode == 0,
    }


def _digest_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts or ".studydd" in path.parts:
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return "sha256:" + digest.hexdigest()


def _statepack_and_run(instance: Path, template: Path) -> dict[str, Any]:
    ir = build_state_ir(instance, template_path=template)
    pack = build_state_pack(
        ir,
        task="StudyState local-alpha synthetic tutor interaction",
        model="synthetic/local-alpha",
        budget_tokens=512,
        profile="compact",
        selection="eager",
    )
    pack_json = json.dumps(pack.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    pack_digest = "sha256:" + hashlib.sha256(pack_json.encode("utf-8")).hexdigest()
    spec = AgentRunSpec(
        run_id="run-local-alpha-001",
        instance_id=ir.instance_id,
        source_revision=ir.source_revision,
        objective="StudyState local-alpha synthetic tutor interaction",
        statepack_reference="inline-statepack:" + pack_digest[7:],
        statepack_digest=pack_digest,
        required_capabilities=(
            CapabilityRequest("repositoryInstructions"),
            CapabilityRequest("nonInteractiveExecution"),
        ),
        optional_capabilities=("structuredEvents", "changedFileReporting", "tokenTelemetry"),
        backend_id="synthetic",
        adapter_id="synthetic-executor",
        adapter_version="1.0.0",
        model_identifier="synthetic/local-alpha",
        authentication_route_class="external_manual",
        permitted_capabilities=(),
        sandbox_profile="synthetic-no-execution",
        budgets={"token": 512, "costMinor": 0, "timeSeconds": 1, "steps": 8},
        validation_commands=(),
        required_output_artifacts=(),
        benchmark_configuration={"contextPolicy": "eager", "statepackFormat": pack.manifest["formatVersion"]},
        approval_required_level="external_manual",
        repository_instructions=("Synthetic fixture only; never mutate canonical state.",),
    )
    executor = SyntheticExecutor()
    assert_production_ineligible(executor)
    before = _digest_tree(instance)
    trace = executor.run(executor.prepare(spec, scenario=Scenario.SUCCESS))
    after = _digest_tree(instance)
    approval_trace = executor.run(executor.prepare(spec, scenario=Scenario.APPROVAL_REQUIRED))
    return {
        "statePackDigest": pack_digest,
        "includedFiles": len(pack.manifest.get("includedFiles", [])),
        "excludedFiles": len(pack.manifest.get("excludedFiles", [])),
        "runSpecDigest": spec.digest,
        "syntheticRunResult": {
            "status": trace.run_result["executionStatus"],
            "eventDigest": trace.event_digest,
            "eventCount": len(trace.events),
            "changedFileProposals": len(trace.changed_file_proposals),
            "productionEligible": trace.production_eligible,
        },
        "approvalScenario": {
            "status": approval_trace.run_result["executionStatus"],
            "failureClassification": approval_trace.run_result["failureClassification"],
        },
        "runResultDidNotMutateCanonicalState": before == after,
    }


def _complete_upgrade_proof(studydd_root: Path, target: str) -> dict[str, Any]:
    """Run StudyState's authoritative synthetic lifecycle proof and summarize it."""
    proof_script = ROOT / "scripts" / "test_complete_studydd_upgrade.py"
    if not proof_script.is_file():
        raise RuntimeError(f"StudyState upgrade proof is missing: {proof_script}")
    result = _run(
        [
            sys.executable,
            str(proof_script),
            "--studydd-root",
            str(studydd_root),
            "--target",
            target,
        ],
        cwd=ROOT,
    )
    proof = json.loads(result.stdout)
    return {
        "targetCommit": proof["target"]["resolvedCommit"],
        "targetTree": proof["target"]["resolvedTree"],
        "initialPlanDigest": proof["planDigest"],
        "conflictPlanDigest": proof["conflictPlanDigest"],
        "ejectedPlanDigest": proof["ejectedPlanDigest"],
        "conflict": proof["conflict"],
        "ejection": proof["ejection"],
        "approvalIdentity": proof["approvalIdentity"],
        "rollback": {
            "byteIdentical": proof["rollback"]["byteIdentical"],
        },
        "successfulApply": proof["receiptIdentity"],
        "learnerStatePreserved": proof["preservation"]["learnerStatePreserved"],
        "idempotentRerun": proof["idempotentRerun"],
    }


def _select_source(
    *,
    profile: str | None,
    repository: str | None,
    commit: str | None,
    template_id: str | None,
    expected_tree: str | None,
    expected_manifest_digest: str | None,
) -> tuple[SourceContract, Path | None]:
    if profile is not None:
        from diagnostics import Diagnostic

        try:
            contract = (
                load_builtin_source_contract(profile)
                if profile == BUILTIN_STUDYDD_PROFILE
                else load_source_contract(profile)
            )
        except ValueError as exc:
            raise SourceSelectionError(
                Diagnostic(
                    "SP-SOURCE-IDENTITY-MISMATCH",
                    "error",
                    "source",
                    "The selected source profile is invalid.",
                    {"repository": "<profile>", "requestedRef": profile, "profileError": str(exc)},
                    "Use the versioned built-in StudyState profile or a source profile that declares an exact commit and canonical source policy.",
                    ("source profile",),
                )
            ) from exc
        if commit is not None and commit.lower() != contract.commit:
            raise SourceSelectionError(
                Diagnostic(
                    "SP-SOURCE-IDENTITY-MISMATCH", "error", "source",
                    "The requested commit conflicts with the immutable source profile.",
                    {"repository": contract.repository, "requestedRef": commit},
                    "Use the exact commit declared by the selected versioned profile.",
                    ("source profile",),
                )
            )
        if template_id is not None and template_id != contract.template_id:
            raise SourceSelectionError(
                Diagnostic(
                    "SP-SOURCE-TEMPLATE-ID-MISMATCH", "error", "source",
                    "The requested template ID conflicts with the immutable source profile.",
                    {"repository": contract.repository, "requestedRef": contract.commit, "expectedTemplateId": contract.template_id, "requestedTemplateId": template_id},
                    "Use the template ID declared by the selected versioned profile.",
                    ("source profile",),
                )
            )
        if expected_tree is not None and expected_tree.lower() != contract.expected_tree:
            raise SourceSelectionError(
                Diagnostic(
                    "SP-SOURCE-IDENTITY-MISMATCH", "error", "source",
                    "The requested tree conflicts with the immutable source profile.",
                    {"repository": contract.repository, "requestedRef": contract.commit, "expectedTree": contract.expected_tree, "requestedTree": expected_tree},
                    "Use the tree declared by the selected versioned profile.",
                    ("source profile",),
                )
            )
        if (
            expected_manifest_digest is not None
            and expected_manifest_digest.lower() != contract.expected_manifest_digest
        ):
            raise SourceSelectionError(
                Diagnostic(
                    "SP-SOURCE-IDENTITY-MISMATCH", "error", "source",
                    "The requested manifest digest conflicts with the immutable source profile.",
                    {"repository": contract.repository, "requestedRef": contract.commit, "expectedManifestDigest": contract.expected_manifest_digest},
                    "Use the manifest digest declared by the selected versioned profile.",
                    ("source profile",),
                )
            )
        return contract, Path(repository).expanduser() if repository is not None else None
    if repository is None or commit is None or template_id is None:
        from diagnostics import Diagnostic

        raise SourceSelectionError(
            Diagnostic(
                "SP-SOURCE-EXPLICIT-REQUIRED",
                "error",
                "source",
                "The local-alpha demo requires an explicit source profile or repository, exact commit, and template ID.",
                {
                    "repository": "<not-supplied>",
                    "requestedRef": "<not-supplied>",
                    "acceptedInputs": ["--source-profile", "--source-repository + --source-commit + --source-template-id"],
                },
                "Select the versioned built-in StudyState profile or supply all immutable source arguments; the demo will not search ambient checkouts.",
                ("source contract",),
            )
        )
    return (
        SourceContract(
            "stateport.source-contract/v1",
            template_id,
            repository,
            commit,
            ".statedd/manifest.yaml",
            expected_tree,
            expected_manifest_digest,
            "canonical_source",
            True,
            None,
        ),
        None,
    )


def run_demo(
    *,
    source_profile: str | None = None,
    source_repository: str | None = None,
    source_commit: str | None = None,
    source_template_id: str | None = None,
    source_tree: str | None = None,
    source_manifest_digest: str | None = None,
    source_checkout: str | None = None,
) -> dict[str, Any]:
    contract, repository_override = _select_source(
        profile=source_profile,
        repository=source_repository,
        commit=source_commit,
        template_id=source_template_id,
        expected_tree=source_tree,
        expected_manifest_digest=source_manifest_digest,
    )
    with tempfile.TemporaryDirectory(prefix="stateport-local-alpha-") as raw:
        root = Path(raw)
        instances_root = root / "instances"
        instance = instances_root / "studydd-alpha"
        if repository_override is not None:
            # A local mirror may be on an evidence successor branch. Resolve
            # the profile's exact commit in a disposable detached checkout;
            # never inspect or move the caller's checkout in place.
            source_checkout_path = root / "source-checkout"
            _run(["git", "clone", "--no-checkout", str(repository_override), str(source_checkout_path)], cwd=ROOT)
            _run(["git", "checkout", "--detach", contract.commit], cwd=source_checkout_path)
            _run(["git", "remote", "set-url", "origin", contract.repository], cwd=source_checkout_path)
            # Resolve it as the canonical remote contract against this
            # already-materialised checkout, so the mirror path is never part
            # of source identity.
            repository_override = None
        elif source_checkout is not None:
            source_checkout_path = Path(source_checkout).expanduser()
        elif "://" in contract.repository:
            source_checkout_path = root / "source-checkout"
        else:
            source_checkout_path = None
        resolved = resolve_source_contract(
            contract,
            repository_override=repository_override,
            checkout_path=source_checkout_path,
        )
        studydd_root = resolved.root
        source_commit = resolved.descriptor["resolvedCommit"]
        source_tree = resolved.descriptor["resolvedTree"]
        _run(
            [
                str(ROOT / "stateport"),
                "create-instance",
                str(studydd_root),
                str(instance),
                "--id",
                "studydd-local-alpha",
                "--name",
                "StudyState local alpha",
                "--owner-name",
                "Synthetic Owner",
                "--owner-handle",
                "synthetic",
            ],
            cwd=ROOT,
        )
        doctor = _json_command([str(ROOT / "stateport"), "doctor", "--root", str(ROOT), "--json"], cwd=ROOT)
        catalog = _json_command(
            [str(ROOT / "stateport"), "catalog", "--root", str(root), "register", str(instance), "--instance-id", "studydd-local-alpha", "--json"],
            cwd=ROOT,
        )
        source = _json_command(
            [
                str(ROOT / "stateport"),
                "source-resolve",
                str(studydd_root),
                "--ref",
                source_commit,
                "--expected-commit",
                source_commit,
            ],
            cwd=ROOT,
        )
        statepack = _statepack_and_run(instance, studydd_root)
        backup_path = root / "studydd-alpha.tar"
        backup = _json_command([str(ROOT / "stateport"), "backup", "create", str(instance), str(backup_path), "--json"], cwd=ROOT)
        restore_dry = _json_command([str(ROOT / "stateport"), "backup", "restore", str(backup_path), str(root / "restored"), "--dry-run", "--json"], cwd=ROOT)

        studydd_demo = _studydd_demo_summary(studydd_root)
        upgrade = _complete_upgrade_proof(studydd_root, source_commit)
        statebench = _json_command(
            [
                sys.executable,
                str(ROOT / "scripts/statebench_local_alpha.py"),
                "--candidate-commit",
                source_commit,
                "--candidate-tree",
                source_tree,
            ],
            cwd=ROOT,
        )
        return {
            "formatVersion": "stateport.local-alpha-demo/v1",
            "providerContacted": False,
            "credentialsUsed": False,
            "publicEvidenceSafe": True,
            "doctor": {"ok": doctor.get("ok"), "warningCount": doctor.get("warnings", 0)},
            "source": {
                "templateId": contract.template_id,
                "repository": resolved.descriptor["repository"],
                "commit": source.get("resolvedCommit"),
                "tree": source.get("resolvedTree"),
                "manifestPath": contract.manifest_path,
                "manifestDigest": resolved.descriptor["manifestDigest"],
                "sourceDigest": resolved.descriptor["sourceDigest"],
                "matchesContract": (
                    source.get("resolvedCommit") == contract.commit
                    and (contract.expected_tree is None or source.get("resolvedTree") == contract.expected_tree)
                    and (
                        contract.expected_manifest_digest is None
                        or resolved.descriptor["manifestDigest"] == contract.expected_manifest_digest
                    )
                ),
            },
            "instance": {"id": catalog.get("instanceId"), "pathState": catalog.get("pathState"), "canonicalDigest": _digest_tree(instance)},
            "statepackAndExecution": statepack,
            "backup": {
                "archiveDigest": backup.get("archiveDigest"),
                "dryRunRestore": restore_dry.get("dryRun"),
                "governedMutationPerformed": False,
                "restoreMutationContract": "stateport.restore-plan/v1",
            },
            "upgradePlan": upgrade,
            "studyddDemo": {"formatVersion": studydd_demo.get("formatVersion"), "treeDigest": studydd_demo.get("instance", {}).get("treeDigest"), "syntheticOnly": studydd_demo.get("syntheticOnly")},
            "stateBench": {
                "formatVersion": statebench.get("formatVersion"),
                "resultTier": statebench.get("resultTier"),
                "configurationIds": {
                    "baseline": statebench.get("configurations", {}).get("baseline", {}).get("configurationId"),
                    "selected": statebench.get("configurations", {}).get("selected", {}).get("configurationId"),
                },
                "objectiveMetrics": statebench.get("objectiveMetrics"),
            },
            "limitations": [
                "The alpha demo records a managed-file conflict but does not auto-apply an upgrade.",
                "Synthetic execution is explicitly test-only and never writes canonical state.",
                "The standalone proof performs restore dry-run only; managed restore requires the exact plan, approval, and receipt transaction.",
                "No live provider, managed host session, cloud resource, or credential route is used.",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-profile",
        default=None,
        help="versioned source profile path or builtin:studydd-local-alpha",
    )
    parser.add_argument(
        "--source-repository",
        "--studydd-root",
        dest="source_repository",
        default=None,
        help="explicit remote URL or local Git mirror; --studydd-root is a compatibility alias",
    )
    parser.add_argument("--source-commit", default=None)
    parser.add_argument("--source-template-id", default=None)
    parser.add_argument("--source-tree", default=None)
    parser.add_argument("--source-manifest-digest", default=None)
    parser.add_argument("--source-checkout", default=None)
    parser.add_argument("--json", action="store_true", help="emit structured diagnostics on expected input errors")
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                run_demo(
                    source_profile=args.source_profile,
                    source_repository=args.source_repository,
                    source_commit=args.source_commit,
                    source_template_id=args.source_template_id,
                    source_tree=args.source_tree,
                    source_manifest_digest=args.source_manifest_digest,
                    source_checkout=args.source_checkout,
                ),
                sort_keys=True,
                indent=2,
            )
        )
        return 0
    except SourceSelectionError as exc:
        payload = {"ok": False, "error": exc.diagnostic.to_dict(), "exitCode": 2}
        if args.json:
            print(json.dumps(payload, sort_keys=True, indent=2))
        else:
            diagnostic = exc.diagnostic
            print(
                f"{diagnostic.code.value} {diagnostic.severity.value} "
                f"[{diagnostic.component.value}] {diagnostic.explanation}"
            )
            print(f"  details: {json.dumps(diagnostic.details, sort_keys=True)}")
            print(f"  remediation: {diagnostic.remediation}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
