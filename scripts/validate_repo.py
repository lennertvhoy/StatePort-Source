#!/usr/bin/env python3
"""Validate the StatePort repo skeleton."""

import os
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CORE_SRC = REPO_ROOT / "packages" / "statedd-core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))

from statedd_core import (
    MANIFEST_V2_FORMAT,
    LifecycleError,
    assert_production_eligible,
    load_canonical_source_descriptor,
    load_template_manifest,
    load_source_contract,
)
from statedd_core.yaml import StateDDYamlError, parse_yaml_text

REQUIRED_DOCS = [
    "README.md",
    ".gitignore",
    "LICENSE_DECISION.md",
    "docs/ARCHITECTURE.md",
    "docs/SECURITY.md",
    "docs/GDPR.md",
    "docs/NIS2_CYFUN_ALIGNMENT.md",
    "docs/AZURE_DEPLOYMENT.md",
    "docs/OPEN_CORE_MODEL.md",
    "docs/BOSS_PITCH.md",
    "docs/ROADMAP.md",
    "docs/REFERENCES.md",
    "docs/THREAT_MODEL.md",
    "docs/DATA_PROCESSING.md",
    "docs/NAMING.md",
]

REQUIRED_FOLDERS = [
    "apps/runner",
    "apps/telegram-adapter",
    "apps/admin-cli",
    "packages/statedd-core",
    "packages/template-validator",
    "packages/quota-engine",
    "packages/approval-gate",
    "packages/audit-log",
    "packages/tool-gateway",
    "templates/classdd",
    "templates/projectdd",
    "fixtures/templates/studydd-minimal",
    "instances/demo-classdd",
    "infra/azure/terraform",
    "infra/azure/terraform/envs",
]

REQUIRED_TEMPLATES = [
    "templates/classdd/template.yaml",
    "templates/projectdd/template.yaml",
    "fixtures/templates/studydd-minimal/template.yaml",
]

TERRAFORM_FILES = [
    "infra/azure/terraform/versions.tf",
    "infra/azure/terraform/providers.tf",
    "infra/azure/terraform/variables.tf",
    "infra/azure/terraform/main.tf",
    "infra/azure/terraform/outputs.tf",
    "infra/azure/terraform/locals.tf",
]

REQUIRED_LINKS = [
    "https://core.telegram.org/bots/api",
    "https://learn.microsoft.com/en-us/azure/reliability/regions-list",
    "https://learn.microsoft.com/en-us/privacy/eudb/eu-data-boundary-learn",
    "https://ccb.belgium.be/regulation/nis2",
    "https://atwork.safeonweb.be/tools-resources/cyberfundamentals-framework",
    "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs",
    "https://commission.europa.eu/law/law-topic/data-protection/rules-business-and-organisations/obligations/controllerprocessor/what-data-controller-or-data-processor_en",
]

_SECRET_VALUE = r"['\"]?[A-Za-z0-9+/=_\-]{16,}"
SECRET_PATTERNS = [
    re.compile(rf"(?i)(api[_-]?key|apikey)\s*[:=]\s*{_SECRET_VALUE}"),
    re.compile(rf"(?i)(token|secret|password)\s*[:=]\s*{_SECRET_VALUE}"),
    re.compile(r"(?i)BEGIN\s+(RSA|OPENSSH|PRIVATE)\s+KEY"),
]

SCANNED_SECRET_EXTENSIONS = {
    ".md",
    ".yaml",
    ".yml",
    ".tf",
    ".py",
    ".txt",
    ".tfvars",
    ".example",
    ".env",
}

SKIP_SECRET_CHECK = {
    ".git",
    ".venv",
    "node_modules",
    ".terraform",
    "__pycache__",
}


def check_required_docs():
    missing = []
    for doc in REQUIRED_DOCS:
        path = REPO_ROOT / doc
        if not path.is_file():
            missing.append(doc)
    if missing:
        print(f"FAIL: missing docs: {missing}")
        return False
    print("PASS: required docs present")
    return True


def check_required_folders():
    missing = []
    for folder in REQUIRED_FOLDERS:
        path = REPO_ROOT / folder
        if not path.is_dir():
            missing.append(folder)
    if missing:
        print(f"FAIL: missing folders: {missing}")
        return False
    print("PASS: required folders present")
    return True


def check_templates():
    errors = []
    for template in REQUIRED_TEMPLATES:
        path = REPO_ROOT / template
        if not path.is_file():
            source_root = path.parent
            manifest_path = source_root / ".statedd" / "manifest.yaml"
            if manifest_path.is_file():
                try:
                    manifest = load_template_manifest(source_root)
                except LifecycleError as exc:
                    errors.append(f"invalid lifecycle source in {source_root}: {exc}")
                else:
                    if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
                        continue
            errors.append(f"missing {template}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
            parse_yaml_text(text)
        except StateDDYamlError as e:
            errors.append(f"invalid YAML in {template}: {e}")
        except (OSError, UnicodeDecodeError) as e:
            errors.append(f"could not read {template}: {e}")
    if errors:
        print(f"FAIL: template checks: {errors}")
        return False
    print("PASS: template files present and valid")
    return True


def check_synthetic_fixture_boundary():
    """Ensure the legacy-named StudyState fixture cannot become a production source."""
    path = REPO_ROOT / "fixtures/templates/studydd-minimal"
    try:
        manifest = load_template_manifest(path)
        if manifest["templateId"] != "stateport.fixture.studydd-minimal":
            raise LifecycleError("fixture identity is not fixture-only")
        if manifest["sourceClass"] != "synthetic_fixture":
            raise LifecycleError("fixture source class is not synthetic")
        try:
            assert_production_eligible(manifest)
        except LifecycleError:
            pass
        else:
            raise LifecycleError("synthetic fixture was accepted for production")
    except LifecycleError as exc:
        print(f"FAIL: synthetic fixture boundary: {exc}")
        return False
    print("PASS: synthetic fixture is explicit and production-rejected")
    return True


def check_source_profiles():
    """Ensure every tracked demo source profile is explicit and immutable."""
    profile_root = REPO_ROOT / "sources" / "profiles"
    if not profile_root.is_dir():
        print("FAIL: source profile directory is missing")
        return False
    errors = []
    for path in sorted(profile_root.glob("*.yaml")):
        try:
            contract = load_source_contract(path)
            if not re.fullmatch(r"[0-9a-f]{40}", contract.commit):
                errors.append(f"{path}: commit is not immutable")
            if contract.repository.startswith("/"):
                errors.append(f"{path}: portable profile contains an absolute repository path")
        except (LifecycleError, OSError, UnicodeError, ValueError) as exc:
            errors.append(f"{path}: {exc}")
    catalog_root = REPO_ROOT / "sources" / "canonical"
    if not catalog_root.is_dir():
        errors.append("canonical source catalog directory is missing")
    else:
        for path in sorted(catalog_root.glob("*.yaml")):
            try:
                descriptor = load_canonical_source_descriptor(path)
                if descriptor.status.installable and descriptor.identity is None:
                    errors.append(f"{path}: unresolved source is installable")
                if descriptor.repository.startswith("/"):
                    errors.append(f"{path}: catalog contains an absolute repository path")
            except (LifecycleError, OSError, UnicodeError, ValueError) as exc:
                errors.append(f"{path}: {exc}")
    if errors:
        print(f"FAIL: source profiles: {errors}")
        return False
    print("PASS: source profiles and canonical catalog are explicit and fail closed")
    return True


def check_terraform():
    missing = []
    for tf_file in TERRAFORM_FILES:
        path = REPO_ROOT / tf_file
        if not path.is_file():
            missing.append(tf_file)
    if missing:
        print(f"FAIL: missing Terraform files: {missing}")
        return False
    print("PASS: Terraform scaffold present")
    return True


def check_references():
    path = REPO_ROOT / "docs" / "REFERENCES.md"
    if not path.is_file():
        print("FAIL: REFERENCES.md missing")
        return False
    content = path.read_text(encoding="utf-8")
    missing = [link for link in REQUIRED_LINKS if link not in content]
    if missing:
        print(f"FAIL: REFERENCES.md missing links: {missing}")
        return False
    print("PASS: REFERENCES.md contains required links")
    return True


def check_secrets():
    hits = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_SECRET_CHECK]
        for filename in files:
            ext = Path(filename).suffix.lower()
            # Scan files with known text extensions plus extensionless files.
            if ext and ext not in SCANNED_SECRET_EXTENSIONS:
                continue
            filepath = Path(root) / filename
            try:
                text = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for pattern in SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    line = text[:match.start()].count("\n") + 1
                    hits.append(f"{filepath.relative_to(REPO_ROOT)}:{line}")
    if hits:
        print(f"WARN: possible secrets detected (review manually): {hits}")
        # Treat as warning, not failure, because patterns can false-positive.
        return True
    print("PASS: no obvious secrets detected")
    return True


def check_statedd_schema():
    """Run the standalone StateSpec schema validator and propagate its exit code."""
    validator = REPO_ROOT / "scripts" / "statedd_validate_schema.py"
    try:
        subprocess.run(
            [sys.executable, str(validator), str(REPO_ROOT)],
            check=True,
        )
    except subprocess.CalledProcessError:
        print("FAIL: StateSpec schema validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run StateSpec validator: {exc}")
        return False
    print("PASS: StateSpec schema validation passed")
    return True


def check_statespec_schema_registry():
    """Resolve every tracked lifecycle schema ID and validate generated locks."""
    validator = REPO_ROOT / "scripts" / "validate_statespec_schema_registry.py"
    try:
        subprocess.run([sys.executable, str(validator)], check=True)
    except subprocess.CalledProcessError:
        print("FAIL: StateSpec logical schema registry validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run StateSpec schema registry validator: {exc}")
        return False
    print("PASS: StateSpec logical schemas and generated lock variants passed")
    return True


def check_terminology_policy():
    """Require the public naming and compatibility migration boundary."""
    validator = REPO_ROOT / "scripts" / "validate_terminology_policy.py"
    try:
        subprocess.run([sys.executable, str(validator)], check=True)
    except subprocess.CalledProcessError:
        print("FAIL: terminology policy validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run terminology policy validator: {exc}")
        return False
    print("PASS: Stateware public terminology and compatibility policy passed")
    return True


def check_projectstate_contract():
    """Validate coordination structure without pretending an in-progress journey passed."""
    try:
        from projectstate_gate import validate

        errors, blockers, warnings = validate(REPO_ROOT)
    except (ImportError, OSError, ValueError) as exc:
        print(f"FAIL: could not validate ProjectState contract: {exc}")
        return False
    if errors:
        for error in errors:
            print(f"FAIL: ProjectState contract: {error}")
        return False
    for warning in warnings:
        print(f"WARN: ProjectState: {warning}")
    if blockers:
        print("INFO: ProjectState outcome remains in progress:")
        for blocker in blockers:
            print(f"  - {blocker}")
    print("PASS: ProjectState coordination contract is structurally valid")
    return True


def check_release_disposition():
    """Validate the release work disposition ledger (PRs #8-#21 authority)."""
    validator = REPO_ROOT / "scripts" / "validate_release_disposition.py"
    try:
        subprocess.run(
            [sys.executable, str(validator), str(REPO_ROOT)],
            check=True,
        )
    except subprocess.CalledProcessError:
        print("FAIL: release disposition validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run release disposition validator: {exc}")
        return False
    print("PASS: release disposition validation passed")
    return True


def check_workspace_lifecycle():
    """Require one fail-closed leased and bounded managed-workspace authority."""
    validator = REPO_ROOT / "scripts" / "validate_workspace_lifecycle.py"
    try:
        subprocess.run([sys.executable, str(validator)], check=True)
    except subprocess.CalledProcessError:
        print("FAIL: workspace lifecycle validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run workspace lifecycle validator: {exc}")
        return False
    print("PASS: managed workspace lifecycle validation passed")
    return True


def check_authority_policy():
    """Require typed bounded delegation and receipt-bearing action enforcement."""
    validator = REPO_ROOT / "scripts" / "validate_authority_policy.py"
    try:
        subprocess.run([sys.executable, str(validator)], check=True)
    except subprocess.CalledProcessError:
        print("FAIL: authority policy validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run authority policy validator: {exc}")
        return False
    print("PASS: bounded delegation authority validation passed")
    return True


def check_release_guard():
    """Require command-, head-, and single-use-bound release admission."""
    validator = REPO_ROOT / "scripts" / "release_guard.py"
    try:
        subprocess.run([sys.executable, str(validator), "validate"], check=True)
    except subprocess.CalledProcessError:
        print("FAIL: release guard validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run release guard validator: {exc}")
        return False
    print("PASS: protected release actions require exact single-use admission")
    return True


def check_public_snapshot_tooling():
    """Require active exact-path export, materialization, rights, and audit contracts."""
    required = (
        "config/public-export-allowlist.v1.yaml",
        "schemas/public-export-manifest.v1.schema.json",
        "schemas/rights-inventory.v1.schema.json",
        "scripts/export_public_candidate.py",
        "scripts/materialize_public_snapshot.py",
        "scripts/public_snapshot_audit.py",
    )
    missing = [path for path in required if not (REPO_ROOT / path).is_file()]
    if missing:
        print(f"FAIL: public snapshot tooling is incomplete: {missing}")
        return False
    try:
        from export_public_candidate import _classify, load_policy

        policy = load_policy((REPO_ROOT / required[0]).read_bytes())
        source_paths = sorted(
            set(
                subprocess.check_output(
                    ["git", "-C", str(REPO_ROOT), "ls-files", "--cached"],
                    text=True,
                ).splitlines()
            )
        )
        selected_paths = sorted(path for rule in policy.rules for path in rule.paths)
        if selected_paths != source_paths:
            raise ValueError("exact-path policy does not cover the current source once")
        if policy.default.classification != "unresolved-blocking":
            raise ValueError("future source paths do not default to blocking")
        if _classify("future/unreviewed.py", policy).classification != "unresolved-blocking":
            raise ValueError("future source path unexpectedly inherits public authority")
        if _classify("apps/web/assets/brand/stateport-mascot-shell.svg", policy).classification != "private-internal":
            raise ValueError("asset without established redistribution rights is not private")
        for schema_path in required[1:3]:
            schema = json.loads((REPO_ROOT / schema_path).read_text(encoding="utf-8"))
            if not isinstance(schema, dict) or "$id" not in schema:
                raise ValueError(f"{schema_path} is not an identified JSON schema")
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: public snapshot tooling validation failed: {exc}")
        return False
    print("PASS: exact-path public snapshot tooling and rights contracts are valid")
    return True


def check_local_artifact_safety():
    """Keep staged/generated/operator artifacts outside committed-source authority."""
    validator = REPO_ROOT / "scripts" / "validate_local_artifacts.py"
    try:
        subprocess.run([sys.executable, str(validator)], check=True)
    except subprocess.CalledProcessError:
        print("FAIL: local artifact safety validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run local artifact safety validator: {exc}")
        return False
    return True


def check_candidate_provenance():
    """Require every live external candidate identity to have a typed recovery contract."""
    validator = REPO_ROOT / "scripts" / "validate_candidate_provenance.py"
    try:
        subprocess.run([sys.executable, str(validator)], check=True)
    except subprocess.CalledProcessError:
        print("FAIL: candidate provenance validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run candidate provenance validator: {exc}")
        return False
    return True


def check_python_dependency_policy():
    """Require exact hashed image/test dependencies and separate optional providers."""
    validator = REPO_ROOT / "scripts" / "validate_python_dependency_policy.py"
    try:
        subprocess.run([sys.executable, str(validator)], check=True)
    except subprocess.CalledProcessError:
        print("FAIL: Python dependency supply-chain validation failed")
        return False
    except FileNotFoundError as exc:
        print(f"FAIL: could not run Python dependency validator: {exc}")
        return False
    return True


def main():
    print(f"Validating StatePort repo at {REPO_ROOT}")
    results = [
        check_required_docs(),
        check_required_folders(),
        check_templates(),
        check_synthetic_fixture_boundary(),
        check_source_profiles(),
        check_terraform(),
        check_references(),
        check_secrets(),
        check_statedd_schema(),
        check_statespec_schema_registry(),
        check_terminology_policy(),
        check_projectstate_contract(),
        check_release_disposition(),
        check_workspace_lifecycle(),
        check_candidate_provenance(),
        check_python_dependency_policy(),
        check_authority_policy(),
        check_release_guard(),
        check_public_snapshot_tooling(),
    ]
    if all(results):
        print("\nOK: validation passed")
        return 0
    else:
        print("\nERROR: validation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
