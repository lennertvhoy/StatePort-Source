from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from validate_python_dependency_policy import PythonDependencyPolicyError, validate


ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for relative in (
        "config/python-dependency-policy.v1.json",
        "config/provider-runtime-inputs.yaml",
        "config/codex-runtime/package.json",
        "config/codex-runtime/package-lock.json",
        "config/python-dependency-licenses.v1.json",
        "requirements/runtime-linux-amd64.in",
        "requirements/runtime-linux-amd64.txt",
        "requirements/dev-test.in",
        "requirements/dev-test.txt",
        "requirements/provider-extras.in",
        "apps/api/Dockerfile",
        "apps/runner/Dockerfile",
        "apps/web/Dockerfile",
        "apps/worker/Dockerfile",
    ):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    return root


def test_repository_python_dependencies_are_closed_and_hashed() -> None:
    result = validate(ROOT)
    assert result == {"runtimePackages": 1, "developmentPackages": 13, "licensedPackages": 13}


def test_best_effort_provider_install_is_rejected(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    dockerfile = root / "apps" / "web" / "Dockerfile"
    dockerfile.write_text(dockerfile.read_text(encoding="utf-8") + "\nRUN pip install openai || true\n", encoding="utf-8")
    with pytest.raises(PythonDependencyPolicyError, match="best-effort"):
        validate(root)


def test_missing_hash_is_rejected(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    lock = root / "requirements" / "runtime-linux-amd64.txt"
    lock.write_text("PyYAML==6.0.3\n", encoding="utf-8")
    with pytest.raises(PythonDependencyPolicyError, match="no SHA-256 hash"):
        validate(root)


def test_license_inventory_must_exactly_match_lock(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    path = root / "config" / "python-dependency-licenses.v1.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["packages"].pop()
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PythonDependencyPolicyError, match="exactly match"):
        validate(root)


@pytest.mark.parametrize("install", [
    "RUN pip install --require-hashes codex-cli==1.0",
    "RUN python3 -m pip install --require-hashes codex_cli==1.0",
    "RUN pip3 install --require-hashes codex-cli==1.0",
    "RUN python3 -m pip --disable-pip-version-check install --require-hashes codex.cli==1.0",
])
def test_obsolete_pypi_codex_install_is_rejected(tmp_path: Path, install: str) -> None:
    root = _fixture(tmp_path)
    path = root / "apps/web/Dockerfile"
    path.write_text(path.read_text() + "\n" + install + "\n")
    with pytest.raises(PythonDependencyPolicyError, match="undeclared provider install"):
        validate(root)


@pytest.mark.parametrize("mutation", ["wrong-provider", "unhashed-native", "wrong-native-digest", "unverified-copy"])
def test_native_provider_requires_declared_integrity_locked_import(tmp_path: Path, mutation: str) -> None:
    root = _fixture(tmp_path)
    if mutation == "wrong-provider":
        path = root / "config/codex-runtime/package.json"
        value = json.loads(path.read_text())
        value["dependencies"] = {"@other/provider": "0.146.0"}
        path.write_text(json.dumps(value))
    elif mutation in ("unhashed-native", "wrong-native-digest"):
        path = root / "config/codex-runtime/package-lock.json"
        value = json.loads(path.read_text())
        entry = value["packages"]["node_modules/@openai/codex-linux-x64"]
        if mutation == "unhashed-native":
            del entry["integrity"]
        else:
            entry["integrity"] = "sha512-" + "A" * 86 + "=="
        path.write_text(json.dumps(value))
    else:
        path = root / "apps/web/Dockerfile"
        path.write_text(path.read_text().replace("cp node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex /out/codex", "cp /tmp/unverified-codex /out/codex"))
    with pytest.raises(PythonDependencyPolicyError, match="unverified native provider"):
        validate(root)


def test_unhashed_python_install_is_still_rejected(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    path = root / "apps/web/Dockerfile"
    path.write_text(path.read_text() + "\nRUN pip install --no-cache-dir requests==2.32.4\n")
    with pytest.raises(PythonDependencyPolicyError, match="unhashed pip install"):
        validate(root)
