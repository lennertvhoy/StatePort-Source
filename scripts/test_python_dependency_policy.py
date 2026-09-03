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
