from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from validate_local_artifacts import LocalArtifactPolicyError, inspect, load_policy, validate_ignore_contract


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "local-artifact-policy.v1.json"


def _git(repository: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repository), *args], check=True, capture_output=True)


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.email", "test@stateport.invalid")
    _git(repository, "config", "user.name", "StatePort Test")
    (repository / ".gitignore").write_text(
        "/.commandcode/\n/.stateport-local/\n/apps/web/playwright-report/\n/apps/web/test-results/\n/docs/audit/\n/release-output/\n",
        encoding="utf-8",
    )
    (repository / ".dockerignore").write_text(
        ".commandcode\n.stateport-local\napps/web/playwright-report\napps/web/test-results\ndocs/audit\nrelease-output\n",
        encoding="utf-8",
    )
    (repository / "safe.py").write_text("print('safe')\n", encoding="utf-8")
    _git(repository, "add", ".gitignore", ".dockerignore", "safe.py")
    _git(repository, "commit", "--quiet", "-m", "base")
    return repository


def test_exact_policy_and_clean_tree_pass() -> None:
    policy = load_policy(POLICY)
    assert policy.local_roots[0] == (".commandcode", "agent_tool_local_metadata")
    validate_ignore_contract(ROOT, POLICY)


def test_source_like_untracked_path_is_detected_separately(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "new_source.py").write_text("print('new')\n", encoding="utf-8")
    findings = inspect(repository, POLICY)
    assert [(item.code, item.path) for item in findings] == [("untracked_source_like_path", "new_source.py")]


@pytest.mark.parametrize(
    "path",
    [
        ".commandcode/settings.json",
        "release-output/runtime.sqlite3",
        "docs/audit/private-report.md",
        "apps/web/test-results/trace.zip",
        ".stateport-local/operator.json",
    ],
)
def test_local_root_content_cannot_be_staged(tmp_path: Path, path: str) -> None:
    repository = _repository(tmp_path)
    target = repository / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("local only\n", encoding="utf-8")
    _git(repository, "add", "-f", path)
    findings = inspect(repository, POLICY)
    assert any(item.code == "local_artifact_tracked" and item.path == path for item in findings)


def test_generated_database_outside_local_root_is_rejected(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "runtime.sqlite3").write_bytes(b"SQLite format 3\x00")
    findings = inspect(repository, POLICY)
    assert [(item.code, item.path) for item in findings] == [
        ("generated_or_sensitive_artifact_untracked", "runtime.sqlite3")
    ]


def test_policy_rejects_absolute_or_unsorted_roots(tmp_path: Path) -> None:
    value = json.loads(POLICY.read_text(encoding="utf-8"))
    value["localRoots"][0]["path"] = "/tmp/private"
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(LocalArtifactPolicyError, match="repository-relative"):
        load_policy(path)
