#!/usr/bin/env python3
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/contribution-bundle/src"))
sys.path.insert(0, str(ROOT / "packages/statedd-core/src"))
from contribution_bundle import build_bundle


def test_bundle_only_contains_changed_public_template_files() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        base = root / "base"
        candidate = root / "candidate"
        shutil.copytree(ROOT / "templates/classdd", base)
        shutil.copytree(base, candidate)
        (candidate / "README.md").write_text("updated public template\n", encoding="utf-8")
        bundle = build_bundle(base, candidate, evidence=["pytest:test_public_change"], version_bump="0.2.0")
        assert bundle["status"] == "needs_review"
        assert bundle["privateContentIncluded"] is False
        assert bundle["files"] == ["README.md"]


def test_bundle_requires_evidence_and_changes() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir) / "base"
        candidate = Path(tmpdir) / "candidate"
        shutil.copytree(ROOT / "templates/classdd", base)
        shutil.copytree(base, candidate)
        try:
            build_bundle(base, candidate, evidence=[], version_bump="0.2.0")
        except ValueError:
            pass
        else:
            raise AssertionError("missing evidence must fail")
        (candidate / "README.md").write_text("changed\n", encoding="utf-8")
        try:
            build_bundle(base, candidate, evidence=["test"], version_bump="")
        except ValueError:
            pass
        else:
            raise AssertionError("missing version bump must fail")


if __name__ == "__main__":
    test_bundle_only_contains_changed_public_template_files()
    test_bundle_requires_evidence_and_changes()
    print("PASS")
