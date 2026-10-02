#!/usr/bin/env python3
"""Focused tests for the read-only StudyDD generated-view adapter."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "stateport-compat" / "src"))

from stateport_compat import (  # noqa: E402
    CompatibilityViewError,
    load_studydd_compatibility_views,
)
from stateport_compat.studydd_views import _digest_sources  # noqa: E402


def _write_root(parent: Path) -> Path:
    root = parent / "studydd"
    (root / ".statedd").mkdir(parents=True)
    (root / "state").mkdir()
    (root / "instance.yaml").write_text(
        """apiVersion: studydd.studydd.io/v1
kind: StudyDDInstance
spec:
  mode: template
  templateOrigin: https://example.invalid/StudyDD_Template.git
  personalized: false
  publicSafe: true
  modules:
    - studydd.core
""",
        encoding="utf-8",
    )
    (root / ".statedd" / "lock.yaml").write_text(
        """formatVersion: statedd.lock/v1
template:
  version: 0.11.0
  sourceRevision: abc123
  sourcePath: ""
instance:
  createdFromTemplateVersion: 0.10.0
  createdFromTemplateCommit: oldcommit
  lastTemplateUpgradeVersion: 0.11.0
  lastTemplateUpgradeCommit: newcommit
  upgradeHistory: []
""",
        encoding="utf-8",
    )
    (root / "state" / "STATE_MANIFEST.template.yaml").write_text(
        """manifest_version: '1.0'
last_updated: '2026-07-12'
files:
  README.md:
    role: canonical
    owner: template
    boundary: template
  state/STUDYDD_MODE.yaml:
    role: canonical
    owner: generated
    boundary: generated
    generated_by: scripts/generate_compatibility_views.py
  state/STUDYDD_TEMPLATE_VERSION.yaml:
    role: canonical
    owner: generated
    boundary: generated
    generated_by: scripts/generate_compatibility_views.py
  state/STATE_MANIFEST.yaml:
    role: canonical
    owner: generated
    boundary: generated
    generated_by: scripts/generate_compatibility_views.py
""",
        encoding="utf-8",
    )
    (root / "state" / "STATE_MANIFEST.instance.yaml").write_text(
        """files:
  state/LOCAL.yaml:
    role: canonical
    owner: instance
    boundary: instance
""",
        encoding="utf-8",
    )
    (root / "state" / "STUDYDD_MODE.yaml").write_text(
        """# GENERATED FILE
mode: template
template_remote: https://example.invalid/StudyDD_Template.git
personalized: false
public_safe: true
modules:
- studydd.core
""",
        encoding="utf-8",
    )
    (root / "state" / "STUDYDD_TEMPLATE_VERSION.yaml").write_text(
        """template_version: 0.11.0
template_commit: abc123
template_source_path: ""
instance_created_from_template_version: 0.10.0
instance_created_from_template_commit: oldcommit
last_template_upgrade_version: 0.11.0
last_template_upgrade_commit: newcommit
upgrade_history: []
""",
        encoding="utf-8",
    )
    (root / "state" / "STATE_MANIFEST.yaml").write_text(
        """manifest_version: '1.0'
last_updated: '2026-07-12'
generated_by: scripts/generate_compatibility_views.py
files:
  README.md:
    role: canonical
    owner: template
    boundary: template
  state/LOCAL.yaml:
    role: canonical
    owner: instance
    boundary: instance
  state/STATE_MANIFEST.yaml:
    role: canonical
    owner: generated
    boundary: generated
    generated_by: scripts/generate_compatibility_views.py
  state/STUDYDD_MODE.yaml:
    role: canonical
    owner: generated
    boundary: generated
    generated_by: scripts/generate_compatibility_views.py
  state/STUDYDD_TEMPLATE_VERSION.yaml:
    role: canonical
    owner: generated
    boundary: generated
    generated_by: scripts/generate_compatibility_views.py
""",
        encoding="utf-8",
    )
    import yaml

    digest = _digest_sources(root, (
        "instance.yaml", ".statedd/lock.yaml",
        "state/STATE_MANIFEST.template.yaml", "state/STATE_MANIFEST.instance.yaml",
    ))
    for relative in ("state/STUDYDD_MODE.yaml", "state/STUDYDD_TEMPLATE_VERSION.yaml", "state/STATE_MANIFEST.yaml"):
        path = root / relative
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        value = {"schema_version": "studydd.compatibility-view/v1", "view_version": 1, "source_digest": digest, **value}
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    return root


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_views_are_deterministic_and_source_digest_is_authority_bound() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-studydd-views-") as raw:
        root = _write_root(Path(raw))
        first = load_studydd_compatibility_views(root)
        second = load_studydd_compatibility_views(root)
        assert first.as_dict() == second.as_dict()
        assert first.source_digest.startswith("sha256:")
        assert first.view_digests == tuple(sorted(first.view_digests))

        source_before = first.source_digest
        (root / "instance.yaml").write_text(
            (root / "instance.yaml").read_text(encoding="utf-8")
            + "\n# Formatting-only authority change.\n",
            encoding="utf-8",
        )
        changed = load_studydd_compatibility_views(root)
        # The source digest is canonical over parsed portable inputs, so a
        # comment-only authority edit does not alter semantic identity.
        assert changed.source_digest == source_before
        assert changed.mode == first.mode


def test_manual_tamper_and_authority_conflict_fail_closed_without_writes() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-studydd-views-") as raw:
        root = _write_root(Path(raw))
        mode = root / "state" / "STUDYDD_MODE.yaml"
        mode.write_text(
            mode.read_text(encoding="utf-8").replace("mode: template", "mode: bootstrap"),
            encoding="utf-8",
        )
        after_tamper = _snapshot(root)
        try:
            load_studydd_compatibility_views(root)
        except CompatibilityViewError as exc:
            assert "stale" in str(exc) or "modified" in str(exc)
        else:
            raise AssertionError("manually modified generated view was accepted")
        assert _snapshot(root) == after_tamper

        root = _write_root(Path(raw) / "conflict")
        overlay = root / "state" / "STATE_MANIFEST.instance.yaml"
        overlay.write_text(
            overlay.read_text(encoding="utf-8").replace(
                "  state/LOCAL.yaml:", "  state/STUDYDD_MODE.yaml:"
            ),
            encoding="utf-8",
        )
        try:
            load_studydd_compatibility_views(root)
        except CompatibilityViewError as exc:
            assert "stale" in str(exc) or "conflicts" in str(exc)
        else:
            raise AssertionError("authority conflict with generated view was accepted")


def test_composition_rejects_recursive_unknown_fields_and_ejection_of_generated_view() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-studydd-views-") as raw:
        root = _write_root(Path(raw))
        overlay = root / "state" / "STATE_MANIFEST.instance.yaml"
        overlay.write_text(
            """files:
  state/LOCAL.yaml:
    role: canonical
    owner: instance
    boundary: instance
    nested: {owner: template}
""",
            encoding="utf-8",
        )
        try:
            load_studydd_compatibility_views(root)
        except CompatibilityViewError as exc:
            assert "unknown key" in str(exc)
        else:
            raise AssertionError("recursive unknown manifest field was accepted")

        root = _write_root(Path(raw) / "ejection")
        views = load_studydd_compatibility_views(root, ejected_paths=["README.md"])
        assert views.ejections == ("README.md",)
        try:
            load_studydd_compatibility_views(root, ejected_paths=["state/STUDYDD_MODE.yaml"])
        except CompatibilityViewError as exc:
            assert "cannot be ejected" in str(exc)
        else:
            raise AssertionError("generated compatibility view was ejected")


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_") and callable(test):
            test()
    print("PASS")
