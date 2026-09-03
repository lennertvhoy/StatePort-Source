#!/usr/bin/env python3
"""Synthetic tests for lock-proven, read-only contribution bundle validation."""

from __future__ import annotations

import copy
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "contribution-bundle-v2" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))

from contribution_bundle_v2 import bundle_digest, content_digest, tree_digest, validate_bundle
from contribution_bundle_v2.validator import make_patch


def _write_lock(instance: Path, lock: dict) -> None:
    lock_path = instance / ".statedd" / "lock.yaml"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        'formatVersion: "statedd.lock/v1"',
        'instanceId: "synthetic-instance"',
        'template:',
        '  id: "synthetic-template"',
        '  sourceRevision: "sha256:' + "1" * 64 + '"',
        '  source:',
        '    formatVersion: "stateport.source/v1"',
        '    kind: "local"',
        '    sourceClass: "synthetic_fixture"',
        '    productionEligible: false',
        '    sourceDigest: "sha256:' + "1" * 64 + '"',
        '    checkoutLocation: "' + str(instance.parent / "source") + '"',
        'files:',
        '  - path: "state/public-guide.md"',
        '    owner: "template"',
        '    sensitivity: "public"',
        '  - path: "state/private-notes.md"',
        '    owner: "instance"',
        '    sensitivity: "private"',
        '  - path: ".statedd/generated.md"',
        '    owner: "generated"',
        '    sensitivity: "internal"',
    ]
    lock_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _fixture(root: Path) -> tuple[dict, dict[str, Path]]:
    instance = root / "instance"
    source = root / "source"
    baseline = root / "baseline"
    synthetic = root / "synthetic"
    for tree in (instance, source, baseline, synthetic):
        (tree / "state").mkdir(parents=True)
        (tree / ".statedd").mkdir()
    before = b"# Guide\nold public wording\n"
    after = b"# Guide\nnew public wording\n"
    for tree in (source, baseline, synthetic):
        (tree / "state/public-guide.md").write_bytes(before)
    (instance / "state/public-guide.md").write_bytes(after)
    (instance / "state/private-notes.md").write_text("learner-only\n", encoding="utf-8")
    (instance / ".statedd/generated.md").write_text("generated\n", encoding="utf-8")
    lock = {
        "formatVersion": "statedd.lock/v1",
        "instanceId": "synthetic-instance",
        "template": {
            "id": "synthetic-template",
            "sourceRevision": "sha256:" + "1" * 64,
            "source": {
                "formatVersion": "stateport.source/v1",
                "kind": "local",
                "sourceClass": "synthetic_fixture",
                "productionEligible": False,
                "sourceDigest": "sha256:" + "1" * 64,
                "checkoutLocation": source.as_posix(),
            },
        },
        "files": [
            {"path": "state/public-guide.md", "owner": "template", "sensitivity": "public"},
            {"path": "state/private-notes.md", "owner": "instance", "sensitivity": "private"},
            {"path": ".statedd/generated.md", "owner": "generated", "sensitivity": "internal"},
        ],
    }
    _write_lock(instance, lock)
    # The test lock is intentionally a compact JSON-shaped YAML subset; the
    # validator compares the parsed document, so use the same actual bytes.
    actual = {
        "formatVersion": "statedd.lock/v1",
        "instanceId": "synthetic-instance",
        "template": lock["template"],
        "files": lock["files"],
    }
    source_revision = tree_digest(source)
    actual["template"]["sourceRevision"] = source_revision
    actual["template"]["source"]["sourceDigest"] = source_revision
    # Replace the hand-written lock with JSON, accepted as YAML and exact.
    import json

    (instance / ".statedd/lock.yaml").write_text(json.dumps(actual, sort_keys=True) + "\n", encoding="utf-8")
    return actual, {"instance": instance, "source": source, "baseline": baseline, "synthetic": synthetic, "before": before, "after": after}


def _valid_bundle(lock: dict, roots: dict[str, Path]) -> dict:
    before = roots["before"]
    after = roots["after"]
    path = "state/public-guide.md"
    patch = make_patch(path, before, after)
    bundle = {
        "formatVersion": "stateport.contribution-bundle/v2",
        "templateId": "synthetic-template",
        "automaticApply": False,
        "upstreamApplied": False,
        "lock": {
            "document": lock,
            "digest": content_digest((roots["instance"] / ".statedd/lock.yaml").read_bytes()),
        },
        "source": lock["template"]["source"],
        "baseline": {
            "templateId": "synthetic-template",
            "sourceDigest": lock["template"]["source"]["sourceDigest"],
            "rootDigest": tree_digest(roots["baseline"]),
        },
        "selectedPaths": [
            {
                "path": path,
                "owner": "template",
                "sensitivity": "public",
                "provenance": {
                    "authority": "locked_template_source",
                    "sourcePath": path,
                    "sourceRevision": lock["template"]["source"]["sourceDigest"],
                    "baselineRootDigest": tree_digest(roots["baseline"]),
                },
                "baselineContentDigest": content_digest(before),
                "contentDigest": content_digest(after),
                "patch": patch,
                "patchDigest": content_digest(patch),
            }
        ],
        "reproduction": {
            "clean": True,
            "sourceClass": "synthetic_fixture",
            "productionEligible": False,
            "baselineRootDigest": tree_digest(roots["synthetic"]),
            "paths": [{
                "path": path,
                "baselineContentDigest": content_digest(before),
                "resultContentDigest": content_digest(after),
            }],
            "resultRootDigest": tree_digest(roots["synthetic"], {path: after}),
        },
    }
    bundle["bundleDigest"] = bundle_digest(bundle)
    return bundle


def _validate(bundle: dict, roots: dict[str, Path]) -> dict:
    return validate_bundle(
        bundle,
        instance_root=roots["instance"],
        source_root=roots["source"],
        baseline_root=roots["baseline"],
        synthetic_root=roots["synthetic"],
    )


def test_valid_bundle_is_lock_bound_and_read_only() -> None:
    with tempfile.TemporaryDirectory() as raw:
        lock, roots = _fixture(Path(raw))
        bundle = _valid_bundle(lock, roots)
        before = {path: path.read_bytes() for path in roots["instance"].rglob("*") if path.is_file()}
        result = _validate(bundle, roots)
        after = {path: path.read_bytes() for path in roots["instance"].rglob("*") if path.is_file()}
        assert result["valid"], result["issues"]
        assert result["automaticApply"] is False
        assert result["upstreamApplied"] is False
        assert before == after


def test_exact_lock_source_and_baseline_are_required() -> None:
    with tempfile.TemporaryDirectory() as raw:
        lock, roots = _fixture(Path(raw))
        bundle = _valid_bundle(lock, roots)
        tampered = copy.deepcopy(bundle)
        tampered["lock"]["document"]["instanceId"] = "other"
        tampered["bundleDigest"] = bundle_digest(tampered)
        result = _validate(tampered, roots)
        assert not result["valid"]
        assert any("exact instance lock" in issue for issue in result["issues"])

        tampered = copy.deepcopy(bundle)
        (roots["baseline"] / "state/public-guide.md").write_text("different\n", encoding="utf-8")
        result = _validate(tampered, roots)
        assert not result["valid"]
        assert any("baseline" in issue for issue in result["issues"])


def test_selection_is_positive_and_structurally_excludes_private_generated_unknown() -> None:
    with tempfile.TemporaryDirectory() as raw:
        lock, roots = _fixture(Path(raw))
        for selected_path in ("state/private-notes.md", ".statedd/generated.md", "state/unknown.md"):
            bundle = _valid_bundle(lock, roots)
            entry = copy.deepcopy(bundle["selectedPaths"][0])
            entry["path"] = selected_path
            entry["provenance"]["sourcePath"] = selected_path
            bundle["selectedPaths"] = [entry]
            bundle["bundleDigest"] = bundle_digest(bundle)
            result = _validate(bundle, roots)
            assert not result["valid"], (selected_path, result)


def test_secret_like_patch_and_bad_reproduction_fail_without_path_blacklist() -> None:
    with tempfile.TemporaryDirectory() as raw:
        lock, roots = _fixture(Path(raw))
        bundle = _valid_bundle(lock, roots)
        entry = bundle["selectedPaths"][0]
        entry["patch"] = make_patch(
            "state/public-guide.md",
            roots["before"],
            b"# Guide\napi_key = \"not-a-real-but-secret-like-value\"\n",
        )
        entry["patchDigest"] = content_digest(entry["patch"])
        bundle["bundleDigest"] = bundle_digest(bundle)
        result = _validate(bundle, roots)
        assert not result["valid"]
        assert any("secret-like" in issue for issue in result["issues"])

        bundle = _valid_bundle(lock, roots)
        bundle["reproduction"]["clean"] = False
        bundle["bundleDigest"] = bundle_digest(bundle)
        result = _validate(bundle, roots)
        assert not result["valid"]
        assert any("clean" in issue for issue in result["issues"])


if __name__ == "__main__":
    for test in (
        test_valid_bundle_is_lock_bound_and_read_only,
        test_exact_lock_source_and_baseline_are_required,
        test_selection_is_positive_and_structurally_excludes_private_generated_unknown,
        test_secret_like_patch_and_bad_reproduction_fail_without_path_blacklist,
    ):
        test()
    print("PASS")
