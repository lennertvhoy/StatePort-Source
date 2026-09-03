"""Isolated regression tests for the private public-candidate exporter."""

from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys

import jsonschema
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import export_public_candidate as public_export  # noqa: E402
from export_public_candidate import (  # noqa: E402
    COPYABLE_CLASSIFICATIONS,
    DETECTOR_FORMAT,
    ExportError,
    _classify,
    _javascript_module_specifiers,
    _web_dependency_issues,
    audit_fresh_git,
    extract_private_detectors,
    export_candidate,
    inspect_source,
    load_policy,
)


POLICY_PATH = "config/export.yaml"


def _write(path: Path, value: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value, encoding="utf-8")


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _policy(
    *,
    public_paths: list[str] | None = None,
    private_paths: list[str] | None = None,
    default_classification: str = "unresolved-blocking",
) -> dict[str, object]:
    public_paths = public_paths if public_paths is not None else ["src/app.py"]
    private_paths = private_paths if private_paths is not None else ["internal/notes.txt", POLICY_PATH]
    rules: list[dict[str, object]] = []
    if public_paths:
        rules.append(
            {
                "id": "reviewed-public-source",
                "classification": "public-source",
                "license": "AGPL-3.0-or-later",
                "provenanceRationale": "Fixture source authored for deterministic public export testing.",
                "paths": public_paths,
            }
        )
    if private_paths:
        rules.append(
            {
                "id": "private-fixture-control",
                "classification": "private-internal",
                "license": "NOASSERTION",
                "provenanceRationale": "Fixture-only internal material is never copied to a public candidate.",
                "paths": private_paths,
            }
        )
    return {
        "formatVersion": "stateport.public-export-allowlist/v1",
        "default": {
            "id": "not-reviewed",
            "classification": default_classification,
            "license": "NOASSERTION",
            "provenanceRationale": "Unreviewed fixture content blocks export.",
        },
        "rules": rules,
    }


def _commit(repository: Path, message: str = "fixture root") -> str:
    _git(repository, "add", "--all")
    _git(
        repository,
        "-c",
        "user.name=Private Fixture Identity",
        "-c",
        "user.email=private-fixture@example.invalid",
        "commit",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD")


def _repository(
    tmp_path: Path,
    *,
    name: str = "private-source",
    policy: dict[str, object] | None = None,
    extra: dict[str, str | bytes] | None = None,
) -> tuple[Path, str]:
    repository = tmp_path / name
    repository.mkdir()
    _git(repository, "init", "--quiet", "--initial-branch=private-work")
    _write(repository / "src/app.py", "print('public fixture')\n")
    _write(repository / "internal/notes.txt", "private fixture note\n")
    _write(repository / POLICY_PATH, yaml.safe_dump(policy or _policy(), sort_keys=False))
    for relative, value in (extra or {}).items():
        _write(repository / relative, value)
    return repository, _commit(repository)


def _detectors(tmp_path: Path, value: str = "do-not-export-this-private-literal") -> Path:
    path = tmp_path / "operator-private-detectors.json"
    _write(
        path,
        json.dumps(
            {
                "formatVersion": DETECTOR_FORMAT,
                "forbiddenLiterals": [{"id": "fixture-private-value", "value": value}],
            }
        )
        + "\n",
    )
    return path


def _targets(tmp_path: Path, suffix: str = "") -> tuple[Path, Path, Path]:
    return (
        tmp_path / f"candidate{suffix}",
        tmp_path / f"public-manifest{suffix}.json",
        tmp_path / f"private-inventory{suffix}.json",
    )


def _export(
    repository: Path,
    commit: str,
    detector_path: Path,
    targets: tuple[Path, Path, Path],
) -> bool:
    output, manifest, inventory = targets
    return export_candidate(
        repository,
        commit,
        POLICY_PATH,
        detector_path,
        output,
        manifest,
        inventory,
    )


def _export_external_policy(
    repository: Path,
    commit: str,
    policy_file: Path,
    detector_path: Path,
    targets: tuple[Path, Path, Path],
) -> bool:
    output, manifest, inventory = targets
    return export_candidate(
        repository,
        commit,
        None,
        detector_path,
        output,
        manifest,
        inventory,
        policy_file=policy_file,
    )


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _codes(findings: list[object]) -> set[str]:
    return {str(getattr(finding, "code")) for finding in findings}


def _validate_public_manifest(document: dict[str, object]) -> None:
    schema = json.loads((ROOT / "schemas/public-export-manifest.v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(document)


def test_atomic_output_file_preserves_racing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "public-manifest.json"
    rename = public_export._rename_noreplace

    def race(parent_fd: int, source_name: str, target_name: str) -> None:
        target.write_text("foreign\n", encoding="utf-8")
        rename(parent_fd, source_name, target_name)

    monkeypatch.setattr(public_export, "_rename_noreplace", race)
    with pytest.raises(ExportError, match="refusing to overwrite"):
        public_export._atomic_write_new(target, b"candidate\n", mode=0o644)
    assert target.read_text(encoding="utf-8") == "foreign\n"


def test_export_preserves_racing_output_directory_and_published_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, commit = _repository(tmp_path)
    detectors = _detectors(tmp_path)
    output, manifest_path, inventory_path = _targets(tmp_path)
    rename = public_export._rename_noreplace

    def race(parent_fd: int, source_name: str, target_name: str) -> None:
        if target_name == output.name:
            output.mkdir(mode=0o700)
            (output / "foreign-sentinel.txt").write_text("preserve me\n", encoding="utf-8")
        rename(parent_fd, source_name, target_name)

    monkeypatch.setattr(public_export, "_rename_noreplace", race)
    with pytest.raises(ExportError, match="refusing to overwrite"):
        _export(repository, commit, detectors, (output, manifest_path, inventory_path))
    assert (output / "foreign-sentinel.txt").read_text(encoding="utf-8") == "preserve me\n"
    assert manifest_path.is_file()
    assert inventory_path.is_file()


def test_atomic_output_refuses_rebound_staging_name_without_touching_victim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "public-manifest.json"
    victim = tmp_path / "victim.txt"
    victim.write_text("preserve me\n", encoding="utf-8")
    promote = public_export._promote_new_path

    def rebind(source: Path, destination: Path, **kwargs: object) -> None:
        original = source.with_suffix(source.suffix + ".owned")
        source.rename(original)
        source.symlink_to(victim)
        promote(source, destination, **kwargs)

    monkeypatch.setattr(public_export, "_promote_new_path", rebind)
    with pytest.raises(ExportError, match="staging identity changed"):
        public_export._atomic_write_new(target, b"candidate\n", mode=0o644)
    assert victim.read_text(encoding="utf-8") == "preserve me\n"
    assert not target.exists()


def test_exact_allowlist_copies_public_and_omits_private_source_mapping(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    detector_value = "private-detector-value-never-public"
    detectors = _detectors(tmp_path, detector_value)
    output, manifest_path, inventory_path = _targets(tmp_path)

    assert _export(repository, commit, detectors, (output, manifest_path, inventory_path))
    assert (output / "src/app.py").read_text(encoding="utf-8") == "print('public fixture')\n"
    assert not (output / "internal").exists()
    assert not (output / ".git").exists()
    assert stat_mode(output / "src/app.py") == 0o644
    assert (output / "src/app.py").stat().st_mtime_ns == 0

    manifest = _load(manifest_path)
    _validate_public_manifest(manifest)
    assert manifest["status"] == "exported"
    files = manifest["files"]
    assert isinstance(files, list) and len(files) == 1
    assert files[0]["path"] == "src/app.py"
    public_bytes = manifest_path.read_bytes()
    for private_value in (
        str(repository),
        commit,
        "Private Fixture Identity",
        "private-fixture@example.invalid",
        detector_value,
        "internal/notes.txt",
    ):
        assert private_value.encode("utf-8") not in public_bytes

    inventory = _load(inventory_path)
    assert inventory["source"]["repository"] == str(repository)
    by_path = {entry["sourcePath"]: entry for entry in inventory["files"]}
    assert by_path["src/app.py"]["selectedForPublic"] is True
    assert by_path["internal/notes.txt"]["classification"] == "private-internal"
    assert by_path["internal/notes.txt"]["selectedForPublic"] is False


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_unclassified_default_blocks_without_creating_candidate(tmp_path: Path) -> None:
    policy = _policy(private_paths=["internal/notes.txt", POLICY_PATH])
    repository, commit = _repository(tmp_path, policy=policy, extra={"unreviewed.txt": "unknown\n"})
    detectors = _detectors(tmp_path)
    output, manifest_path, inventory_path = _targets(tmp_path)

    assert not _export(repository, commit, detectors, (output, manifest_path, inventory_path))
    assert not output.exists()
    manifest = _load(manifest_path)
    _validate_public_manifest(manifest)
    assert manifest["status"] == "blocked"
    assert manifest["files"] == []
    assert {item["code"] for item in manifest["blockingIssueCounts"]} == {"unresolved_classification"}
    inventory = _load(inventory_path)
    by_path = {entry["sourcePath"]: entry for entry in inventory["files"]}
    assert by_path["unreviewed.txt"]["classification"] == "unresolved-blocking"


def test_policy_without_blocking_default_is_rejected(tmp_path: Path) -> None:
    invalid = _policy(default_classification="excluded")
    repository, commit = _repository(tmp_path, policy=invalid)
    targets = _targets(tmp_path)
    with pytest.raises(ExportError, match="default classification"):
        _export(repository, commit, _detectors(tmp_path), targets)
    assert not any(path.exists() for path in targets)


def test_hard_private_path_cannot_be_publicly_classified(tmp_path: Path) -> None:
    policy = _policy(public_paths=["src/app.py", "AGENTS.md"], private_paths=["internal/notes.txt", POLICY_PATH])
    repository, commit = _repository(tmp_path, policy=policy, extra={"AGENTS.md": "private control\n"})
    output, manifest_path, inventory_path = _targets(tmp_path)

    assert not _export(repository, commit, _detectors(tmp_path), (output, manifest_path, inventory_path))
    assert not output.exists()
    manifest = _load(manifest_path)
    assert {item["code"] for item in manifest["blockingIssueCounts"]} == {"forbidden_public_path"}
    inventory = _load(inventory_path)
    agents = next(item for item in inventory["files"] if item["sourcePath"] == "AGENTS.md")
    assert agents["selectedForPublic"] is False


@pytest.mark.parametrize(
    ("unsafe_name", "unsafe_value", "expected_code"),
    [
        ("unsafe.bin", b"prefix\x00suffix", "binary_content"),
        ("unsafe.txt", b"prefix\xffsuffix", "non_utf8_content"),
    ],
)
def test_binary_and_non_utf8_private_input_is_evidenced_but_not_copied(
    tmp_path: Path, unsafe_name: str, unsafe_value: bytes, expected_code: str
) -> None:
    policy = _policy(private_paths=["internal/notes.txt", POLICY_PATH, unsafe_name])
    repository, commit = _repository(tmp_path, policy=policy, extra={unsafe_name: unsafe_value})
    output, manifest_path, inventory_path = _targets(tmp_path)
    assert _export(repository, commit, _detectors(tmp_path), (output, manifest_path, inventory_path))
    assert output.exists()
    assert not (output / unsafe_name).exists()
    manifest = _load(manifest_path)
    assert manifest["status"] == "exported"
    assert manifest["blockingIssueCounts"] == []
    inventory = _load(inventory_path)
    unsafe = next(item for item in inventory["files"] if item["sourcePath"] == unsafe_name)
    assert unsafe["selectedForPublic"] is False
    assert unsafe["contentKind"] == ("binary" if expected_code == "binary_content" else "non-utf8")
    assert inventory["summary"]["contentKindCounts"][unsafe["contentKind"]] == 1


@pytest.mark.parametrize(
    ("unsafe_name", "unsafe_value", "expected_code"),
    [
        ("src/unsafe.bin", b"prefix\x00suffix", "binary_content"),
        ("src/unsafe.txt", b"prefix\xffsuffix", "non_utf8_content"),
    ],
)
def test_binary_and_non_utf8_public_input_still_fail_closed(
    tmp_path: Path, unsafe_name: str, unsafe_value: bytes, expected_code: str
) -> None:
    policy = _policy(
        public_paths=["src/app.py", unsafe_name],
        private_paths=["internal/notes.txt", POLICY_PATH],
    )
    repository, commit = _repository(tmp_path, policy=policy, extra={unsafe_name: unsafe_value})
    output, manifest_path, inventory_path = _targets(tmp_path)

    assert not _export(repository, commit, _detectors(tmp_path), (output, manifest_path, inventory_path))
    assert not output.exists()
    manifest = _load(manifest_path)
    assert expected_code in {item["code"] for item in manifest["blockingIssueCounts"]}


def test_symlink_tree_entry_fails_closed(tmp_path: Path) -> None:
    policy = _policy(private_paths=["internal/notes.txt", POLICY_PATH, "link.txt"])
    repository, _commit_id = _repository(tmp_path, policy=policy)
    os.symlink("src/app.py", repository / "link.txt")
    commit = _commit(repository, "add symlink")
    output, manifest_path, inventory_path = _targets(tmp_path)

    assert not _export(repository, commit, _detectors(tmp_path), (output, manifest_path, inventory_path))
    assert not output.exists()
    manifest = _load(manifest_path)
    assert "symlink_entry" in {item["code"] for item in manifest["blockingIssueCounts"]}


def test_private_detector_blocks_payload_without_leaking_value_or_path(tmp_path: Path) -> None:
    detector_value = "private-marker-945a"
    repository, commit = _repository(
        tmp_path,
        extra={"src/app.py": f"print('{detector_value}')\n"},
    )
    output, manifest_path, inventory_path = _targets(tmp_path)

    assert not _export(repository, commit, _detectors(tmp_path, detector_value), (output, manifest_path, inventory_path))
    assert not output.exists()
    manifest_bytes = manifest_path.read_bytes()
    assert detector_value.encode("utf-8") not in manifest_bytes
    assert str(repository).encode("utf-8") not in manifest_bytes
    manifest = _load(manifest_path)
    assert manifest["files"] == []
    assert {item["code"] for item in manifest["blockingIssueCounts"]} == {"restricted_content"}
    assert detector_value not in inventory_path.read_text(encoding="utf-8")


def test_export_is_deterministic_across_distinct_source_git_objects(tmp_path: Path) -> None:
    first_repository, first_commit = _repository(tmp_path, name="first-private-source")
    second_repository, second_commit = _repository(tmp_path, name="second-private-source")
    assert first_commit != second_commit or first_repository != second_repository
    detectors = _detectors(tmp_path)
    first = _targets(tmp_path, "-one")
    second = _targets(tmp_path, "-two")

    assert _export(first_repository, first_commit, detectors, first)
    assert _export(second_repository, second_commit, detectors, second)
    assert first[1].read_bytes() == second[1].read_bytes()
    assert tree_snapshot(first[0]) == tree_snapshot(second[0])


def test_external_reviewed_policy_can_classify_an_older_exact_source(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    external_policy = tmp_path / "reviewed-policy.yaml"
    _write(external_policy, (repository / POLICY_PATH).read_bytes())
    targets = _targets(tmp_path)
    assert _export_external_policy(repository, commit, external_policy, _detectors(tmp_path), targets)
    inventory = _load(targets[2])
    assert inventory["policy"]["kind"] == "external-reviewed-input"
    assert inventory["summary"]["defaultMatchedFileCount"] == 0


def test_detector_extraction_and_source_inspection_are_private_and_deterministic(tmp_path: Path) -> None:
    source_policy_path = "config/source-release-policy.yaml"
    source_policy = {
        "forbiddenIdentifiers": [
            {"id": "private-one", "value": "private-value-one"},
            {"id": "private-two", "value": "private-value-two"},
        ]
    }
    fixture_policy = _policy(private_paths=["internal/notes.txt", POLICY_PATH, source_policy_path])
    repository, commit = _repository(
        tmp_path,
        policy=fixture_policy,
        extra={
            source_policy_path: yaml.safe_dump(source_policy, sort_keys=False),
            "assets/image.png": b"\x89PNG\r\n\x1a\nfixture\x00",
            "assets/vector.svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>\n",
            "internal/notes.txt": "private-value-one\n",
        },
    )
    detector_output = tmp_path / "extracted-private-detectors.json"
    extract_private_detectors(repository, commit, source_policy_path, detector_output)
    assert stat_mode(detector_output) == 0o600
    detector_document = _load(detector_output)
    assert [item["id"] for item in detector_document["forbiddenLiterals"]] == ["private-one", "private-two"]

    first_inspection = tmp_path / "inspection-one.json"
    second_inspection = tmp_path / "inspection-two.json"
    first = inspect_source(repository, commit, detector_output, first_inspection)
    second = inspect_source(repository, commit, detector_output, second_inspection)
    assert first == second
    assert first_inspection.read_bytes() == second_inspection.read_bytes()
    assert stat_mode(first_inspection) == 0o600
    assert first["summary"]["trackedFileCount"] == 6
    by_path = {item["sourcePath"]: item for item in first["files"]}
    assert by_path["src/app.py"]["contentKind"] == "utf8-text"
    assert "source-or-build-input" in by_path["src/app.py"]["relevanceCues"]
    assert by_path["assets/image.png"]["contentKind"] == "binary"
    assert by_path["assets/image.png"]["mediaKind"] == "raster-image"
    assert by_path["assets/vector.svg"]["mediaKind"] == "vector-image"
    assert by_path["internal/notes.txt"]["detectorHitIds"] == ["private-one"]


def test_matching_known_source_report_remains_explicitly_blocked(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    detectors = _detectors(tmp_path)
    inspection_path = tmp_path / "known-source-inspection.json"
    inspection = inspect_source(repository, commit, detectors, inspection_path)
    policy = _policy()
    policy["knownSourceReview"] = {
        "treeSnapshotDigest": inspection["source"]["treeSnapshotDigest"],
        "status": "blocked",
        "trackedFileCount": 3,
        "defaultMatchedFileCount": 0,
        "classificationCounts": {"private-internal": 2, "public-source": 1},
        "observedCounts": {
            "binary-file-count": 0,
            "dependency-input-count": 0,
            "detector-hit-file-count": 0,
            "eligible-public-file-count": 1,
            "raster-media-file-count": 0,
            "source-or-build-input-count": 1,
            "vector-media-file-count": 0,
        },
        "blockerCategories": ["fixture-review-remains-blocked"],
    }
    external_policy = tmp_path / "known-source-policy.yaml"
    _write(external_policy, yaml.safe_dump(policy, sort_keys=False))
    output, manifest_path, inventory_path = _targets(tmp_path)
    assert not _export_external_policy(repository, commit, external_policy, detectors, (output, manifest_path, inventory_path))
    assert not output.exists()
    manifest = _load(manifest_path)
    assert manifest["blockingIssueCounts"] == [{"code": "known_source_review_blocked", "count": 1}]
    inventory = _load(inventory_path)
    assert inventory["summary"]["eligiblePublicFileCount"] == 1
    assert inventory["summary"]["publicFileCount"] == 0

    _write(repository / "src/app.py", "print('changed reviewed path')\n")
    changed_commit = _commit(repository, "change exact reviewed content")
    changed_targets = _targets(tmp_path, "-changed")
    assert not _export_external_policy(
        repository,
        changed_commit,
        external_policy,
        detectors,
        changed_targets,
    )
    changed_manifest = _load(changed_targets[1])
    assert changed_manifest["blockingIssueCounts"] == [
        {"code": "known_source_review_snapshot_mismatch", "count": 1}
    ]


def tree_snapshot(root: Path) -> list[tuple[str, int, int, bytes]]:
    return [
        (path.relative_to(root).as_posix(), stat_mode(path), path.stat().st_mtime_ns, path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


def test_dirty_or_nonexact_source_is_rejected_before_output(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    detectors = _detectors(tmp_path)
    dirty_targets = _targets(tmp_path, "-dirty")
    _write(repository / "untracked.txt", "dirty\n")
    with pytest.raises(ExportError, match="not clean"):
        _export(repository, commit, detectors, dirty_targets)
    assert not any(path.exists() for path in dirty_targets)
    (repository / "untracked.txt").unlink()
    with pytest.raises(ExportError, match="exact full"):
        _export(repository, commit[:12], detectors, _targets(tmp_path, "-short"))


def test_unsafe_tracked_path_is_rejected_before_output(tmp_path: Path) -> None:
    unsafe_path = "unsafe:name.txt"
    policy = _policy(private_paths=["internal/notes.txt", POLICY_PATH, unsafe_path])
    repository, commit = _repository(tmp_path, policy=policy, extra={unsafe_path: "unsafe path\n"})
    targets = _targets(tmp_path)
    with pytest.raises(ExportError, match="non-portable path character"):
        _export(repository, commit, _detectors(tmp_path), targets)
    assert not any(path.exists() for path in targets)


def _fresh_repository(candidate_tree: Path) -> Path:
    _git(candidate_tree, "init", "--quiet", "--initial-branch=main")
    _git(candidate_tree, "config", "core.logAllRefUpdates", "false")
    _git(candidate_tree, "add", "--all")
    _git(
        candidate_tree,
        "-c",
        "user.name=Public Candidate Builder",
        "-c",
        "user.email=public-candidate@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fresh public candidate root",
    )
    return candidate_tree


def test_fresh_git_audit_passes_one_self_contained_root(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    targets = _targets(tmp_path)
    assert _export(repository, commit, _detectors(tmp_path), targets)
    fresh = _fresh_repository(targets[0])
    assert audit_fresh_git(fresh) == []


def test_fresh_git_audit_reports_history_and_metadata_without_values(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    targets = _targets(tmp_path)
    assert _export(repository, commit, _detectors(tmp_path), targets)
    fresh = _fresh_repository(targets[0])
    _write(fresh / "src/second.py", "print('second')\n")
    _commit(fresh, "second private-named commit")
    (fresh / ".git/logs/HEAD").parent.mkdir(parents=True, exist_ok=True)
    _write(fresh / ".git/logs/HEAD", "private reflog value\n")
    (fresh / ".git/objects/info").mkdir(parents=True, exist_ok=True)
    _write(fresh / ".git/objects/info/alternates", "/private/object/store\n")
    head = _git(fresh, "rev-parse", "HEAD")
    _write(fresh / f".git/refs/replace/{head}", head + "\n")

    findings = audit_fresh_git(fresh)
    codes = _codes(findings)
    assert {
        "alternates_present",
        "commit_count_not_one",
        "head_has_parent",
        "reflogs_present",
        "replace_refs_present",
    } <= codes
    serialized = json.dumps([finding.__dict__ for finding in findings], sort_keys=True)
    for private_value in (str(fresh), head, "/private/object/store", "private reflog value"):
        assert private_value not in serialized


def test_fresh_git_audit_rejects_additional_worktree(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    targets = _targets(tmp_path)
    assert _export(repository, commit, _detectors(tmp_path), targets)
    fresh = _fresh_repository(targets[0])
    linked = tmp_path / "linked-candidate"
    _git(fresh, "worktree", "add", "--quiet", "-b", "secondary", str(linked))
    try:
        assert "additional_worktrees" in _codes(audit_fresh_git(fresh))
    finally:
        _git(fresh, "worktree", "remove", "--force", str(linked))


def test_fresh_git_audit_rejects_dirty_tree_and_remote_without_leaking_values(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    targets = _targets(tmp_path)
    assert _export(repository, commit, _detectors(tmp_path), targets)
    fresh = _fresh_repository(targets[0])
    _write(fresh / "untracked-private-name.txt", "untracked private value\n")
    _git(fresh, "remote", "add", "private-origin", "https://private.invalid/repository.git")

    findings = audit_fresh_git(fresh)
    assert {"remotes_present", "worktree_not_clean"} <= _codes(findings)
    serialized = json.dumps([finding.__dict__ for finding in findings], sort_keys=True)
    assert "private-origin" not in serialized
    assert "https://private.invalid/repository.git" not in serialized
    assert "untracked-private-name.txt" not in serialized


def test_repository_policy_exactly_classifies_the_current_source_and_future_paths_block() -> None:
    policy_bytes = (ROOT / "config/public-export-allowlist.v1.yaml").read_bytes()
    policy = load_policy(policy_bytes)
    assert policy.default.classification == "unresolved-blocking"
    assert policy.known_source_review is None
    source_paths = sorted(set(_git(ROOT, "ls-files", "--cached").splitlines()))
    selected_paths = sorted(path for rule in policy.rules for path in rule.paths)
    classifications = Counter(_classify(path, policy).classification for path in source_paths)
    default_matches = sum(_classify(path, policy).identifier == policy.default.identifier for path in source_paths)
    assert selected_paths == source_paths
    assert default_matches == 0
    assert classifications["public-source"] > 0
    assert classifications["public-documentation"] > 0
    assert classifications["private-internal"] > 0
    assert classifications["excluded"] > 0
    public_classes = {"public-source", "public-documentation", "public-generated", "third-party-reviewed"}
    assert all(not rule.prefixes for rule in policy.rules if rule.classification in public_classes)
    public_source_paths = {
        path
        for rule in policy.rules
        if rule.classification == "public-source"
        for path in rule.paths
    }
    assert {
        "apps/web/src/features/application-experience/useApplicationReceiptRoute.ts",
        "apps/web/src/features/receipts/ApplicationReceiptsPage.tsx",
        "infra/qualification/__init__.py",
        "infra/qualification/example-config.json",
        "infra/qualification/runner.py",
        "infra/qualification/schemas/qualification-config.v1.schema.json",
        "infra/qualification/schemas/qualification-manifest.v1.schema.json",
        "infra/qualification/schemas/qualification-stage-receipt.v1.schema.json",
        "infra/qualification/tests/__init__.py",
        "infra/qualification/tests/test_runner.py",
        "packages/execution-host/src/execution_host/identity-contract.v1.json",
        "packages/execution-host/src/execution_host/identity_contract.py",
        "packages/release-contracts/src/stateport_release/schemas/release-provenance.v1.schema.json",
        "schemas/candidate-provenance.v2.schema.json",
        "schemas/identity-contract.v1.schema.json",
        "schemas/release-provenance.v1.schema.json",
    } <= public_source_paths
    assert _classify("docs/operations/backup-restore-durability.md", policy).classification == "public-documentation"
    assert _classify("infra/qualification/README.md", policy).classification == "public-documentation"
    assert _classify("config/public-export-allowlist.v1.yaml", policy).classification == "public-source"
    assert _classify("apps/web/assets/brand/stateport-mascot-shell.svg", policy).classification == "private-internal"
    assert _classify("instances/demo-classdd/instance.yaml", policy).classification == "private-internal"
    assert _classify("scripts/materialize_public_snapshot.py", policy).classification == "public-source"
    assert _classify("future/new-file.py", policy).classification == "unresolved-blocking"


def test_copyable_web_sources_have_a_closed_relative_import_graph() -> None:
    policy = load_policy((ROOT / "config/public-export-allowlist.v1.yaml").read_bytes())
    tracked_paths = set(_git(ROOT, "ls-files").splitlines())
    failures: list[str] = []
    copyable_paths = {
        path
        for path in tracked_paths
        if _classify(path, policy).classification in COPYABLE_CLASSIFICATIONS
    }
    web_sources = sorted(
        path
        for path in tracked_paths
        if path.startswith("apps/web/")
        and path.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".css"))
        and path in copyable_paths
    )
    for source_path in web_sources:
        source = (ROOT / source_path).read_text(encoding="utf-8")
        for issue in _web_dependency_issues(
            source_path, source, tracked_paths, copyable_paths
        ):
            failures.append(
                f"{source_path}: {issue.code} {issue.specifier} -> {issue.target}"
            )

    assert not failures, "Public web source import graph is not closed:\n" + "\n".join(failures)


def test_javascript_module_specifiers_ignore_comments_and_noncode_strings() -> None:
    source = '''
// import "./commented"
/* export { hidden } from "./blocked" */
const example = "import('./ordinary-string')"
const template = `export * from "./template"`
const jsx = <p>import "./jsx-text"</p>
import type { Shape } from "./types"
export { value } from "./value"
const lazy = import("./lazy")
const templateLazy = import(`./template-lazy`)
type Query = import("./query").Query
import "@/side-effect"
const commonjs = require("./commonjs")
'''
    assert _javascript_module_specifiers(source) == [
        ("./types", False),
        ("./value", False),
        ("./lazy", False),
        ("./template-lazy", False),
        ("./query", False),
        ("@/side-effect", False),
        ("./commonjs", False),
    ]


def test_web_dependency_closure_handles_aliases_and_fails_unsafe_edges() -> None:
    source_path = "apps/web/src/main.ts"
    tracked_paths = {
        source_path,
        "apps/web/src/types.ts",
        "apps/web/src/alias.ts",
        "apps/web/src/lazy/index.ts",
        "apps/web/src/hidden.ts",
    }
    copyable_paths = tracked_paths - {"apps/web/src/hidden.ts"}
    source = '''
import type { Shape } from "./types"
import { alias } from "@/alias"
const lazy = import("./lazy")
import { hidden } from "./hidden"
import { absent } from "./absent"
import { escaped } from "../../../outside"
import { absolute } from "/absolute"
import { external } from "react"
const commonjs = require("./types")
'''
    issues = _web_dependency_issues(source_path, source, tracked_paths, copyable_paths)
    assert [(issue.code, issue.specifier, issue.target) for issue in issues] == [
        ("noncopyable_public_import", "./hidden", "apps/web/src/hidden.ts"),
        ("unresolved_public_import", "./absent", None),
        ("unsafe_public_import", "../../../outside", "outside"),
        ("unsafe_public_import", "/absolute", None),
    ]


def test_css_dependency_closure_ignores_comments_and_checks_relative_imports() -> None:
    source_path = "apps/web/src/index.css"
    tracked_paths = {source_path, "apps/web/src/styles/tokens.css"}
    source = '''
/* @import "./missing.css"; */
@import "@fontsource/inter/latin-400.css";
@import './styles/tokens.css';
'''
    assert _web_dependency_issues(
        source_path, source, tracked_paths, tracked_paths
    ) == []


def test_export_blocks_when_copyable_web_source_imports_private_module(tmp_path: Path) -> None:
    policy = _policy(
        public_paths=["src/app.py", "apps/web/src/main.ts"],
        private_paths=["internal/notes.txt", "apps/web/src/hidden.ts", POLICY_PATH],
    )
    repository, commit = _repository(
        tmp_path,
        policy=policy,
        extra={
            "apps/web/src/main.ts": 'import { hidden } from "./hidden"\n',
            "apps/web/src/hidden.ts": "export const hidden = true\n",
        },
    )
    output, manifest_path, inventory_path = _targets(tmp_path)

    assert not _export(
        repository,
        commit,
        _detectors(tmp_path),
        (output, manifest_path, inventory_path),
    )
    manifest = _load(manifest_path)
    assert manifest["blockingIssueCounts"] == [
        {"code": "noncopyable_public_import", "count": 1}
    ]
    inventory = _load(inventory_path)
    by_path = {entry["sourcePath"]: entry for entry in inventory["files"]}
    assert by_path["apps/web/src/main.ts"]["selectedForPublic"] is False
    assert by_path["apps/web/src/main.ts"]["issues"] == ["noncopyable_public_import"]
