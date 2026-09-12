from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import zipfile

import pytest
import yaml
import build_public_release_bundle as bundle
import export_public_candidate as public_export
import validate_candidate_provenance as provenance
from build_public_release_bundle import (
    PublicReleaseBuildError,
    _bind_public_ref,
    _archive,
    _bundle,
    _local_qualification_clone_receipt,
    _locked_wheels,
    _normal_clone_receipt,
    _python_build_environment,
    _release_manifest,
)
from validate_candidate_provenance import (
    CandidateProvenanceError,
    _verify_updater_wheel,
    validate_contract,
    verify_release_tree,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/candidate-provenance.v2.schema.json").read_text(encoding="utf-8"))


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _locked_inputs_digest(wheels: dict[str, bytes]) -> str:
    return hashlib.sha256(
        (
            json.dumps(
                [
                    {"filename": filename, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                    for filename, data in wheels.items()
                ],
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
    ).hexdigest()


def _wheel_bytes(evidence: dict[str, object]) -> bytes:
    encoded = json.dumps(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")), ensure_ascii=True
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as wheel:
        info = zipfile.ZipInfo("stateport_updater/_build_identity.py", date_time=(1980, 1, 1, 0, 0, 0))
        wheel.writestr(info, f"STATEPORT_BUILD_EVIDENCE_JSON = {encoded}\n".encode("ascii"))
    return output.getvalue()


def _locked_wheel_bytes(package: str, version: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as wheel:
        prefix = f"{package}-{version}.dist-info"
        for relative, content in (
            (
                f"{prefix}/METADATA",
                f"Metadata-Version: 2.1\nName: {package}\nVersion: {version}\n",
            ),
            (f"{prefix}/WHEEL", "Wheel-Version: 1.0\nGenerator: synthetic\n"),
        ):
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            wheel.writestr(info, content)
    return output.getvalue()


def _candidate(tmp_path: Path) -> tuple[Path, str, str]:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _git(candidate, "init", "--quiet", "--initial-branch=public-main")
    (candidate / "README.md").write_text("public candidate\n", encoding="utf-8")
    (candidate / "src").mkdir()
    (candidate / "src/main.py").write_text("print('public')\n", encoding="utf-8")
    policy_paths = [
        "README.md",
        "src/main.py",
        "config/public-export-allowlist.v1.yaml",
        "packages/execution-host/src/execution_host/identity-contract.v1.json",
        "packages/execution-host/src/execution_host/identity_contract.py",
        "packages/updater/build-requirements.lock",
        "packages/updater/pyproject.toml",
        "scripts/build_public_release_bundle.py",
        "scripts/export_public_candidate.py",
        "scripts/materialize_public_snapshot.py",
        "scripts/public_snapshot_audit.py",
        "scripts/install_no_checkout.py",
        "scripts/stateport-execution-host-provision",
    ]
    for relative in policy_paths[2:]:
        path = candidate / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
    setuptools_wheel = _locked_wheel_bytes("setuptools", "80.10.2")
    wheel_wheel = _locked_wheel_bytes("wheel", "0.45.1")
    (candidate / "packages/updater/build-requirements.lock").write_text(
        "setuptools==80.10.2 --hash=sha256:"
        + hashlib.sha256(setuptools_wheel).hexdigest()
        + "\nwheel==0.45.1 --hash=sha256:"
        + hashlib.sha256(wheel_wheel).hexdigest()
        + "\n",
        encoding="utf-8",
    )
    install = candidate / "scripts/install_no_checkout.py"
    install.parent.mkdir(parents=True, exist_ok=True)
    install.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    provisioner = candidate / "scripts/stateport-execution-host-provision"
    provisioner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (candidate / "config/public-export-allowlist.v1.yaml").write_text(
        yaml.safe_dump(
            {
                "formatVersion": "stateport.public-export-allowlist/v1",
                "default": {
                    "id": "future-file-not-reviewed",
                    "classification": "unresolved-blocking",
                    "license": "NOASSERTION",
                    "provenanceRationale": "Everything else is blocked.",
                },
                "rules": [
                    {
                        "id": "synthetic-public-source",
                        "classification": "public-source",
                        "license": "AGPL-3.0-or-later",
                        "provenanceRationale": "Synthetic exact export policy.",
                        "paths": policy_paths,
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    _git(candidate, "add", "--all")
    _git(
        candidate,
        "-c",
        "user.name=StatePort test",
        "-c",
        "user.email=stateport-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "candidate",
    )
    return candidate, _git(candidate, "rev-parse", "HEAD"), _git(candidate, "rev-parse", "HEAD^{tree}")


def test_source_validator_accepts_frozen_ancestor_and_attests_current_controller(
    tmp_path: Path,
) -> None:
    candidate, payload_commit, payload_tree = _candidate(tmp_path)
    (candidate / "CONTROL_STATE.md").write_text("later controller state\n", encoding="utf-8")
    _git(candidate, "add", "CONTROL_STATE.md")
    _git(
        candidate,
        "-c",
        "user.name=StatePort test",
        "-c",
        "user.email=stateport-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "controller state",
    )
    controller_commit = _git(candidate, "rev-parse", "HEAD")

    tree, epoch, controller = bundle._validate_source(candidate, payload_commit)

    assert tree == payload_tree
    assert epoch > 0
    assert controller["commit"] == controller_commit
    assert controller["tree"] == _git(candidate, "rev-parse", "HEAD^{tree}")
    assert controller["payloadRelationship"] == "payload-is-ancestor"
    assert controller["buildTool"]["path"] == "scripts/build_public_release_bundle.py"


def test_frozen_payload_clone_satisfies_nested_exact_head_verifier(tmp_path: Path) -> None:
    candidate, payload_commit, payload_tree = _candidate(tmp_path)
    (candidate / "CONTROL_STATE.md").write_text("later controller state\n", encoding="utf-8")
    _git(candidate, "add", "CONTROL_STATE.md")
    _git(
        candidate,
        "-c",
        "user.name=StatePort test",
        "-c",
        "user.email=stateport-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "controller state",
    )
    with pytest.raises(public_export.ExportError, match="HEAD does not equal"):
        public_export._verify_source(candidate, payload_commit)

    payload_source = bundle._clone_frozen_payload_source(
        candidate, payload_commit, tmp_path / "payload-source"
    )

    observed_tree, _entries = public_export._verify_source(payload_source, payload_commit)
    assert observed_tree == payload_tree
    assert _git(payload_source, "rev-parse", "HEAD") == payload_commit
    assert _git(payload_source, "status", "--porcelain=v1") == ""
    assert _git(payload_source, "remote") == ""


def test_source_validator_refuses_dirty_or_abbreviated_payload(tmp_path: Path) -> None:
    candidate, payload_commit, _payload_tree = _candidate(tmp_path)
    with pytest.raises(PublicReleaseBuildError, match="one exact full commit"):
        bundle._validate_source(candidate, payload_commit[:12])
    (candidate / "dirty.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(PublicReleaseBuildError, match="worktree must be clean"):
        bundle._validate_source(candidate, payload_commit)


def test_execution_host_identity_contract_paths_are_public_policy_bound() -> None:
    policy = yaml.safe_load(
        (ROOT / "config/public-export-allowlist.v1.yaml").read_text(encoding="utf-8")
    )
    selected = {
        path
        for rule in policy["rules"]
        for path in rule.get("paths", [])
    }
    assert {
        "packages/execution-host/src/execution_host/identity-contract.v1.json",
        "packages/execution-host/src/execution_host/identity_contract.py",
        "packages/execution-host/src/execution_host/staging_identity.py",
        "packages/execution-host/src/execution_host/workspace_revisions.py",
        "packages/execution-host/src/execution_host/daemon_contract.py",
        "packages/execution-host/src/execution_host/contracts.py",
        "packages/execution-host/tests/test_execution_host_daemon_unit.py",
        "schemas/execution-host-contract.v1.schema.json",
        "schemas/execution-host-operation.v1.schema.json",
        "schemas/execution-host-receipt.v1.schema.json",
    } <= selected


def test_podman_package_lock_builds_byte_identical_plain_tar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_dir = tmp_path / "packages"
    package_dir.mkdir()
    records = []
    by_file: dict[str, dict[str, object]] = {}
    for position, name in enumerate(sorted(bundle.PODMAN_REQUIRED_PACKAGES), 1):
        version = f"1.0.{position}"
        architecture = "all" if name.startswith("golang-github-containers-") else "amd64"
        filename = f"{name}_{version}_{architecture}.deb"
        payload = f"synthetic deb {name} {version} {architecture}\n".encode()
        (package_dir / filename).write_bytes(payload)
        record: dict[str, object] = {
            "name": name,
            "version": version,
            "architecture": architecture,
            "file": filename,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
        records.append(record)
        by_file[filename] = record
    lock_value = {
        "schema": bundle.PODMAN_PACKAGE_BUNDLE_SCHEMA,
        "target": bundle.PODMAN_PACKAGE_TARGET,
        "rootfs": bundle.PODMAN_PACKAGE_ROOTFS,
        "sourceDateEpoch": 1788220800,
        "packages": records,
        "install": {
            "packageNames": sorted(bundle.PODMAN_REQUIRED_PACKAGES),
            "packageVersions": {
                str(record["name"]): record["version"]
                for record in sorted(records, key=lambda item: str(item["name"]))
            },
        },
    }
    lock = tmp_path / "package-lock.json"
    lock.write_bytes(bundle._canonical_json(lock_value))

    def fake_run(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        record = by_file[Path(arguments[2]).name]
        stdout = (
            f"Package: {record['name']}\nVersion: {record['version']}\n"
            f"Architecture: {record['architecture']}\n"
        )
        return subprocess.CompletedProcess(arguments, 0, stdout, "")

    monkeypatch.setattr(bundle.subprocess, "run", fake_run)
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    first_result = bundle.build_podman_package_bundle(
        lock=lock, package_dir=package_dir, output=first
    )
    second_result = bundle.build_podman_package_bundle(
        lock=lock, package_dir=package_dir, output=second
    )

    assert first.read_bytes() == second.read_bytes()
    assert first_result["sha256"] == second_result["sha256"]
    assert first_result["packageCount"] == len(bundle.PODMAN_REQUIRED_PACKAGES)
    assert bundle._podman_package_bundle_metadata(first)["rootfsIdentity"] == (
        bundle.PODMAN_PACKAGE_ROOTFS
    )


def test_signed_known_limitations_preserve_the_wsl_version_boundary() -> None:
    limitations = bundle._known_limitations("0.1.0-alpha.10").decode("utf-8")
    assert "0.1.0-alpha.10" in limitations
    assert "Alpha.6" not in limitations
    assert "WSL2 on Windows 11" in limitations
    assert "wsl1_substrate_unsupported" in limitations
    assert "Native Linux remains a separate signed target" in limitations
    assert "before provisioning-plan emission" in limitations
    assert "Windows 11, WSL2, and Ubuntu identities remain evidence dimensions" in limitations
    assert "`compatible_unvalidated` until a clean-install acceptance receipt exists" in limitations


def test_signed_release_notes_disclose_the_public_test_boundary() -> None:
    notes = bundle._release_notes("0.1.0-alpha.10").decode("utf-8")
    assert "0.1.0-alpha.10" in notes
    assert "alpha.6" not in notes.lower()
    assert "151.0.7922" not in notes
    assert "public-test candidate" in notes
    assert "agent-owned installed qualification before product acceptance" in notes
    assert "clean-install receipt does not yet exist" in notes
    assert "unpublished bundle" not in notes


def test_default_candidate_id_is_derived_from_the_exact_release_version() -> None:
    commit = "a" * 40
    assert bundle._default_candidate_id("0.1.0-alpha.10", commit) == "stateport-alpha10-aaaaaaaaaaaa"
    with pytest.raises(PublicReleaseBuildError, match="explicit alpha or local qualification version"):
        bundle._default_candidate_id("0.1.0", commit)


def test_normal_clone_receipt_is_separate_and_content_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate, commit, tree = _candidate(tmp_path)
    clone_parent = tmp_path / "clone-parent"
    clone_parent.mkdir()
    authority = "https://github.com/example/stateport.git"
    calls: list[tuple[str, ...]] = []

    def fake_credential_free_git(arguments: list[str], *, cwd: Path | None = None) -> str:
        calls.append(tuple(arguments))
        if arguments[:3] == ["ls-remote", "--heads", authority]:
            return f"{commit}\trefs/heads/public-main\n"
        mapped = [str(candidate) if value == authority else value for value in arguments]
        if arguments[0] == "clone":
            subprocess.run(["git", *mapped], check=True, capture_output=True, text=True, cwd=cwd)
            return ""
        if arguments[:3] == ["-C", arguments[1], "remote"]:
            return authority + "\n"
        subprocess.run(["git", *mapped], check=True, capture_output=True, text=True, cwd=cwd)
        return ""

    monkeypatch.setattr(bundle, "_credential_free_git", fake_credential_free_git)
    receipt = _normal_clone_receipt(
        clone_parent,
        authority_url=authority,
        ref="refs/heads/public-main",
        commit=commit,
        tree=tree,
    )
    canonical = {
        "formatVersion": "stateport.anonymous-normal-clone-receipt/v1",
        "url": receipt["url"],
        "ref": receipt["ref"],
        "commit": receipt["commit"],
        "tree": receipt["tree"],
        "verification": receipt["verification"],
    }
    assert receipt["receiptSha256"] == hashlib.sha256(
        (json.dumps(canonical, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    assert any(call[:2] == ("ls-remote", "--heads") for call in calls)
    assert any(call[0] == "clone" and "--no-checkout" not in call and "--no-tags" in call for call in calls)
    assert any(call[0] == "-C" and "fetch" in call for call in calls)
    forged = tmp_path / "forged-parent"
    forged.mkdir()
    with pytest.raises(PublicReleaseBuildError, match="exact requested ref"):
        _normal_clone_receipt(
            forged,
            authority_url=authority,
            ref="refs/heads/public-main",
            commit="0" * 40,
            tree=tree,
        )


def test_local_qualification_clone_receipt_verifies_clone_and_recovery(tmp_path: Path) -> None:
    candidate, commit, tree = _candidate(tmp_path)
    _git(candidate, "branch", "-m", "qualification-local-900001")
    receipt = _local_qualification_clone_receipt(
        candidate,
        authority_url="https://127.0.0.1:5443/stateport-qualification.git",
        ref="refs/heads/qualification-local-900001",
        commit=commit,
        tree=tree,
    )
    assert receipt["formatVersion"] == "stateport.local-qualification-clone-receipt/v1"
    assert receipt["verification"] == "local-clone-and-recovery-with-fsck"
    canonical = {
        key: receipt[key]
        for key in ("formatVersion", "url", "ref", "commit", "tree", "verification")
    }
    assert receipt["receiptSha256"] == hashlib.sha256(
        (json.dumps(canonical, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()


def test_bind_public_ref_accepts_append_only_commit_with_same_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate, commit, tree = _candidate(tmp_path)
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "clone", "--bare", str(candidate), str(remote)], check=True, capture_output=True)
    descendant = subprocess.run(
        ["git", "-C", str(candidate), "commit-tree", tree, "-p", commit, "-m", "append-only"],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "StatePort test",
            "GIT_AUTHOR_EMAIL": "stateport-test@example.invalid",
            "GIT_COMMITTER_NAME": "StatePort test",
            "GIT_COMMITTER_EMAIL": "stateport-test@example.invalid",
        },
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(candidate), "push", str(remote), f"{descendant}:refs/heads/public-main"],
        check=True,
        capture_output=True,
        text=True,
    )
    authority = "https://github.com/example/stateport.git"

    def fake_credential_free_git(arguments: list[str], *, cwd: Path | None = None) -> str:
        mapped = [str(remote) if value == authority else value for value in arguments]
        completed = subprocess.run(
            ["git", *mapped], check=True, capture_output=True, text=True, cwd=cwd
        )
        return completed.stdout

    monkeypatch.setattr(bundle, "_credential_free_git", fake_credential_free_git)
    assert _bind_public_ref(
        candidate, authority_url=authority, ref="refs/heads/public-main", tree=tree
    ) == descendant
    assert _git(candidate, "rev-parse", "HEAD") == descendant
    assert _git(candidate, "rev-parse", "HEAD^{tree}") == tree


def test_credential_free_git_disables_prompts_and_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["environment"] = kwargs["env"]
        observed["cwd"] = kwargs["cwd"]
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(bundle.subprocess, "run", fake_run)
    for name in (
        "GIT_HTTP_EXTRAHEADER",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_REPLACE_REF_BASE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_COMMON_DIR",
        "GIT_ASKPASS",
        "GIT_PROXY_COMMAND",
        "GIT_SSH_COMMAND",
        "GIT_CREDENTIAL_HELPER",
        "GIT_CONFIG_COUNT",
    ):
        monkeypatch.setenv(name, "attacker-controlled")
    assert bundle._credential_free_git(["ls-remote", "--heads", "https://github.com/example/stateport.git"]) == "ok\n"
    assert observed["command"][:5] == ["git", "-c", "core.fsmonitor=false", "-c", "core.fsmonitorHook="]
    assert "credential.helper=" in observed["command"]
    assert observed["cwd"] == Path("/")
    assert observed["environment"]["GIT_TERMINAL_PROMPT"] == "0"
    assert observed["environment"]["GIT_CONFIG_NOSYSTEM"] == "1"
    assert all(name not in observed["environment"] for name in bundle.UNTRUSTED_GIT_ENVIRONMENT)
    assert "GIT_CONFIG_COUNT" not in observed["environment"]
    bundle._git(Path("/"), ["status"])
    assert observed["environment"]["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert all(name not in observed["environment"] for name in bundle.UNTRUSTED_GIT_ENVIRONMENT)


def test_updater_build_environment_and_locked_tools_are_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PIP_INDEX_URL", "https://attacker.invalid/simple")
    monkeypatch.setenv("PIP_CONFIG_FILE", "/tmp/attacker-pip.conf")
    monkeypatch.setenv("PYTHONPATH", "/tmp/attacker-python")
    monkeypatch.setenv("PYTHONHOME", "/tmp/attacker-python-home")
    monkeypatch.setenv("HOME", "/tmp/attacker-home")
    monkeypatch.setenv("PATH", "/tmp/attacker-path")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid")
    monkeypatch.setenv("CC", "/tmp/attacker-compiler")
    monkeypatch.setenv("SETUPTOOLS_SCM_PRETEND_VERSION", "9.9.9")
    environment = _python_build_environment(1700000000)
    assert environment["PIP_CONFIG_FILE"] == "/dev/null"
    assert environment["PIP_NO_INDEX"] == "1"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["HOME"] == "/nonexistent"
    assert environment["PATH"] == "/usr/bin:/bin"
    assert "HTTPS_PROXY" not in environment
    assert "CC" not in environment
    assert "SETUPTOOLS_SCM_PRETEND_VERSION" not in environment
    assert {name for name in environment if name.startswith("PIP_")} <= {
        "PIP_CONFIG_FILE",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "PIP_NO_CACHE_DIR",
        "PIP_NO_INDEX",
    }
    assert {name for name in environment if name.startswith("PYTHON")} <= {
        "PYTHONHASHSEED",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
    }

    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    placeholder = wheelhouse / "setuptools-80.10.2-py3-none-any.whl"
    placeholder.write_bytes(b"not a wheel")
    digest = hashlib.sha256(placeholder.read_bytes()).hexdigest()
    lock = tmp_path / "requirements.lock"
    lock.write_text(f"setuptools==80.10.2 --hash=sha256:{digest}\n", encoding="utf-8")
    with pytest.raises(PublicReleaseBuildError, match="real wheel"):
        _locked_wheels(wheelhouse, lock)
    lock.write_text(f"setuptools==81.0.0 --hash=sha256:{digest}\n", encoding="utf-8")
    with pytest.raises(PublicReleaseBuildError, match="unexpected tool version"):
        _locked_wheels(wheelhouse, lock)


def test_archive_and_bundle_are_deterministic_and_recover_exact_identity(tmp_path: Path) -> None:
    candidate, commit, tree = _candidate(tmp_path)
    first_archive = tmp_path / "first.tar"
    second_archive = tmp_path / "second.tar"
    kwargs = {
        "authority_url": "https://github.com/example/stateport.git",
        "ref": "refs/heads/public-main",
        "commit": commit,
        "tree": tree,
        "manifest_sha256": "a" * 64,
        "epoch": 1700000000,
    }
    _archive(candidate, first_archive, **kwargs)
    _archive(candidate, second_archive, **kwargs)
    assert first_archive.read_bytes() == second_archive.read_bytes()

    bundle = tmp_path / "candidate.bundle"
    _bundle(candidate, bundle, commit=commit, tree=tree, ref="refs/heads/public-main")
    assert _git(candidate, "bundle", "list-heads", str(bundle)) == f"{commit} refs/heads/public-main"


def test_release_manifest_is_final_and_excludes_only_itself(tmp_path: Path) -> None:
    root = tmp_path / "release"
    (root / "provenance").mkdir(parents=True)
    (root / "evidence").mkdir()
    (root / "provenance/candidate-provenance.yaml").write_text("schema: v2\n", encoding="utf-8")
    (root / "bundle-receipt.json").write_text("{}\n", encoding="utf-8")
    (root / "evidence/audit.json").write_text("{}\n", encoding="utf-8")
    document = json.loads(_release_manifest(root))
    assert document["excludedPaths"] == [
        "bundle-receipt.json",
        "provenance/candidate-provenance.yaml",
        "release-tree-manifest.json",
    ]
    assert {item["path"] for item in document["files"]} == {"evidence/audit.json"}


def test_successor_provenance_validates_actual_release_tree_and_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = _successor_contract(tmp_path)
    candidate = tmp_path / "candidate"
    root = tmp_path / "release-tree"
    root.mkdir()
    candidate_files = sorted(
        path.relative_to(candidate).as_posix()
        for path in candidate.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(candidate).parts
    )
    public_manifest = {
        "formatVersion": "stateport.public-export-manifest/v1",
        "exportPolicy": "stateport.public-export-allowlist/v1",
        "status": "exported",
        "normalization": {"directoryMode": "0755", "regularFileModes": ["0644", "0755"], "timestamp": "1970-01-01T00:00:00Z"},
        "blockingIssueCounts": [],
        "files": [
            {
                "path": path,
                "mode": "0644",
                "digest": "sha256:" + hashlib.sha256((candidate / path).read_bytes()).hexdigest(),
                "classification": "public-source",
                "license": "AGPL-3.0-or-later",
                "provenanceRationale": "Synthetic exact export policy.",
            }
            for path in candidate_files
        ],
    }
    public_path = root / "source/public-export-manifest.json"
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_text(json.dumps(public_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    value["artifacts"]["publicManifest"]["sha256"] = hashlib.sha256(public_path.read_bytes()).hexdigest()
    value["artifacts"]["publicManifest"]["bytes"] = public_path.stat().st_size
    licensing_path = root / "source/licensing-inventory.yaml"
    licensing_path.write_text(
        yaml.safe_dump(
            {
                "formatVersion": "stateport.rights-inventory/v1",
                "metadata": {
                    "created": "2026-08-09",
                    "scope": "Synthetic exact export policy fixture.",
                    "completeness": "Every synthetic candidate file is covered exactly once.",
                    "notes": "Synthetic fixture only.",
                },
                "files": [
                    {
                        "attribution": "Copyright (C) 2026 Lennert Van Hoyweghen",
                        "category": "owned_code",
                        "evidence": "Synthetic exact export policy fixture.",
                        "path": path,
                        "proposedLicence": "AGPL-3.0-or-later",
                        "publicExportDecision": "include",
                        "redistributable": True,
                        "reviewerStatus": "reviewed_internal",
                        "source": "Synthetic exact export policy fixture.",
                    }
                    for path in candidate_files
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    value["artifacts"]["licensingInventory"]["sha256"] = hashlib.sha256(licensing_path.read_bytes()).hexdigest()
    value["artifacts"]["licensingInventory"]["bytes"] = licensing_path.stat().st_size
    archive_temp = tmp_path / "source.tar"
    _archive(
        candidate,
        archive_temp,
        authority_url=value["repository"]["authorityUrl"],
        ref=value["repository"]["ref"],
        commit=value["repository"]["commit"],
        tree=value["repository"]["tree"],
        manifest_sha256=value["artifacts"]["publicManifest"]["sha256"],
        epoch=1700000000,
    )
    archive_path = root / "source/stateport-source.tar"
    archive_path.write_bytes(archive_temp.read_bytes())
    value["artifacts"]["sourceArchive"]["sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    value["artifacts"]["sourceArchive"]["bytes"] = archive_path.stat().st_size
    value["artifacts"]["sourceArchive"]["embeddedGitIdentity"]["manifestSha256"] = value["artifacts"]["publicManifest"]["sha256"]
    bundle_temp = tmp_path / "source.bundle"
    _bundle(
        candidate,
        bundle_temp,
        commit=value["repository"]["commit"],
        tree=value["repository"]["tree"],
        ref=value["repository"]["ref"],
    )
    bundle_path = root / "source/stateport-public.git.bundle"
    bundle_path.write_bytes(bundle_temp.read_bytes())
    value["artifacts"]["gitBundle"]["sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    value["artifacts"]["gitBundle"]["bytes"] = bundle_path.stat().st_size
    clone_payload = {
        "formatVersion": "stateport.anonymous-normal-clone-receipt/v1",
        "url": value["repository"]["authorityUrl"],
        "ref": value["repository"]["ref"],
        "commit": value["repository"]["commit"],
        "tree": value["repository"]["tree"],
        "verification": "credential-free-normal-clone-fetch-and-ls-remote",
    }
    clone_digest = hashlib.sha256(
        (json.dumps(clone_payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    clone_data = (
        json.dumps(
            {**clone_payload, "receiptId": "clone_receipt_" + clone_digest[:32], "receiptSha256": clone_digest},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    value["repository"]["normalCloneVerification"]["receiptId"] = "clone_receipt_" + clone_digest[:32]
    value["repository"]["normalCloneVerification"]["receiptSha256"] = clone_digest
    for record, data in (
        (value["artifacts"]["normalCloneReceipt"], clone_data),
        (value["artifacts"]["installer"], b"#!/usr/bin/env python3\n"),
        (value["artifacts"]["executionHostProvisioner"], b"#!/bin/sh\nexit 0\n"),
    ):
        path = root / record["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if record in (
            value["artifacts"]["installer"],
            value["artifacts"]["executionHostProvisioner"],
        ):
            path.chmod(0o755)
        record["sha256"] = hashlib.sha256(data).hexdigest()
        record["bytes"] = len(data)
    input_path = root / "candidate-input-manifest.json"
    tracked_paths = [
        "config/public-export-allowlist.v1.yaml",
        "packages/execution-host/src/execution_host/identity-contract.v1.json",
        "packages/execution-host/src/execution_host/identity_contract.py",
        "packages/updater/build-requirements.lock",
        "packages/updater/pyproject.toml",
        "scripts/build_public_release_bundle.py",
        "scripts/export_public_candidate.py",
            "scripts/install_no_checkout.py",
            "scripts/stateport-execution-host-provision",
        "scripts/materialize_public_snapshot.py",
        "scripts/public_snapshot_audit.py",
    ]
    locked_wheels = {
        "setuptools-80.10.2-py3-none-any.whl": _locked_wheel_bytes("setuptools", "80.10.2"),
        "wheel-0.45.1-py3-none-any.whl": _locked_wheel_bytes("wheel", "0.45.1"),
    }
    for filename, wheel_data in locked_wheels.items():
        wheel_path = root / "evidence/locked-build-inputs" / filename
        wheel_path.parent.mkdir(parents=True, exist_ok=True)
        wheel_path.write_bytes(wheel_data)
    tracked_inputs = []
    for path in tracked_paths:
        input_data = (candidate / path).read_bytes()
        tracked_inputs.append(
            {
                "path": path,
                "gitBlob": hashlib.sha1(f"blob {len(input_data)}\0".encode() + input_data).hexdigest(),
                "sha256": hashlib.sha256(input_data).hexdigest(),
                "bytes": len(input_data),
            }
        )
    input_path.write_text(
        json.dumps(
            {
                "formatVersion": "stateport.candidate-input-manifest/v1",
                "authority": {"url": value["repository"]["authorityUrl"], "ref": value["repository"]["ref"]},
                "source": {"commit": value["materialization"]["sourceCommit"], "tree": value["materialization"]["sourceTree"]},
                "trackedInputs": tracked_inputs,
                "externalInputs": {
                    "privateDetectorSet": {"sha256": "d" * 64, "bytes": 1},
                    "lockedBuildInputsSha256": _locked_inputs_digest(locked_wheels),
                    "lockedBuildWheels": [
                        {
                            "filename": filename,
                            "path": f"evidence/locked-build-inputs/{filename}",
                            "sha256": hashlib.sha256(wheel_data).hexdigest(),
                            "bytes": len(wheel_data),
                        }
                        for filename, wheel_data in locked_wheels.items()
                    ],
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    value["artifacts"]["candidateInputManifest"]["sha256"] = hashlib.sha256(input_path.read_bytes()).hexdigest()
    value["artifacts"]["candidateInputManifest"]["bytes"] = input_path.stat().st_size
    wheel = value["artifacts"]["updaterWheel"]
    wheel_data = _wheel_bytes({key: value for key, value in wheel["buildEvidence"].items() if key != "path"})
    for path_value in (wheel["path"], wheel["firstPath"], wheel["secondPath"]):
        path = root / path_value
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(wheel_data)
    wheel["sha256"] = wheel["firstSha256"] = wheel["secondSha256"] = hashlib.sha256(wheel_data).hexdigest()
    wheel["bytes"] = wheel["firstBytes"] = wheel["secondBytes"] = len(wheel_data)
    materialization_receipt = root / "evidence/materialization-receipt.json"
    materialization_receipt.parent.mkdir(parents=True, exist_ok=True)
    materialization_receipt.write_text(
        json.dumps(
            {
                "formatVersion": "stateport.public-snapshot-materialization/v1",
                "candidateHead": value["repository"]["commit"],
                "candidateTree": value["repository"]["tree"],
                "sourceCommit": value["materialization"]["sourceCommit"],
                "sourceTree": value["materialization"]["sourceTree"],
                "publicManifestDigest": "sha256:" + value["artifacts"]["publicManifest"]["sha256"],
                "status": "passed",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest_path = root / "release-tree-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(_release_manifest(root))
    value["artifacts"]["releaseTreeManifest"]["sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    value["artifacts"]["releaseTreeManifest"]["bytes"] = manifest_path.stat().st_size
    provenance_path = root / "provenance/candidate-provenance.yaml"
    provenance_path.parent.mkdir(parents=True, exist_ok=True)
    provenance_path.write_text(yaml.safe_dump(value, sort_keys=True), encoding="utf-8")
    provenance_bytes = provenance_path.read_bytes()
    receipt_payload = {
        "formatVersion": "stateport.public-release-bundle/v1",
        "candidateId": value["candidateId"],
        "sourceCommit": value["materialization"]["sourceCommit"],
        "sourceTree": value["materialization"]["sourceTree"],
        "publicCommit": value["repository"]["commit"],
        "publicTree": value["repository"]["tree"],
        "publicAuthority": value["repository"]["authorityUrl"],
        "publicRef": value["repository"]["ref"],
        "candidateInputManifestSha256": value["artifacts"]["candidateInputManifest"]["sha256"],
        "releaseTreeManifestSha256": value["artifacts"]["releaseTreeManifest"]["sha256"],
        "provenance": {
            "path": "provenance/candidate-provenance.yaml",
            "sha256": hashlib.sha256(provenance_bytes).hexdigest(),
            "bytes": len(provenance_bytes),
        },
        "status": "built_local_unpublished_pending_signing",
    }
    receipt_content = (json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    bundle_receipt = root / "bundle-receipt.json"
    bundle_receipt.write_bytes(
        json.dumps(
            {
                **receipt_payload,
                "receiptContentSha256": hashlib.sha256(receipt_content).hexdigest(),
                "receiptContentBytes": len(receipt_content),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    verify_release_tree(value, root)
    archive_files, _archive_modes = provenance._verify_source_archive(
        value, root, (root / "source/stateport-source.tar").read_bytes()
    )
    bundle_files = provenance._recover_bundle_files(value, root / "source/stateport-public.git.bundle")
    manifest_document = json.loads((root / "source/public-export-manifest.json").read_text(encoding="utf-8"))
    rights_document = yaml.safe_load((root / "source/licensing-inventory.yaml").read_text(encoding="utf-8"))
    forged_manifest = deepcopy(manifest_document)
    forged_manifest["files"][0]["license"] = "CC-BY-4.0"
    with pytest.raises(CandidateProvenanceError, match="does not match exact policy"):
        provenance._verify_exact_export_policy(forged_manifest, rights_document, archive_files, bundle_files)
    forged_rights = deepcopy(rights_document)
    forged_rights["files"][0]["proposedLicence"] = "CC-BY-4.0"
    with pytest.raises(CandidateProvenanceError, match="does not match exact policy"):
        provenance._verify_exact_export_policy(manifest_document, forged_rights, archive_files, bundle_files)
    forged_inputs = json.loads((root / "candidate-input-manifest.json").read_text(encoding="utf-8"))
    forged_value = deepcopy(value)
    forged_value["materialization"]["exporter"]["gitBlob"] = "0" * 40
    with pytest.raises(CandidateProvenanceError, match="exporter blob"):
        provenance._verify_candidate_input_manifest(
            forged_value,
            (json.dumps(forged_inputs, sort_keys=True) + "\n").encode(),
            root,
            archive_files,
            bundle_files,
        )
    with pytest.raises(CandidateProvenanceError):
        provenance._validate_schema_document(
            {"formatVersion": "stateport.public-export-manifest/v1"},
            "public-export-manifest.v1.schema.json",
            "public export manifest",
        )
    release_manifest = json.loads((root / "release-tree-manifest.json").read_text(encoding="utf-8"))
    release_manifest["files"][0]["unexpected"] = True
    with pytest.raises(CandidateProvenanceError):
        provenance._validate_schema_document(
            release_manifest,
            "release-tree-manifest.v1.schema.json",
            "release-tree manifest",
        )
    installer = root / "installer/install.sh"
    installer.chmod(0o644)
    with pytest.raises(CandidateProvenanceError):
        verify_release_tree(value, root)
    installer.chmod(0o755)
    with pytest.raises(CandidateProvenanceError, match="real wheel"):
        provenance._verify_locked_wheel("wheel-0.45.1-py3-none-any.whl", b"not a wheel")
    original_recover = provenance._recover_bundle_files

    def forged_modes(contract: dict[str, object], bundle_path: Path) -> dict[str, tuple[bytes, str]]:
        files = original_recover(contract, bundle_path)
        path = next(iter(files))
        content, mode = files[path]
        files[path] = (content, "0755" if mode == "0644" else "0644")
        return files

    monkeypatch.setattr(provenance, "_recover_bundle_files", forged_modes)
    with pytest.raises(CandidateProvenanceError, match="mode does not match"):
        verify_release_tree(value, root)
    monkeypatch.undo()

    for path_value in (
        value["artifacts"]["updaterWheel"]["path"],
        value["artifacts"]["updaterWheel"]["firstPath"],
        value["artifacts"]["updaterWheel"]["secondPath"],
    ):
        (root / path_value).write_bytes(b"arbitrary replacement")
    with pytest.raises(CandidateProvenanceError, match="valid ZIP wheel"):
        _verify_updater_wheel(
            value,
            root,
            value["artifacts"]["updaterWheel"]["buildEvidence"]["lockedInputsSha256"],
        )
    for relative in (
        "source/stateport-source.tar",
        "source/stateport-public.git.bundle",
        "candidate-input-manifest.json",
        "bundle-receipt.json",
    ):
        path = root / relative
        original = path.read_bytes()
        path.write_bytes(original + b"tampered\n")
        with pytest.raises(CandidateProvenanceError):
            verify_release_tree(value, root)
        path.write_bytes(original)
    (root / "source/public-export-manifest.json").write_bytes(b"tampered\n")
    with pytest.raises(CandidateProvenanceError, match="digest or size mismatch"):
        verify_release_tree(value, root)


def _successor_contract(tmp_path: Path) -> dict[str, object]:
    candidate_path, commit, tree = _candidate(tmp_path)
    locked_wheels = {
        "setuptools-80.10.2-py3-none-any.whl": _locked_wheel_bytes("setuptools", "80.10.2"),
        "wheel-0.45.1-py3-none-any.whl": _locked_wheel_bytes("wheel", "0.45.1"),
    }
    wheel_evidence = {
        "path": "stateport_updater/_build_identity.py",
        "formatVersion": "stateport.updater-build-evidence/v1",
        "sourceTree": tree,
        "lockedInputsSha256": _locked_inputs_digest(locked_wheels),
        "runtime": {
            "implementation": "CPython",
            "pip": "25.0.1",
            "pipExecutable": "build-venv/bin/python -m pip",
            "python": "3.14.6",
            "pythonExecutable": "build-venv/bin/python",
            "setuptools": "80.10.2",
            "wheel": "0.45.1",
        },
    }
    wheel_data = _wheel_bytes({key: value for key, value in wheel_evidence.items() if key != "path"})

    def source_blob(path: str) -> dict[str, str]:
        data = (candidate_path / path).read_bytes()
        return {
            "gitBlob": hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    payload = {
        "formatVersion": "stateport.anonymous-normal-clone-receipt/v1",
        "url": "https://github.com/example/stateport.git",
        "ref": "refs/heads/public-main",
        "commit": commit,
        "tree": tree,
        "verification": "credential-free-normal-clone-fetch-and-ls-remote",
    }
    receipt_digest = hashlib.sha256(
        (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    receipt = {
        **payload,
        "receiptId": "clone_receipt_" + receipt_digest[:32],
        "receiptSha256": receipt_digest,
    }
    receipt_bytes = (json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    def artifact(path: str, digest: str = "b" * 64) -> dict[str, object]:
        return {"path": path, "sha256": digest, "bytes": 1}

    public_manifest = artifact("source/public-export-manifest.json", "5" * 64)
    return {
        "schema": "stateport.candidate-provenance/v2",
        "candidateId": "stateport-alpha4-test",
        "classification": "public_successor_release_candidate",
        "authorityClass": "public_git_authority_and_local_build_evidence",
        "authoritativeForInstallation": False,
        "repository": {
            "authorityUrl": payload["url"],
            "ref": payload["ref"],
            "commit": commit,
            "tree": tree,
            "objectFormat": "sha1",
            "normalCloneVerification": {
                "status": "verified_anonymous_normal_clone",
                "receiptId": "clone_receipt_" + receipt_digest[:32],
                "receiptSha256": receipt_digest,
                "url": payload["url"],
                "ref": payload["ref"],
                "commit": commit,
                "tree": tree,
            },
        },
        "materialization": {
            "sourceRepository": "https://github.com/example/private.git",
            "sourceCommit": "c" * 40,
            "sourceTree": "d" * 40,
            "materializer": source_blob("scripts/materialize_public_snapshot.py"),
            "exporter": source_blob("scripts/export_public_candidate.py"),
            "policy": source_blob("config/public-export-allowlist.v1.yaml"),
        },
        "artifacts": {
            "publicManifest": public_manifest,
            "licensingInventory": artifact("source/licensing-inventory.yaml"),
            "normalCloneReceipt": {**artifact("evidence/anonymous-normal-clone-receipt.json"), "sha256": hashlib.sha256(receipt_bytes).hexdigest(), "bytes": len(receipt_bytes)},
            "sourceArchive": {**artifact("source/stateport-source.tar"), "embeddedGitIdentity": {"authorityUrl": payload["url"], "ref": payload["ref"], "commit": commit, "tree": tree, "manifestSha256": "5" * 64}},
            "gitBundle": {**artifact("source/stateport-public.git.bundle"), "ref": payload["ref"], "commit": commit, "tree": tree},
            "installer": {**artifact("installer/install.sh"), "sourceCommit": "c" * 40, "sourcePath": "scripts/install_no_checkout.py"},
            "executionHostProvisioner": {**artifact("provisioning/stateport-execution-host-provision"), "sourceCommit": "c" * 40, "sourcePath": "scripts/stateport-execution-host-provision"},
            "updaterWheel": {"path": "updater/stateport-updater.whl", "sha256": hashlib.sha256(wheel_data).hexdigest(), "bytes": len(wheel_data), "firstPath": "updater/stateport-updater-first.whl", "secondPath": "updater/stateport-updater-second.whl", "reproducible": True, "firstSha256": hashlib.sha256(wheel_data).hexdigest(), "secondSha256": hashlib.sha256(wheel_data).hexdigest(), "firstBytes": len(wheel_data), "secondBytes": len(wheel_data), "buildEvidence": wheel_evidence},
            "candidateInputManifest": artifact("candidate-input-manifest.json"),
            "releaseTreeManifest": artifact("release-tree-manifest.json"),
        },
        "verification": {
            "normalClone": "verified_anonymous_normal_clone",
            "sourceArchive": "verified_contents_and_embedded_git_identity",
            "gitBundle": "verified_ref_commit_tree_recovery",
            "updaterWheel": "verified_twice_byte_equal_from_locked_inputs",
            "signing": "pending_owner_authorized_signing",
        },
        "retention": {
            "status": "local_candidate_not_published",
            "retainUntil": "explicit_owner_disposition_or_superseding_verified_candidate",
            "deletionRequiresExplicitOwnerApproval": True,
        },
    }


def test_successor_contract_binds_public_authority_and_clone_receipt(tmp_path: Path) -> None:
    value = _successor_contract(tmp_path)
    validate_contract(value, SCHEMA)
    forged = deepcopy(value)
    forged["repository"]["normalCloneVerification"]["url"] = "https://github.com/example/other.git"
    with pytest.raises(CandidateProvenanceError, match="public Git authority"):
        validate_contract(forged, SCHEMA)
    forged_archive = deepcopy(value)
    forged_archive["artifacts"]["sourceArchive"]["embeddedGitIdentity"]["manifestSha256"] = "0" * 64
    with pytest.raises(CandidateProvenanceError, match="manifest digest"):
        validate_contract(forged_archive, SCHEMA)
    forged_receipt = deepcopy(value)
    forged_receipt["artifacts"]["normalCloneReceipt"]["sha256"] = "0" * 64
    with pytest.raises(CandidateProvenanceError, match="receipt artifact digest"):
        validate_contract(forged_receipt, SCHEMA)
    forged_wheel = deepcopy(value)
    forged_wheel["artifacts"]["updaterWheel"]["sha256"] = "0" * 64
    with pytest.raises(CandidateProvenanceError, match="wheel artifact digest"):
        validate_contract(forged_wheel, SCHEMA)
    forged_provisioner = deepcopy(value)
    forged_provisioner["artifacts"]["executionHostProvisioner"]["sourceCommit"] = "0" * 40
    with pytest.raises(CandidateProvenanceError, match="provisioner is not extracted"):
        validate_contract(forged_provisioner, SCHEMA)


def test_local_qualification_provenance_validates_through_complete_contract(tmp_path: Path) -> None:
    value = _successor_contract(tmp_path)
    authority = "https://127.0.0.1:5443/stateport-qualification.git"
    ref = "refs/heads/qualification-local-900001"
    value["classification"] = "local_qualification_candidate"
    value["authorityClass"] = "local_qualification_git_authority_and_local_build_evidence"
    value["repository"]["authorityUrl"] = authority
    value["repository"]["ref"] = ref
    clone = value["repository"]["normalCloneVerification"]
    clone["status"] = "verified_local_qualification_clone"
    clone["url"] = authority
    clone["ref"] = ref
    value["artifacts"]["sourceArchive"]["embeddedGitIdentity"]["authorityUrl"] = authority
    value["artifacts"]["sourceArchive"]["embeddedGitIdentity"]["ref"] = ref
    value["artifacts"]["gitBundle"]["ref"] = ref
    value["verification"]["normalClone"] = "verified_local_qualification_clone"

    payload = {
        "formatVersion": "stateport.local-qualification-clone-receipt/v1",
        "url": authority,
        "ref": ref,
        "commit": value["repository"]["commit"],
        "tree": value["repository"]["tree"],
        "verification": "local-clone-and-recovery-with-fsck",
    }
    receipt_digest = hashlib.sha256(
        (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    receipt = {
        **payload,
        "receiptId": "clone_receipt_" + receipt_digest[:32],
        "receiptSha256": receipt_digest,
    }
    clone["receiptId"] = receipt["receiptId"]
    clone["receiptSha256"] = receipt_digest
    receipt_bytes = (json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    value["artifacts"]["normalCloneReceipt"]["sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
    value["artifacts"]["normalCloneReceipt"]["bytes"] = len(receipt_bytes)

    validate_contract(value, SCHEMA)


def test_stateport_crun_debian_package_is_deterministic_and_installs_exact_binary(
    tmp_path: Path,
) -> None:
    binary = b"fixture-static-crun\n"
    first = bundle._stateport_crun_deb(binary, epoch=1788220800)
    second = bundle._stateport_crun_deb(binary, epoch=1788220800)
    assert first == second

    package = tmp_path / "stateport-crun.deb"
    package.write_bytes(first)
    metadata = subprocess.run(
        ["dpkg-deb", "--field", str(package), "Package", "Version", "Architecture"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "Package: stateport-crun\n" in metadata
    assert f"Version: {bundle.STATEPORT_CRUN_VERSION}\n" in metadata
    assert "Architecture: amd64\n" in metadata

    extracted = tmp_path / "extracted"
    subprocess.run(["dpkg-deb", "--extract", str(package), str(extracted)], check=True)
    runtime = extracted / "usr/libexec/stateport/crun"
    assert runtime.read_bytes() == binary
    assert runtime.stat().st_mode & 0o111


def _release_bundle_cli_arguments(tmp_path: Path) -> list[str]:
    return [
        "--source",
        str(tmp_path / "source"),
        "--commit",
        "0" * 40,
        "--version",
        "0.1.0-alpha.17",
        "--source-url",
        "https://github.com/lennertvhoy/StatePort.git",
        "--public-url",
        "https://127.0.0.1:5443/stateport-qualification.git",
        "--clone-parent",
        str(tmp_path / "clone-parent"),
        "--private-detectors",
        str(tmp_path / "private-export-detectors.json"),
        "--wheelhouse",
        str(tmp_path / "wheelhouse"),
        "--output",
        str(tmp_path / "output"),
    ]


def test_cli_forwards_local_qualification_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forwarded: dict[str, object] = {}

    def fake_build_release_bundle(**arguments: object) -> dict[str, object]:
        forwarded.update(arguments)
        return {"status": "ok"}

    def fake_require_guard(*arguments: object) -> str:
        return "guard-receipt"

    monkeypatch.setattr(bundle, "build_release_bundle", fake_build_release_bundle)
    monkeypatch.setattr(bundle, "require_guard", fake_require_guard)

    exit_code = bundle.main(
        [
            *_release_bundle_cli_arguments(tmp_path),
            "--qualification-local",
            "--qualification-ref",
            "refs/heads/qualification-local-alpha17",
        ]
    )

    assert exit_code == 0
    assert forwarded["qualification_local"] is True
    assert forwarded["qualification_ref"] == "refs/heads/qualification-local-alpha17"


def test_cli_refuses_qualification_ref_without_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def unexpected(*arguments: object, **keywords: object) -> dict[str, object]:
        raise AssertionError("release build must not run for refused arguments")

    monkeypatch.setattr(bundle, "build_release_bundle", unexpected)
    monkeypatch.setattr(bundle, "require_guard", unexpected)

    with pytest.raises(SystemExit) as refusal:
        bundle.main(
            [
                *_release_bundle_cli_arguments(tmp_path),
                "--qualification-ref",
                "refs/heads/qualification-local-alpha17",
            ]
        )

    assert refusal.value.code == 2
    assert (
        "--qualification-ref is only valid together with --qualification-local"
        in capsys.readouterr().err
    )


def test_cli_requires_qualification_ref_for_local_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def unexpected(*arguments: object, **keywords: object) -> dict[str, object]:
        raise AssertionError("release build must not run for refused arguments")

    monkeypatch.setattr(bundle, "build_release_bundle", unexpected)
    monkeypatch.setattr(bundle, "require_guard", unexpected)

    with pytest.raises(SystemExit) as refusal:
        bundle.main([*_release_bundle_cli_arguments(tmp_path), "--qualification-local"])

    assert refusal.value.code == 2
    assert "--qualification-local requires --qualification-ref" in capsys.readouterr().err
