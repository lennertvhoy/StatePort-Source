"""Mandatory clean-host and no-checkout wheel proof for the updater runtime."""

from __future__ import annotations

import json
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
import zipfile

import pytest

from scripts.test_release_contracts import release_index


ROOT = Path(__file__).resolve().parents[1]


def _source_fixture(tmp_path: Path) -> tuple[Path, dict]:
    """Build the real Git-backed source witness without importing checkout code in the proof."""

    helper_path = ROOT / "packages/execution-host/tests/test_workspace_source.py"
    spec = importlib.util.spec_from_file_location("stateport_source_fixture", helper_path)
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    fixture_parent = tmp_path / "source-fixture"
    fixture_parent.mkdir(mode=0o700)
    return helper._fixture(fixture_parent)


def _build_wheel(
    *,
    build_python: Path,
    build_inputs: Path,
    context: Path,
    wheelhouse: Path,
    environment: dict[str, str],
) -> Path:
    wheelhouse.mkdir()
    subprocess.run(
        [
            str(build_python),
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--find-links",
            str(build_inputs),
            "--wheel-dir",
            str(wheelhouse),
            str(context / "updater"),
        ],
        cwd=Path("/"),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(wheelhouse.glob("stateport_updater-0.1.1-*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def test_updater_package_metadata_is_pinned_and_has_no_runtime_dependency() -> None:
    package = ROOT / "packages/updater"
    metadata = tomllib.loads((package / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["build-system"]["requires"] == [
        "setuptools==80.10.2",
        "wheel==0.45.1",
    ]
    assert metadata["project"]["dependencies"] == []
    assert metadata["project"]["requires-python"] == ">=3.12"
    assert metadata["project"]["version"] == "0.1.1"
    lock = (package / "build-requirements.lock").read_text(encoding="utf-8")
    assert "setuptools==80.10.2" in lock
    assert "95b30ddfb717250edb492926c92b5221f7ef3fbcc2b07579bcd4a27da21d0173" in lock
    assert "wheel==0.45.1" in lock
    assert "708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248" in lock
    authority_source = (package / "src/stateport_updater/authority.py").read_text(encoding="utf-8")
    assert "from governed_runner" not in authority_source
    assert "import governed_runner" not in authority_source


def test_updater_wheel_installs_without_checkout_or_pythonpath(tmp_path: Path) -> None:
    build_inputs_value = os.environ.get("STATEPORT_UPDATER_BUILD_WHEELHOUSE")
    if build_inputs_value is None:
        pytest.fail(
            "mandatory offline wheel proof requires "
            "STATEPORT_UPDATER_BUILD_WHEELHOUSE with the locked build wheels"
        )
    build_inputs = Path(build_inputs_value)
    assert build_inputs.is_absolute() and build_inputs.is_dir()
    context = tmp_path / "context/packages"
    shutil.copytree(ROOT / "packages/updater", context / "updater")
    shutil.copytree(ROOT / "packages/release-contracts", context / "release-contracts")
    shutil.copytree(ROOT / "packages/execution-host", context / "execution-host")
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PIP_NO_INDEX"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["SOURCE_DATE_EPOCH"] = "1785585600"
    build_environment = tmp_path / "build-environment"
    subprocess.run(
        [sys.executable, "-m", "venv", str(build_environment)],
        cwd=tmp_path,
        env=environment,
        check=True,
    )
    build_python = build_environment / "bin/python"
    subprocess.run(
        [
            str(build_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(build_inputs),
            "--require-hashes",
            "-r",
            str(context / "updater/build-requirements.lock"),
        ],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    first_wheel = _build_wheel(
        build_python=build_python,
        build_inputs=build_inputs,
        context=context,
        wheelhouse=tmp_path / "wheelhouse-first",
        environment=environment,
    )
    second_wheel = _build_wheel(
        build_python=build_python,
        build_inputs=build_inputs,
        context=context,
        wheelhouse=tmp_path / "wheelhouse-second",
        environment=environment,
    )
    assert (
        hashlib.sha256(first_wheel.read_bytes()).digest()
        == hashlib.sha256(second_wheel.read_bytes()).digest()
    )
    with zipfile.ZipFile(first_wheel) as archive:
        names = set(archive.namelist())
        contents = {name: archive.read(name) for name in names if not name.endswith("/")}
    assert "stateport_updater/cli.py" in names
    assert "stateport_release/contract.py" in names
    assert "execution_host/client.py" in names
    assert "execution_host/daemon_contract.py" in names
    assert "execution_host/workspace_source.py" in names
    assert any(name.endswith("update-status.v1.schema.json") for name in names)
    allowed_prefixes = (
        "execution_host/",
        "stateport_updater/",
        "stateport_release/",
        "stateport_updater-0.1.1.dist-info/",
    )
    assert all(name.startswith(allowed_prefixes) for name in names)
    assert not any(
        forbidden in name.lower()
        for name in names
        for forbidden in (".git", "__pycache__", ".pyc", "/test", "governed_runner/")
    )
    forbidden_payloads = {
        str(ROOT).encode(),
        str(context).encode(),
        str(tmp_path).encode(),
        b"/home/",
    }
    assert not any(
        marker in payload for payload in contents.values() for marker in forbidden_payloads
    )
    metadata = next(
        payload.decode("utf-8")
        for name, payload in contents.items()
        if name.endswith(".dist-info/METADATA")
    )
    assert "Name: stateport-updater\n" in metadata
    assert "Version: 0.1.1\n" in metadata
    assert "Requires-Dist:" not in metadata

    virtualenv = tmp_path / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(virtualenv)],
        cwd=tmp_path,
        env=environment,
        check=True,
    )
    python = virtualenv / "bin/python"
    updater = virtualenv / "bin/stateport-updater"
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(first_wheel.parent),
            "stateport-updater==0.1.1",
        ],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    state_root = tmp_path / "must-not-exist"
    runtime_environment = {
        "PATH": str(virtualenv / "bin"),
        "LANG": environment.get("LANG", "C.UTF-8"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    assert shutil.which("git", path=runtime_environment["PATH"]) is None
    shutil.rmtree(context.parent)
    shutil.rmtree(build_environment)
    shutil.rmtree(second_wheel.parent)
    origins = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            (
                "import importlib.util,json,execution_host.client,stateport_release,stateport_updater;"
                "print(json.dumps({'release':stateport_release.__file__,"
                "'updater':stateport_updater.__file__,"
                "'executionHostClient':execution_host.client.__file__,"
                "'governedRunner':importlib.util.find_spec('governed_runner')}))"
            ),
        ],
        cwd=Path("/"),
        env=runtime_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    origin_result = json.loads(origins.stdout)
    site_packages = virtualenv / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_packages /= "site-packages"
    assert Path(origin_result["release"]).resolve().is_relative_to(site_packages.resolve())
    assert Path(origin_result["updater"]).resolve().is_relative_to(site_packages.resolve())
    assert Path(origin_result["executionHostClient"]).resolve().is_relative_to(
        site_packages.resolve()
    )
    workspace_source_origin = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import execution_host.workspace_source; print(execution_host.workspace_source.__file__)",
        ],
        cwd=Path("/"),
        env=runtime_environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    workspace_source_path = Path(workspace_source_origin.stdout.strip()).resolve()
    assert workspace_source_path.is_relative_to(site_packages.resolve())
    assert origin_result["governedRunner"] is None

    source_root, source = _source_fixture(tmp_path)
    shutil.rmtree(source_root / ".git")
    assert not (source_root / ".git").exists()
    source_document = tmp_path / "reviewed-source.json"
    source_document.write_text(json.dumps(source), encoding="utf-8")
    verify_script = """
import json
import os
from pathlib import Path
import sys

from execution_host.workspace_source import verify_source_commit

root = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    verify_source_commit(root, json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")), owner_uid=os.geteuid())
finally:
    os.close(root)
print("verified")
"""
    verified_source = subprocess.run(
        [str(python), "-I", "-c", verify_script, str(source_root), str(source_document)],
        cwd=Path("/"),
        env=runtime_environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert verified_source.stdout.strip() == "verified"
    assert next(row for row in source["sourceInventory"] if row["path"] == "bin/run.sh")["mode"] == "100755"
    (source_root / "README.md").write_bytes(b"changed source\n")
    refused_source = subprocess.run(
        [str(python), "-I", "-c", verify_script, str(source_root), str(source_document)],
        cwd=Path("/"),
        env=runtime_environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert refused_source.returncode != 0
    assert "WorkspaceSourceRefusal" in refused_source.stderr

    health = subprocess.run(
        [str(updater), "--state-root", str(state_root), "health"],
        cwd=Path("/"),
        env=runtime_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(health.stdout)["status"] == "alive"
    refusal = subprocess.run(
        [
            str(updater),
            "--state-root",
            str(state_root),
            "apply",
            "--plan-id",
            "update_plan_" + "a" * 32,
        ],
        cwd=Path("/"),
        env=runtime_environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert refusal.returncode == 3
    assert json.loads(refusal.stdout)["code"] == "installed_authority_adapter_required"
    assert not state_root.exists()

    release_document = tmp_path / "release-index.json"
    release_document.write_text(json.dumps(release_index()), encoding="utf-8")
    initialize_script = """
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from stateport_release import (
    ReleaseVerificationPolicy,
    SignatureVerificationProof,
    SignerIdentity,
    to_updater_release_envelope,
    verify_release_index,
)
from stateport_updater import UpdateEngine, UpdatePolicy, UpdateStore


class TestVerifier:
    def _proof(self, signature):
        return SignatureVerificationProof(
            subject_digest=str(signature["subjectDigest"]),
            bundle_digest=str(signature["bundle"]["digest"]),
            trust_mode=str(signature["trustMode"]),
            identity_primary=str(signature["certificateIdentity"]),
            identity_secondary=str(signature["certificateOidcIssuer"]),
            verified_at=datetime(2026, 8, 1, 11, 59, tzinfo=timezone.utc),
            transparency_log_mode=str(signature["transparencyLog"]),
        )

    def verify_blob(self, payload, signature):
        observed = "sha256:" + hashlib.sha256(payload).hexdigest()
        if signature["subjectDigest"] != observed:
            raise ValueError("test descriptor does not bind payload")
        return self._proof(signature)

    def verify_image(self, reference, signature):
        if reference.rsplit("@", 1)[-1] != signature["subjectDigest"]:
            raise ValueError("test descriptor does not bind image")
        return self._proof(signature)


document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
signature = document["signatures"][0]
now = datetime(2026, 8, 1, 12, tzinfo=timezone.utc)
policy = ReleaseVerificationPolicy(
    expected_channel="alpha",
    expected_target="linux-amd64-rootless-podman-quadlet",
    updater_version="0.1.0",
    accepted_signers=frozenset({SignerIdentity(
        signature["certificateIdentity"],
        signature["certificateOidcIssuer"],
    )}),
    expected_trust_mode="keyless-certificate",
    now=now,
    allow_candidate=True,
)
verifier = TestVerifier()
verified = verify_release_index(document, policy=policy, verifier=verifier)
store = UpdateStore.create(Path(sys.argv[2]))
engine = UpdateEngine(
    store,
    object(),
    object(),
    verification_policy=policy,
    signature_verifier=verifier,
    clock=lambda: now,
)
print(json.dumps(engine.initialize(
    to_updater_release_envelope(verified),
    UpdatePolicy(mode="download-and-notify", channel="alpha"),
)))
"""
    initialized = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            initialize_script,
            str(release_document),
            str(state_root),
        ],
        cwd=Path("/"),
        env=runtime_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(initialized.stdout)["current"]["releaseId"] == ("stateport-alpha-0.2.0-rc.1")
    status = subprocess.run(
        [str(updater), "--state-root", str(state_root), "status"],
        cwd=Path("/"),
        env=runtime_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(status.stdout)["current"]["releaseId"] == "stateport-alpha-0.2.0-rc.1"
    for path in state_root.rglob("*"):
        assert not path.is_symlink()
        assert path.stat().st_mode & 0o077 == 0
        if path.is_file():
            payload = path.read_bytes()
            assert str(ROOT).encode() not in payload
            assert str(tmp_path).encode() not in payload
    assert not list(state_root.rglob("__pycache__"))
