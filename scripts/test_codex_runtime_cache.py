"""Cheap tests for the native pilot cached-work correspondence verifier."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPAIR = ROOT / "config" / "codex-runtime" / "v8-repair"
sys.path.insert(0, str(REPAIR))

from verify_cached_work import (  # noqa: E402
    VerificationError,
    _verify_outer_command,
    _verify_planned_owner_interruption,
    _verify_receipts,
    compare_tree,
)
from prepare import recipe, sha256  # noqa: E402


def _tree(root: Path, *, content: str = "ok") -> None:
    (root / "nested").mkdir(parents=True)
    (root / "nested" / "data.txt").write_text(content)
    (root / "run.sh").write_text("#!/bin/sh\n")
    (root / "run.sh").chmod(0o755)
    os.symlink("nested/data.txt", root / "alias")


def test_compare_tree_accepts_matching_file_mode_and_symlink(tmp_path: Path) -> None:
    expected, actual = tmp_path / "expected", tmp_path / "actual"
    expected.mkdir(); actual.mkdir()
    _tree(expected); _tree(actual)
    result = compare_tree(expected, actual, "fixture")
    assert result["files"] == 2
    assert result["symlinks"] == 1


@pytest.mark.parametrize("mutation", ["content", "mode", "link"])
def test_compare_tree_rejects_untrusted_mutation(tmp_path: Path, mutation: str) -> None:
    expected, actual = tmp_path / "expected", tmp_path / "actual"
    expected.mkdir(); actual.mkdir()
    _tree(expected); _tree(actual)
    if mutation == "content":
        (actual / "nested" / "data.txt").write_text("changed")
    elif mutation == "mode":
        (actual / "run.sh").chmod(0o644)
    else:
        (actual / "alias").unlink()
        os.symlink("run.sh", actual / "alias")
    with pytest.raises(VerificationError):
        compare_tree(expected, actual, "fixture")


def _valid_outer_command(image: str) -> list[str]:
    return [
        "/usr/bin/podman", "--cgroup-manager=cgroupfs", "run", "--pull=never", "--cgroups=split", "--network=none",
        "--cidfile", "/home/operator/container-id", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--pids-limit=256", "--cpus=1",
        "--memory=3g", "--memory-swap=3g", "--tmpfs=/tmp:rw,nosuid,nodev,size=64m",
        "--mount", "type=bind,src=/immutable/inputs,dst=/inputs,ro",
        "--mount", "type=bind,src=/immutable/vendor,dst=/vendor-inputs,ro",
        "--mount", "type=bind,src=/cached/work,dst=/work,rw", image,
        "--timeout-seconds=7200", "--require-containment",
    ]


def test_outer_command_requires_read_only_inputs_and_exact_image(tmp_path: Path) -> None:
    image = "sha256:" + "a" * 64
    (tmp_path / "command.json").write_text(json.dumps({"command": _valid_outer_command(image)}))
    inputs = tmp_path / "immutable" / "inputs"
    vendor = tmp_path / "immutable" / "vendor"
    inputs.mkdir(parents=True)
    vendor.mkdir(parents=True)
    command = _valid_outer_command(image)
    command[command.index('/home/operator/container-id')] = str(tmp_path / 'container-id')
    command[command.index("type=bind,src=/immutable/inputs,dst=/inputs,ro")] = (
        f"type=bind,src={inputs},dst=/inputs,ro"
    )
    command[command.index("type=bind,src=/immutable/vendor,dst=/vendor-inputs,ro")] = (
        f"type=bind,src={vendor},dst=/vendor-inputs,ro"
    )
    command[command.index("type=bind,src=/cached/work,dst=/work,rw")] = (
        f"type=bind,src={tmp_path / 'work'},dst=/work,rw"
    )
    (tmp_path / "work").mkdir()
    (tmp_path / "command.json").write_text(json.dumps({"command": command}))
    result = _verify_outer_command(tmp_path, image, inputs, vendor)
    assert result["timeoutArgument"] == "--timeout-seconds=7200"
    command = _valid_outer_command(image)
    command[command.index("type=bind,src=/immutable/inputs,dst=/inputs,ro")] = "type=bind,src=/mutable/inputs,dst=/inputs,rw"
    (tmp_path / "command.json").write_text(json.dumps({"command": command}))
    with pytest.raises(VerificationError):
        _verify_outer_command(tmp_path, image, inputs, vendor)


def test_outer_command_rejects_reviewed_destinations_from_wrong_roots(tmp_path: Path) -> None:
    image = "sha256:" + "b" * 64
    inputs, vendor = tmp_path / "inputs", tmp_path / "vendor"
    inputs.mkdir(); vendor.mkdir(); (tmp_path / "work").mkdir()
    command = _valid_outer_command(image)
    # Keep the expected destination/mode but point at an unrelated root.
    (tmp_path / "command.json").write_text(json.dumps({"command": command}))
    with pytest.raises(VerificationError):
        _verify_outer_command(tmp_path, image, inputs, vendor)


@pytest.mark.parametrize('mutation', [None, 'malformed_scope', 'command_parent', 'proof_parent', 'escaped_process', 'container_id', 'extra_option'])
def test_current_runner_requires_exact_command_and_containment(tmp_path: Path, mutation: str | None) -> None:
    image = 'sha256:' + 'b' * 64
    inputs, vendor = tmp_path / 'inputs', tmp_path / 'vendor'
    inputs.mkdir(); vendor.mkdir(); (tmp_path / 'work').mkdir()
    parent = "/user.slice/user-1000.slice/user@1000.service/stateport.slice/stateport-heavy.slice/stateport-heavy-123-456.service"
    if mutation == 'malformed_scope':
        parent = '/user.slice/unrelated/stateport-heavy-123-456.service'
    cid = 'c' * 64
    command = _valid_outer_command(image)
    command[command.index('--cgroups=split'):command.index('--cgroups=split') + 1] = [
        '--cgroups=no-conmon', '--cgroup-parent', parent,
    ]
    replacements = {
        '/home/operator/container-id': str(tmp_path / 'container-id'),
        'type=bind,src=/immutable/inputs,dst=/inputs,ro': f'type=bind,src={inputs},dst=/inputs,ro',
        'type=bind,src=/immutable/vendor,dst=/vendor-inputs,ro': f'type=bind,src={vendor},dst=/vendor-inputs,ro',
        'type=bind,src=/cached/work,dst=/work,rw': f'type=bind,src={tmp_path / "work"},dst=/work,rw',
    }
    command = [replacements.get(item, item) for item in command]
    proof = {'status': 'passed', 'bookedScope': parent, 'containerId': cid,
             'processes': {'init': {'cgroup': parent + '/libpod-' + cid},
                           'conmon': {'cgroup': parent + '/runtime'}}}
    (tmp_path / 'containment.json').write_text(json.dumps(proof))
    if mutation == 'command_parent': command[command.index(parent)] = parent + '/other'
    if mutation == 'proof_parent': proof['bookedScope'] = parent + '/other'
    if mutation == 'escaped_process': proof['processes']['conmon']['cgroup'] = parent + '/../other'
    if mutation == 'container_id': proof['containerId'] = 'd' * 64
    if mutation == 'extra_option': command.insert(5, '--network=host')
    # Podman removes its cidfile during normal container cleanup. The durable
    # outer observation and inner admission must suffice after that cleanup.
    (tmp_path / 'work/containment-approved.json').write_text(json.dumps(proof))
    (tmp_path / 'command.json').write_text(json.dumps({'command': command, 'governorCgroup': parent}))
    if mutation is None:
        assert _verify_outer_command(tmp_path, image, inputs, vendor)['timeoutArgument'] == '--timeout-seconds=7200'
    else:
        with pytest.raises(VerificationError):
            _verify_outer_command(tmp_path, image, inputs, vendor)


def test_outer_command_rejects_unparsed_extra_mount(tmp_path: Path) -> None:
    image = "sha256:" + "c" * 64
    inputs, vendor = tmp_path / "inputs", tmp_path / "vendor"
    inputs.mkdir(); vendor.mkdir(); (tmp_path / "work").mkdir()
    command = _valid_outer_command(image)
    command[command.index("--require-containment"):command.index("--require-containment")] = [
        "--mount", "type=bind,src=/tmp/other,dst=/tmp,ro"
    ]
    (tmp_path / "command.json").write_text(json.dumps({"command": command}))
    with pytest.raises(VerificationError):
        _verify_outer_command(tmp_path, image, inputs, vendor)


def _interrupted_receipts(tmp_path: Path) -> tuple[Path, Path, dict, str]:
    cached = tmp_path / "cached"
    work = cached / "work"
    work.mkdir(parents=True)
    scope = "/user.slice/user-1000.slice/user@1000.service/stateport.slice/stateport-heavy.slice/stateport-heavy-1-2.service"
    container_id = "a" * 64
    containment = {"status": "passed", "containerId": container_id, "bookedScope": scope}
    (work / "containment-approved.json").write_text(json.dumps(containment))
    (cached / "containment.json").write_text(json.dumps(containment))
    build = {
        "status": "failed", "exitCode": -15,
        "error": "native Cargo build failed with exit -15; see build.log",
        "nativeTests": "not_run", "releaseQualification": "not_run",
    }
    terminal = {
        "containerId": container_id,
        "state": {"Status": "stopped", "Running": False, "OOMKilled": False,
                   "Pid": 0, "ExitCode": 1},
        "build": dict(build), "unit": "ActiveState=inactive\n",
    }
    (cached / "terminal-state.json").write_text(json.dumps(terminal))
    (cached / "cleanup.json").write_text(json.dumps({
        "command": ["podman", "rm", container_id], "exitCode": 0,
        "stdout": container_id + "\n", "stderr": "",
        "preserved": "all host source/tools/vendor/target/receipts/logs",
    }))
    interruption = {
        "at": "2026-09-10T18:27:02.978202+00:00",
        "reason": "Owner explicitly requests breaking monitoring pattern, public-release focus, stop new work and checkpoint owned build.",
        "action": "SIGTERM to verified owned Cargo process group, leaving pilot alive to write honest terminal receipt",
        "pid": 2680853, "pgid": 2680853, "scope": scope,
        "limitation": "Owner interruption is not a planned timeout or successful build; Preserve R13 verified fallback and all R16 output.",
    }
    interruption_path = tmp_path / "owner-interruption.json"
    interruption_path.write_text(json.dumps(interruption))
    return cached, interruption_path, build, scope


def test_planned_owner_interruption_admits_only_matching_terminal_receipts(tmp_path: Path) -> None:
    cached, interruption_path, build, scope = _interrupted_receipts(tmp_path)
    result = _verify_planned_owner_interruption(cached, build, interruption_path, scope)
    assert result["kind"] == "planned-owner-interruption"
    assert result["buildExitCode"] == -15
    assert result["terminalContainerId"] == "a" * 64


@pytest.mark.parametrize("mutation", [
    "action", "scope", "build-exit", "terminal-oom", "cleanup-id", "missing-terminal",
])
def test_planned_owner_interruption_refuses_unbound_or_unsafe_state(
    tmp_path: Path, mutation: str,
) -> None:
    cached, interruption_path, build, scope = _interrupted_receipts(tmp_path)
    interruption = json.loads(interruption_path.read_text())
    if mutation == "action":
        interruption["action"] = "SIGTERM"
        interruption_path.write_text(json.dumps(interruption))
    elif mutation == "scope":
        interruption["scope"] = scope + "/unrelated"
        interruption_path.write_text(json.dumps(interruption))
    elif mutation == "build-exit":
        build["exitCode"] = -1
    elif mutation == "terminal-oom":
        terminal_path = cached / "terminal-state.json"
        terminal = json.loads(terminal_path.read_text())
        terminal["state"]["OOMKilled"] = True
        terminal_path.write_text(json.dumps(terminal))
    elif mutation == "cleanup-id":
        cleanup_path = cached / "cleanup.json"
        cleanup = json.loads(cleanup_path.read_text())
        cleanup["command"][-1] = "b" * 64
        cleanup_path.write_text(json.dumps(cleanup))
    else:
        (cached / "terminal-state.json").unlink()
    with pytest.raises(VerificationError):
        _verify_planned_owner_interruption(cached, build, interruption_path, scope)


def _receipt_gate_fixture(tmp_path: Path, *, interrupted: bool) -> tuple[Path, dict]:
    cached = tmp_path / "cached"
    work = cached / "work"
    (work / "native").mkdir(parents=True)
    value = recipe()
    source = value["source"]
    (work / "native/source-preparation.json").write_text(json.dumps({
        "recipeSha256": sha256(REPAIR / "recipe.json"),
        "chromiumVendorManifestSha256": value["chromiumVendorManifestSha256"],
        "restoredIcuDataSha256": source["missingIcuData"]["sha256"],
    }))
    build = {
        "status": "failed",
        "error": (
            "native Cargo build failed with exit -15; see build.log"
            if interrupted else "bounded native pilot timed out"
        ),
        "exitCode": -15 if interrupted else None,
        "recipeSha256": sha256(REPAIR / "recipe.json"),
        "fixedV8Commit": source["fixedV8Commit"],
        "fixedV8Version": source["fixedV8Version"],
        "nativeTests": "not_run", "releaseQualification": "not_run",
        "command": ["/work/tools/rust/bin/cargo", "build", "--offline", "--locked",
                    "--release", "--target", value["pilot"]["target"], "--lib"],
    }
    (work / "native-build-receipt.json").write_text(json.dumps(build))
    (work / "containment-approved.json").write_text(json.dumps({"status": "passed"}))
    return cached, value


def test_receipt_gate_refuses_interrupted_build_without_explicit_owner_receipt(tmp_path: Path) -> None:
    cached, value = _receipt_gate_fixture(tmp_path, interrupted=True)
    with pytest.raises(VerificationError, match="planned owner interruption receipt"):
        _verify_receipts(cached, "sha256:" + "a" * 64, value)


def test_receipt_gate_refuses_timeout_with_owner_interruption_receipt(tmp_path: Path) -> None:
    cached, value = _receipt_gate_fixture(tmp_path, interrupted=False)
    owner = tmp_path / "owner-interruption.json"
    owner.write_text("{}")
    with pytest.raises(VerificationError, match="cannot accompany a timeout"):
        _verify_receipts(
            cached, "sha256:" + "a" * 64, value,
            planned_owner_interruption=owner,
        )


def test_cli_preserves_owner_receipt_symlink_for_canonical_refusal(tmp_path: Path, monkeypatch) -> None:
    import verify_cached_work

    cached, inputs, vendor = (tmp_path / name for name in ("cached", "inputs", "vendor"))
    cached.mkdir(); inputs.mkdir(); vendor.mkdir()
    image = tmp_path / "image-id"
    image.write_text("sha256:" + "a" * 64)
    owner = tmp_path / "owner.json"
    owner.write_text("{}")
    link = tmp_path / "owner-link.json"
    link.symlink_to(owner)
    observed: dict[str, Path] = {}

    def fake_verify(*args, **kwargs):
        observed["path"] = kwargs["planned_owner_interruption"]
        return {"status": "cached-work-verified"}

    monkeypatch.setattr(verify_cached_work, "verify", fake_verify)
    monkeypatch.setattr(verify_cached_work, "verify_inputs", lambda _path: None)
    monkeypatch.setattr(sys, "argv", [
        "verify_cached_work.py", "--cached-run", str(cached), "--inputs", str(inputs),
        "--vendor-inputs", str(vendor), "--image-id-file", str(image),
        "--staging", str(tmp_path / "staging"), "--planned-owner-interruption", str(link),
    ])
    assert verify_cached_work.main() == 0
    assert observed["path"].is_symlink()
    with pytest.raises(VerificationError, match="canonical regular file"):
        _verify_planned_owner_interruption(cached, {}, observed["path"], None)


def test_full_verifier_receipt_keeps_interruption_admission_when_mocked(tmp_path: Path, monkeypatch) -> None:
    """The correspondence receipt consumed by later lineage review keeps its cache class."""
    import verify_cached_work
    import booked_pilot

    cached = tmp_path / "cached"
    inputs = tmp_path / "inputs"
    vendor = tmp_path / "vendor"
    cached.mkdir(); inputs.mkdir(); vendor.mkdir()
    image = tmp_path / "image-id"
    image.write_text("sha256:" + "a" * 64)
    admission = {
        "kind": "planned-owner-interruption",
        "receiptSha256": "c" * 64,
        "terminalContainerId": "d" * 64,
        "buildExitCode": -15,
        "qualification": "not_run; continuation remains unqualified",
    }
    monkeypatch.setattr(verify_cached_work, "verify_inputs", lambda _path: None)
    monkeypatch.setattr(
        verify_cached_work, "_verify_outer_command",
        lambda *args, **kwargs: {"timeoutArgument": "--timeout-seconds=4800",
                                 "mounts": [], "governorCgroup": None},
    )
    monkeypatch.setattr(
        verify_cached_work, "_verify_receipts",
        lambda *args, **kwargs: {"recipeSha256": sha256(REPAIR / "recipe.json"),
                                 "builderImage": image.read_text(),
                                 "cachedBuildStatus": "failed",
                                 "cacheAdmission": admission},
    )
    monkeypatch.setattr(booked_pilot, "governor_cgroup_parent", lambda: "/booked/test")

    def fake_observed(_command, output, _parent, _log):
        (output / "work/correspondence-result.json").write_text(json.dumps({
            "status": "cached-work-verified",
            "trees": {"native": {}, "tools": {}, "vendor": {}},
        }))
        return 0

    monkeypatch.setattr(booked_pilot, "observed_native", fake_observed)
    result = verify_cached_work.verify(cached, inputs, vendor, image, tmp_path / "staging")
    assert result["cacheAdmission"] == admission


@pytest.mark.parametrize("mutation", [
    None, "receipt-binding", "receipt-bytes", "command-admission", "admission-extra",
    "pilot-identity", "runner-identity", "receipt-symlink", "admission-symlink",
    "cache-symlink", "extra-mount", "privileged", "timeout", "non-string-argv",
    "receipt-not-object", "admission-not-object",
])
def test_outer_command_checks_exact_resumed_pilot_shape(tmp_path: Path, mutation: str | None) -> None:
    image = "sha256:" + "d" * 64
    inputs, vendor, work, prior = (tmp_path / name for name in ("inputs", "vendor", "work", "prior"))
    inputs.mkdir(); vendor.mkdir(); work.mkdir(); (prior / "work").mkdir(parents=True)
    receipt = tmp_path / "correspondence.json"
    receipt.write_text("{}\n")
    admission = {
        "schemaVersion": 1,
        "receiptSha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        "bindings": {"status": "cached-work-verified", "cachedRun": str(prior),
                      "inputs": str(inputs), "vendorInputs": str(vendor),
                      "verifierSha256": "e" * 64,
                      "recipeSha256": hashlib.sha256((REPAIR / "recipe.json").read_bytes()).hexdigest(),
                      "builderImage": image},
    }
    receipt.write_text(json.dumps(admission["bindings"]) + "\n")
    admission["receiptSha256"] = hashlib.sha256(receipt.read_bytes()).hexdigest()
    (tmp_path / "resume-admission.json").write_text(json.dumps(admission))
    command = _valid_outer_command(image)[:-3]
    command[command.index("/home/operator/container-id")] = str(tmp_path / "container-id")
    command += [
        "--mount", f"type=bind,src={prior},dst=/cached-run,ro",
        "--mount", f"type=bind,src={receipt},dst=/correspondence-receipt.json,ro",
        "--mount", f"type=bind,src={tmp_path / 'resume-admission.json'},dst=/resume-admission.json,ro",
        "--mount", f"type=bind,src={Path(__file__).resolve().parents[1] / 'config/codex-runtime/v8-repair/pilot.py'},dst=/opt/stateport-v8-repair/pilot.py,ro",
        "--mount", f"type=bind,src={Path(__file__).resolve().parents[1] / 'config/codex-runtime/v8-repair/verify_cached_work.py'},dst=/opt/stateport-v8-repair/verify_cached_work.py,ro",
        image, "--timeout-seconds=4800", "--require-containment", "--resume-admission", "/resume-admission.json",
    ]
    # Rebuild the three reviewed mounts with their actual paths and active work root.
    command[command.index("type=bind,src=/immutable/inputs,dst=/inputs,ro")] = f"type=bind,src={inputs},dst=/inputs,ro"
    command[command.index("type=bind,src=/immutable/vendor,dst=/vendor-inputs,ro")] = f"type=bind,src={vendor},dst=/vendor-inputs,ro"
    command[command.index("type=bind,src=/cached/work,dst=/work,rw")] = f"type=bind,src={work},dst=/work,rw"
    (tmp_path / "container-id").write_text("")
    command_receipt = {"command": command, "resumeAdmission": admission,
        "pilotSha256": hashlib.sha256((REPAIR / "pilot.py").read_bytes()).hexdigest(),
        "runnerSha256": hashlib.sha256((REPAIR / "booked_pilot.py").read_bytes()).hexdigest()}
    (tmp_path / "command.json").write_text(json.dumps(command_receipt))
    assert _verify_outer_command(tmp_path, image, inputs, vendor)["mounts"] == [
        "/cached-run", "/correspondence-receipt.json", "/inputs", "/opt/stateport-v8-repair/pilot.py",
        "/opt/stateport-v8-repair/verify_cached_work.py", "/resume-admission.json", "/vendor-inputs", "/work"]

    if mutation is None:
        # A reviewed old runner is explicit data, never the executable used
        # for this verification. Drift still refuses without that exact file.
        historical = tmp_path / 'historical-booked-pilot.py'
        historical.write_text('# retained historical runner source\n')
        command_receipt['runnerSha256'] = hashlib.sha256(historical.read_bytes()).hexdigest()
        (tmp_path / 'command.json').write_text(json.dumps(command_receipt))
        with pytest.raises(VerificationError):
            _verify_outer_command(tmp_path, image, inputs, vendor)
        assert _verify_outer_command(tmp_path, image, inputs, vendor,
                                     historical_runner=historical)['timeoutArgument'] == '--timeout-seconds=4800'
        historical.write_text('# altered bytes\n')
        with pytest.raises(VerificationError):
            _verify_outer_command(tmp_path, image, inputs, vendor, historical_runner=historical)
        return
    admission_path = tmp_path / "resume-admission.json"
    if mutation == "receipt-binding":
        content = dict(admission["bindings"], builderImage="sha256:" + "f" * 64)
        receipt.write_text(json.dumps(content))
        admission["receiptSha256"] = hashlib.sha256(receipt.read_bytes()).hexdigest()
        admission_path.write_text(json.dumps(admission))
    elif mutation == "receipt-bytes":
        receipt.write_text(receipt.read_text() + " ")
    elif mutation == "command-admission":
        command_receipt["resumeAdmission"] = None
    elif mutation == "admission-extra":
        admission["extra"] = True
        admission_path.write_text(json.dumps(admission))
    elif mutation in {"pilot-identity", "runner-identity"}:
        command_receipt[mutation.split("-")[0] + "Sha256"] = "f" * 64
    elif mutation in {"receipt-symlink", "admission-symlink"}:
        source = receipt if mutation == "receipt-symlink" else admission_path
        moved = source.with_suffix(".saved")
        source.rename(moved)
        source.symlink_to(moved)
    elif mutation == "cache-symlink":
        moved = prior.with_name("moved-prior")
        prior.rename(moved)
        prior.symlink_to(moved, target_is_directory=True)
    elif mutation == "extra-mount":
        command[command.index(image):command.index(image)] = [
            "--mount", f"type=bind,src={tmp_path},dst=/unexpected,ro"]
    elif mutation == "privileged":
        command.insert(5, "--privileged")
    elif mutation == "timeout":
        command[command.index("--timeout-seconds=4800")] = "--timeout-seconds=invalid"
    elif mutation == "non-string-argv":
        command.append({"unexpected": True})
    elif mutation == "receipt-not-object":
        receipt.write_text("[]")
        admission["receiptSha256"] = hashlib.sha256(receipt.read_bytes()).hexdigest()
        admission_path.write_text(json.dumps(admission))
    elif mutation == "admission-not-object":
        admission_path.write_text("[]")
    (tmp_path / "command.json").write_text(json.dumps(command_receipt))
    with pytest.raises(VerificationError):
        _verify_outer_command(tmp_path, image, inputs, vendor)


def test_verifier_import_preserves_original_builder_pilot_api(tmp_path: Path) -> None:
    # The pinned builder predates host resume-admission helpers. It mounts this
    # verifier alone and must still be able to run inner source reconstruction.
    program = """
import importlib.util, sys, types
from pathlib import Path
pilot = types.ModuleType('pilot')
pilot.HERE = Path(sys.argv[1]).parent
pilot.unpack = lambda *args: None
pilot.vendor = lambda *args: None
sys.modules['pilot'] = pilot
spec = importlib.util.spec_from_file_location('isolated_verifier', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert callable(module.compare_tree)
"""
    completed = subprocess.run(
        [sys.executable, "-c", program, str(REPAIR / "verify_cached_work.py")],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(REPAIR)},
        capture_output=True, text=True, timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
