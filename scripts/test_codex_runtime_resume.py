"""Contract tests for the governed native resume admission.

They specify the pre-build boundary: no target cache
may be copied unless the fresh correspondence receipt binds the exact old run,
input roots, verifier, recipe and builder image.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPAIR = ROOT / "config" / "codex-runtime" / "v8-repair"
sys.path.insert(0, str(REPAIR))

import pilot  # noqa: E402
from pilot import (  # noqa: E402
    compare_and_preserve_cache_times,
    import_target_cache,
    validate_inner_resume,
    validate_resume_admission,
)


def receipt(tmp_path: Path, **overrides: str) -> Path:
    values = {
        "status": "cached-work-verified",
        "cachedRun": str(tmp_path / "old-native-r2"),
        "inputs": str(tmp_path / "inputs"),
        "vendorInputs": str(tmp_path / "vendor-inputs"),
        "verifierSha256": "a" * 64,
        "recipeSha256": "b" * 64,
        "builderImage": "sha256:" + "c" * 64,
    }
    values.update(overrides)
    path = tmp_path / "correspondence-r1.json"
    path.write_text(json.dumps(values))
    return path


def roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    old = tmp_path / "old-native-r2"
    inputs = tmp_path / "inputs"
    vendor = tmp_path / "vendor-inputs"
    (old / "work").mkdir(parents=True)
    inputs.mkdir()
    vendor.mkdir()
    return old, inputs, vendor


def test_resume_refuses_absent_receipt_before_target_copy(tmp_path: Path) -> None:
    old, inputs, vendor = roots(tmp_path)
    with pytest.raises(ValueError, match="correspondence"):
        validate_resume_admission(tmp_path / "missing.json", old, inputs, vendor,
                                  "a" * 64, "b" * 64, "sha256:" + "c" * 64)


@pytest.mark.parametrize("field, value", [
    ("cachedRun", "other-run"),
    ("inputs", "other-inputs"),
    ("vendorInputs", "other-vendor"),
    ("verifierSha256", "d" * 64),
    ("recipeSha256", "e" * 64),
    ("builderImage", "sha256:" + "f" * 64),
])
def test_resume_refuses_identity_or_path_mismatch(
    tmp_path: Path, field: str, value: str
) -> None:
    old, inputs, vendor = roots(tmp_path)
    path = receipt(tmp_path, **{field: value})
    with pytest.raises(ValueError, match="identity|path|correspondence"):
        validate_resume_admission(path, old, inputs, vendor,
                                  "a" * 64, "b" * 64, "sha256:" + "c" * 64)


def test_resume_refuses_non_directory_or_symlink_cached_run(tmp_path: Path) -> None:
    old, inputs, vendor = roots(tmp_path)
    (old / "work").rmdir()
    path = receipt(tmp_path)
    with pytest.raises(ValueError, match="cached|directory|symlink"):
        validate_resume_admission(path, old, inputs, vendor,
                                  "a" * 64, "b" * 64, "sha256:" + "c" * 64)


def test_resume_accepts_exact_external_receipt_without_modifying_old_run(tmp_path: Path) -> None:
    old, inputs, vendor = roots(tmp_path)
    path = receipt(tmp_path)
    observed = validate_resume_admission(path, old, inputs, vendor,
                                        'a' * 64, 'b' * 64, 'sha256:' + 'c' * 64)
    assert observed['receiptSha256'] == pilot.sha256(path)
    assert observed['bindings']['cachedRun'] == str(old)
    assert list((old / 'work').iterdir()) == []


@pytest.mark.parametrize('field', ['receipt', 'cached', 'parent'])
def test_resume_refuses_symlink_admission_paths(tmp_path: Path, field: str) -> None:
    old, inputs, vendor = roots(tmp_path)
    path = receipt(tmp_path)
    link = tmp_path / 'link'
    if field == 'receipt':
        link.symlink_to(path)
        path = link
    elif field == 'cached':
        link.symlink_to(old, target_is_directory=True)
        old = link
    else:
        link.symlink_to(tmp_path, target_is_directory=True)
        old = link / old.name
    with pytest.raises(ValueError):
        validate_resume_admission(path, old, inputs, vendor,
                                  'a' * 64, 'b' * 64, 'sha256:' + 'c' * 64)


def test_inner_refuses_changed_receipt_or_verifier(tmp_path: Path, monkeypatch) -> None:
    old, inputs, vendor = roots(tmp_path)
    recipe = tmp_path / 'recipe.json'
    verifier = tmp_path / 'verify_cached_work.py'
    recipe.write_text('{}')
    verifier.write_text('reviewed verifier')
    path = receipt(tmp_path, verifierSha256=pilot.sha256(verifier), recipeSha256=pilot.sha256(recipe))
    context = validate_resume_admission(path, old, inputs, vendor,
        pilot.sha256(verifier), pilot.sha256(recipe), 'sha256:' + 'c' * 64)
    admission = tmp_path / 'admission.json'
    admission.write_text(json.dumps(context))
    monkeypatch.setattr(pilot, 'HERE', tmp_path)
    assert validate_inner_resume(admission, path) == context
    verifier.write_text('changed verifier')
    with pytest.raises(ValueError, match='identity'):
        validate_inner_resume(admission, path)
    verifier.write_text('reviewed verifier')
    path.write_text(path.read_text() + ' ')
    with pytest.raises(ValueError, match='changed'):
        validate_inner_resume(admission, path)


@pytest.mark.parametrize('kind', ['file-link', 'directory-link', 'fifo'])
def test_target_cache_refuses_links_and_special_files_before_copy(tmp_path: Path, kind: str) -> None:
    source = tmp_path / 'cache'
    source.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'secret').write_text('must not import')
    if kind == 'fifo':
        os.mkfifo(source / 'unsafe')
    else:
        (source / 'unsafe').symlink_to(outside if kind == 'directory-link' else outside / 'secret')
    with pytest.raises(ValueError, match='symlink|special'):
        import_target_cache(source, tmp_path / 'new-target')
    assert not (tmp_path / 'new-target').exists()


def test_target_copy_preserves_bytes_modes_mtime_not_other_work(tmp_path: Path) -> None:
    source = tmp_path / 'old/target'
    source.mkdir(parents=True)
    (source.parent / 'cargo').mkdir()
    artifact = source / 'build-script'
    artifact.write_bytes(b'unqualified cache')
    artifact.chmod(0o755)
    os.utime(artifact, ns=(100000000000, 200000000000))
    destination = tmp_path / 'new/target'
    result = import_target_cache(source, destination)
    assert result['files'] == 1
    assert result['qualification'].startswith('unqualified')
    assert (destination / artifact.name).read_bytes() == artifact.read_bytes()
    assert (destination / artifact.name).stat().st_mtime_ns == artifact.stat().st_mtime_ns
    assert (destination / artifact.name).stat().st_mode == artifact.stat().st_mode
    assert not (destination.parent / 'cargo').exists()


def test_source_times_preserved_only_after_complete_correspondence(tmp_path: Path) -> None:
    fresh, cached = tmp_path / 'fresh', tmp_path / 'cached'
    fresh.mkdir(); cached.mkdir()
    for name in ('a', 'z'):
        (fresh / name).write_text(name)
        (cached / name).write_text(name)
        os.utime(cached / name, ns=(100000000000, 200000000000))
    fresh_time = (fresh / 'a').stat().st_mtime_ns
    (cached / 'z').write_text('changed')
    with pytest.raises(ValueError, match='differs'):
        compare_and_preserve_cache_times(fresh, cached, 'fixture')
    assert (fresh / 'a').stat().st_mtime_ns == fresh_time
    (cached / 'z').write_text('z')
    proof = compare_and_preserve_cache_times(fresh, cached, 'fixture')
    assert proof['files'] == 2
    assert (fresh / 'a').stat().st_mtime_ns == (cached / 'a').stat().st_mtime_ns


def test_booked_resume_mounts_external_receipt_and_reviewed_code_read_only(tmp_path: Path, monkeypatch) -> None:
    import booked_pilot
    old, inputs, vendor = roots(tmp_path)
    (old / 'work/target').mkdir()
    path = receipt(tmp_path, verifierSha256=pilot.sha256(REPAIR / 'verify_cached_work.py'),
                   recipeSha256=pilot.sha256(REPAIR / 'recipe.json'))
    image = tmp_path / 'image-id'
    image.write_text('sha256:' + 'c' * 64)
    output = tmp_path / 'new-native'
    monkeypatch.setattr(booked_pilot, 'governor_cgroup_parent', lambda: '/booked/test')
    observed = []
    monkeypatch.setattr(booked_pilot, 'observed_native', lambda command, *_: observed.append(command) or 0)
    monkeypatch.setattr(sys, 'argv', ['booked_pilot.py', 'native', '--output', str(output),
        '--inputs', str(inputs), '--vendor-inputs', str(vendor), '--image-id-file', str(image),
        '--resume-run', str(old), '--correspondence-receipt', str(path), '--timeout-seconds', '4800'])
    assert booked_pilot.main() == 0
    command = observed[0]
    mounts = [command[i + 1] for i, part in enumerate(command) if part == '--mount']
    assert f'type=bind,src={old},dst=/cached-run,ro' in mounts
    assert f'type=bind,src={path},dst=/correspondence-receipt.json,ro' in mounts
    assert f'type=bind,src={REPAIR / "pilot.py"},dst=/opt/stateport-v8-repair/pilot.py,ro' in mounts
    assert sum(mount.endswith(',rw') for mount in mounts) == 1
    assert command[-2:] == ['--resume-admission', '/resume-admission.json']
    assert '--network=none' in command and '--require-containment' in command
    context = json.loads((output / 'resume-admission.json').read_text())
    assert context['receiptSha256'] == pilot.sha256(path)
    assert not (old / 'work/correspondence-result.json').exists()


def test_delegation_moves_only_owned_direct_tasks_and_preserves_limits(tmp_path: Path, monkeypatch) -> None:
    import booked_pilot
    parent = "/user.slice/user-1000.slice/user@1000.service/stateport.slice/stateport-heavy.slice/stateport-heavy-1-2.service"
    cgroups = tmp_path / 'cgroups'
    directory = cgroups / parent.lstrip('/')
    directory.mkdir(parents=True)
    proc = tmp_path / 'proc'
    for pid in ('self', '11', '12'):
        (proc / pid).mkdir(parents=True)
        (proc / pid / 'cgroup').write_text('0::' + parent + '\n')
    values = {'cgroup.controllers': 'cpu io memory pids', 'cgroup.subtree_control': '',
              'cgroup.procs': '11\n12\n', 'memory.max': '3221225472',
              'memory.high': '2684354560', 'memory.swap.max': '1073741824',
              'cpu.max': '70000 100000', 'pids.max': '4096'}
    for name, value in values.items():
        (directory / name).write_text(value)
    output = tmp_path / 'proof'
    output.mkdir()
    real_write = Path.write_text
    moves = []
    def write(path, value, *args, **kwargs):
        if path == directory / 'runtime/cgroup.procs':
            moves.append(value)
            remaining = [pid for pid in (directory / 'cgroup.procs').read_text().split() if pid != value]
            real_write(directory / 'cgroup.procs', '\n'.join(remaining))
            real_write(proc / value / 'cgroup', '0::' + parent + '/runtime\n')
        elif path == directory / 'cgroup.subtree_control':
            assert not (directory / 'cgroup.procs').read_text().strip()
            value = value.replace('+', '')
        return real_write(path, value, *args, **kwargs)
    monkeypatch.setattr(Path, 'write_text', write)
    booked_pilot.prepare_delegation(parent, output, proc=proc, cgroups=cgroups)
    assert moves == ['11', '12']
    result = json.loads((output / 'delegation.json').read_text())
    assert result['enabledAfter'] == ['cpu', 'io', 'memory', 'pids']
    for name in ('memory.max', 'memory.high', 'memory.swap.max', 'cpu.max', 'pids.max'):
        assert (directory / name).read_text() == values[name]


def test_delegation_failure_prevents_container_launch(tmp_path: Path, monkeypatch) -> None:
    import booked_pilot
    def refuse(*args, **kwargs):
        raise ValueError('missing controller')
    monkeypatch.setattr(booked_pilot, 'prepare_delegation', refuse)
    monkeypatch.setattr(booked_pilot.subprocess, 'Popen', lambda *a, **k: pytest.fail('launched without delegation'))
    assert booked_pilot.observed_native(['podman', 'run'], tmp_path, '/not-admitted', None) == 1
    result = json.loads((tmp_path / 'containment-failure.json').read_text())
    assert 'before launch' in result['nativeCompilation']
