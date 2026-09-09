"""Sealed source command lowering; no container/installed claims."""
from pathlib import Path
import sys
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packages/execution-host/src'))
sys.path.insert(0, str(ROOT / 'packages/runtime-contracts/src'))
from execution_host.engine import (  # noqa: E402
    EngineError, PodmanCliEngine, build_create_argv,
    assert_agent_source_argv_hardened,
)
from runtime_contracts import canonical_digest  # noqa: E402

IMAGE = 'example.test/agent@sha256:' + 'a' * 64


def source_spec(command=None):
    command = command or ['/usr/bin/codex', '--model', 'model-name', '--', 'host']
    return {
        'kind': 'agent-run', 'workloadId': 'agent-source',
        'image': {'reference': IMAGE},
        'parameters': {
            'workSeconds': 0, 'emitBytes': 0,
            'runSpecDigest': 'sha256:' + 'b' * 64,
            'statePackReference': 'statepack.demo',
            'command': command, 'commandDigest': canonical_digest(command),
            'sourceSnapshotPath': '/private/validator-snapshots/op/context',
            'sourceInventory': [], 'sourceArchive': {},
        },
        'resources': {'memoryMaxBytes': 268435456, 'cpuQuotaPercent': 100,
                      'pidsMax': 128, 'diskMaxBytes': 67108864},
        'timeoutSeconds': 30, 'outputByteBound': 4096,
    }


def test_agent_source_argv_preserves_payload_and_all_bounds():
    spec = source_spec()
    argv = build_create_argv(spec)
    assert PodmanCliEngine.agent_source_commands_supported
    assert argv[argv.index(IMAGE) + 4:] == spec['parameters']['command']
    assert argv[argv.index('--tmpfs') + 1] == '/tmp:rw,noexec,nosuid,nodev,size=67108864'
    assert argv[argv.index('--network') + 1] == 'none'
    assert argv[argv.index('--mount') + 1] == 'type=bind,src=/private/validator-snapshots/op/context,dst=/agent-input,readonly,relabel=private'
    assert '--volume' not in argv
    script = argv[argv.index(IMAGE) + 2]
    assert 'chmod -R u+rwX /tmp/workspace' in script
    assert 'chmod -R u+rwX /agent-input' not in script
    assert 'exec "$@"' in script
    assert not any('SOURCESNAPSHOTPATH=' in item for item in argv)


@pytest.mark.parametrize('path', ['/private/../outside', '/private//context', '/private/context/', '/private/context,ro=false', 'relative', '/', '/private\\context', '/private\x00context'])
def test_agent_source_refuses_unsafe_runtime_paths(path):
    spec = source_spec()
    spec['parameters']['sourceSnapshotPath'] = path
    with pytest.raises(EngineError, match='snapshot'):
        build_create_argv(spec)


def test_agent_source_refuses_changed_command_digest():
    spec = source_spec()
    spec['parameters']['command'].append('changed')
    with pytest.raises(EngineError, match='digest'):
        build_create_argv(spec)


@pytest.mark.parametrize('flag', ['--privileged', '--device', '--userns', '--network=host'])
def test_agent_source_refuses_runtime_override_but_preserves_payload(flag):
    spec = source_spec(['/usr/bin/codex', flag])
    argv = build_create_argv(spec)
    assert argv[-1] == flag
    argv[1:1] = [flag]
    with pytest.raises(EngineError):
        assert_agent_source_argv_hardened(argv, source=spec['parameters']['sourceSnapshotPath'])


def test_agent_source_refuses_writable_mount_and_network():
    spec = source_spec()
    argv = build_create_argv(spec)
    argv[argv.index('--mount') + 1] = argv[argv.index('--mount') + 1].replace('readonly', 'rw')
    with pytest.raises(EngineError, match='source mount'):
        assert_agent_source_argv_hardened(argv, source=spec['parameters']['sourceSnapshotPath'])
    argv = build_create_argv(spec)
    argv[argv.index('--network') + 1] = 'host'
    with pytest.raises(EngineError):
        assert_agent_source_argv_hardened(argv, source=spec['parameters']['sourceSnapshotPath'])


@pytest.mark.parametrize('replacement', ['/tmp:rw,size=67108864', '/workspace:rw,noexec,nosuid,nodev,size=67108864', '/tmp:rw,noexec,nosuid,nodev,size=0'])
def test_agent_source_refuses_weakened_candidate_filesystem(replacement):
    spec = source_spec()
    argv = build_create_argv(spec)
    argv[argv.index('--tmpfs') + 1] = replacement
    with pytest.raises(EngineError, match='candidate filesystem'):
        assert_agent_source_argv_hardened(argv, source=spec['parameters']['sourceSnapshotPath'])


def test_validator_payload_options_are_not_engine_options():
    spec = source_spec(['/usr/bin/python3', '--version'])
    spec['kind'] = 'validator-run'
    spec['parameters']['stagingPath'] = '/private/validator/context'
    argv = build_create_argv(spec)
    assert argv[-1] == '--version'
    assert argv[argv.index('--entrypoint') + 1] == '/usr/bin/python3'


def test_fixed_supervisor_copies_writable_candidate_and_merges_child_stderr(tmp_path):
    # Exercise the production shell text on owned paths. Container isolation
    # remains covered separately by the governor-managed daemon journey.
    source = tmp_path / "source"
    source.mkdir()
    original = source / "input.txt"
    original.write_text("original")
    original.chmod(0o444)
    candidate = tmp_path / "candidate"
    command = [sys.executable, "-c", "from pathlib import Path; import sys; Path('input.txt').write_text('changed'); print('child-stderr-canary', file=sys.stderr); sys.exit(7)"]
    argv = build_create_argv(source_spec(command))
    payload = argv[argv.index(IMAGE) + 1:]
    payload[1] = payload[1].replace('/agent-input', shlex.quote(str(source))).replace('/tmp/workspace', shlex.quote(str(candidate)))
    completed = subprocess.run(['/bin/sh', *payload], capture_output=True, text=True, timeout=5)
    assert completed.returncode == 7
    assert completed.stdout == 'child-stderr-canary\n'
    assert completed.stderr == ''
    assert original.read_text() == 'original'
    assert original.stat().st_mode & 0o777 == 0o444
    assert (candidate / 'input.txt').read_text() == 'changed'
