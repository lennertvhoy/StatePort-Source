"""Fixture-only live identity checks for managed-workload controls; no Podman."""
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packages/execution-host/src'))
from execution_host.daemon import ExecutionHostDaemon, _Refusal
from execution_host.engine import MANAGED_LABEL_KEY, WORKLOAD_LABEL, KIND_LABEL


class FixtureEngine:
    identity = {'engine': 'fixture'}
    def __init__(self):
        self.calls = []
        self.workspace_data = b'recognizable user workspace data'
        self.info = {'present': True, 'running': False, 'labels': {
            MANAGED_LABEL_KEY: 'true', WORKLOAD_LABEL: 'default-dev', KIND_LABEL: 'workspace'},
            'imageDigest': 'sha256:' + 'a' * 64}
        self.leave_container = False
    def inspect(self, workload_id):
        return dict(self.info)
    def start(self, workload_id, **kwargs):
        self.calls.append('start'); self.info['running'] = True
    def stop(self, workload_id, **kwargs):
        self.calls.append('stop'); self.info['running'] = False
    def remove(self, workload_id, **kwargs):
        self.calls.append('remove')
        if not self.leave_container:
            self.info['present'] = False


class FixtureDaemon(ExecutionHostDaemon):
    def __init__(self, state='stopped'):
        self._engine = FixtureEngine()
        self.entry = {'workloadId': 'default-dev', 'state': state, 'version': 1,
            'spec': {'kind': 'workspace', 'image': {'reference': 'example@sha256:' + 'a' * 64}}}
        self._ledger = SimpleNamespace(get=lambda _: self.entry)
        self._config = SimpleNamespace(clock=lambda: '2026-09-05T00:00:00Z')
        self.sessions_closed = 0
    def _close_sessions_for(self, workload_id):
        self.sessions_closed += 1
    def _assert_activation_authority(self, entry, grant):
        pass
    def _touch_activity(self, workload_id):
        pass
    def _observed_for(self, workload_id):
        return {}
    def _residual_evidence(self, workload_id):
        return {'containerPresent': self._engine.info['present']}
    def _transition_snapshot(self, ledger, entry, state, **kwargs):
        self.entry['state'] = state
        self.entry['version'] += 1
        return self.entry


def call(daemon, action):
    return getattr(daemon, '_op_' + action)({'timeoutSeconds': 2}, {'workloadId': 'default-dev'}, {})


@pytest.mark.parametrize('action,state', [('start', 'created'), ('stop', 'running'), ('cancel', 'running'), ('remove', 'stopped')])
@pytest.mark.parametrize('mismatch', ['managed', 'workload', 'kind', 'image', 'unknown'])
def test_controls_refuse_foreign_replacement_before_any_effect(action, state, mismatch):
    daemon = FixtureDaemon(state)
    info = daemon._engine.info
    if mismatch == 'managed': info['labels'][MANAGED_LABEL_KEY] = 'false'
    elif mismatch == 'workload': info['labels'][WORKLOAD_LABEL] = 'foreign-work'
    elif mismatch == 'kind': info['labels'][KIND_LABEL] = 'job'
    elif mismatch == 'image': info['imageDigest'] = 'sha256:' + 'b' * 64
    else: info['present'] = None
    with pytest.raises(_Refusal):
        call(daemon, action)
    assert daemon._engine.calls == []
    assert daemon.sessions_closed == 0
    assert daemon.entry['state'] == state
    assert daemon._engine.workspace_data == b'recognizable user workspace data'


def test_remove_preserves_workspace_data_and_confirms_absence():
    daemon = FixtureDaemon()
    result = call(daemon, 'remove')
    assert result[0]['state'] == 'removed'
    assert daemon._engine.info['present'] is False
    assert daemon._engine.workspace_data == b'recognizable user workspace data'
    assert 'volume is preserved' in result[2]['detail']


def test_remove_never_claims_removed_when_engine_retains_container():
    daemon = FixtureDaemon()
    daemon._engine.leave_container = True
    with pytest.raises(_Refusal):
        call(daemon, 'remove')
    assert daemon.entry['state'] == 'cleanup_failed'
    assert daemon._engine.info['present'] is True


def test_missing_container_start_fails_without_an_engine_effect():
    daemon = FixtureDaemon('created')
    daemon._engine.info['present'] = False
    with pytest.raises(_Refusal):
        call(daemon, 'start')
    assert daemon._engine.calls == []


def test_foreign_replacement_logs_are_refused_before_engine_read():
    daemon = FixtureDaemon()
    daemon._engine.info['labels'][WORKLOAD_LABEL] = 'foreign-work'
    def forbidden_logs(*args, **kwargs):
        raise AssertionError('foreign resource logs must never be read')
    daemon._engine.logs = forbidden_logs
    with pytest.raises(_Refusal, match='workload label'):
        daemon._op_logs({'outputByteBound': 100}, {'workloadId': 'default-dev'}, {})


@pytest.mark.parametrize('action,state,expected', [('start', 'created', 'running'), ('stop', 'running', 'stopped'), ('cancel', 'running', 'cancelled')])
def test_owned_workload_controls_keep_existing_lifecycle(action, state, expected):
    daemon = FixtureDaemon(state)
    result = call(daemon, action)
    assert result[0]['state'] == expected
    assert daemon.entry['state'] == expected
    assert daemon._engine.workspace_data == b'recognizable user workspace data'
