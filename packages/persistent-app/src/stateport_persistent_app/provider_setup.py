"""Nonsecret provider selection; enabled Codex authentication stays CLI-owned.

Official contract checked 2026-09-05: https://learn.chatgpt.com/docs/auth
and https://learn.chatgpt.com/docs/developer-commands?surface=cli .
Login status observes credential presence, never remote freshness or quota.
"""
from __future__ import annotations

import hashlib
import os
import re
import select
import shutil
import signal
from pathlib import Path
import subprocess
import threading
import time
from uuid import uuid4

from codex_adapter import CodexAdapter
from external_engine_runtime import ProcessSpec, TemporaryWorkspace, filtered_environment, run_process
from .provider_router import ProviderRouter, ProviderRouterError, PROVIDERS, OPENCODE_REFUSAL

# Device-login observation is a narrow extraction from an untrusted stream:
# only the verification URL and the one-time user code are retained; every
# other byte is discarded and can never enter responses, logs or state.
_VERIFICATION_URL_PATTERN = re.compile(r"https://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{4,512}")
_USER_CODE_PATTERN = re.compile(r"\b([A-Z0-9]{4,8}-[A-Z0-9]{4,8})\b")
_LOGIN_OUTPUT_BOUND_BYTES = 16384
_LOGIN_TERMINAL_PHASES = frozenset({'authenticated', 'failed', 'expired', 'cancelled'})


class ProviderLoginError(ProviderRouterError):
    """A fixed-code device-login refusal; the detail is generic, never CLI output."""

    def __init__(self, code: str, detail: str):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _terminate_login_process(process: subprocess.Popen) -> None:
    """Terminate the login process group with a bounded hard-kill fallback."""
    try:
        if os.name == 'posix':
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=1.0)
        if os.name == 'posix':
            # Re-signal the group after the leader is reaped so no late
            # descendant can keep inherited stdout open.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    except subprocess.TimeoutExpired:
        try:
            if os.name == 'posix':
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=1.0)
        except Exception:  # noqa: BLE001 - cleanup is bounded and never reported as output
            pass
    except (ProcessLookupError, OSError):
        pass


def _reap_login_process(process: subprocess.Popen) -> int | None:
    """Reap the login leader without keeping the caller blocked on descendants."""
    if process.poll() is None:
        try:
            return process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            _terminate_login_process(process)
    return process.poll()


class ProviderSetup:
    def __init__(self, config_root: Path, state_root: Path, *, adapter_factory=CodexAdapter,
                 login_code_wait_seconds: float = 60.0, login_flow_timeout_seconds: float = 900.0):
        self.profile_path = config_root / 'provider-router.json'
        self.disabled_path = self.profile_path.with_suffix('.disabled')
        self.staging_root = state_root / 'provider-verification'
        self.adapter_factory = adapter_factory
        self.login_code_wait_seconds = float(login_code_wait_seconds)
        self.login_flow_timeout_seconds = float(login_flow_timeout_seconds)
        if self.login_code_wait_seconds <= 0 or self.login_flow_timeout_seconds <= 0:
            raise ValueError('login bounds must be positive')
        self.observed_adapter = None
        self.observed_provider = None
        self.observed_identity = None
        self.lock = threading.RLock()
        # The login-state guard is separate from the status lock: a sign-in
        # flow must never hold the status lock for its whole duration.
        self.login_lock = threading.RLock()
        self.login_state = {
            'active': False, 'phase': 'cancelled', 'verificationUrl': None, 'userCode': None,
            'detail': 'No provider sign-in has been started in this runtime.',
            'cancel_requested': False, 'process': None}
        self.authentication = 'unverified'
        self.request = 'unverified'
        self.detail = 'Select a model, authenticate using Codex in this runtime, then verify.'

    def selected_provider(self):
        if not os.path.lexists(self.profile_path):
            return 'codex'
        return ProviderRouter.read_profile(self.profile_path)['provider']['backendId']

    def startup_allowed(self):
        if os.path.lexists(self.disabled_path):
            return False
        try:
            return self.selected_provider() == 'codex'
        except ProviderRouterError:
            return False

    def _observation_identity(self, provider_id):
        if provider_id == 'codex':
            factory = self.adapter_factory
        else:
            from opencode_adapter import OpenCodeAdapter
            factory = OpenCodeAdapter
        executable = shutil.which(provider_id)
        try:
            metadata = os.stat(executable) if executable else None
        except OSError:
            metadata = None
        return (provider_id, factory, os.environ.get('PATH'), executable,
                (metadata.st_dev, metadata.st_ino, metadata.st_size,
                 metadata.st_mtime_ns, metadata.st_ctime_ns) if metadata else None)

    def _invalidate_observation(self):
        self.observed_adapter = None
        self.observed_provider = None
        self.observed_identity = None
        self.authentication = self.request = 'unverified'
        self.detail = 'Provider runtime changed. Verify authentication and a bounded request again.'

    def probe(self, provider_id):
        # Only explicit configure/verify invokes a CLI probe. Stat/PATH/factory
        # changes invalidate prior success without executing anything on GET.
        self._invalidate_observation()
        identity = self._observation_identity(provider_id)
        if provider_id == 'codex':
            adapter = self.adapter_factory()
        else:
            from opencode_adapter import OpenCodeAdapter
            adapter = OpenCodeAdapter()
        if identity == self._observation_identity(provider_id):
            self.observed_adapter = adapter
            self.observed_provider = provider_id
            self.observed_identity = identity
        return adapter

    def status(self):
        with self.lock:
            model = None
            configured = False
            provider_id = 'codex'
            try:
                profile = ProviderRouter.read_profile(self.profile_path)
                model = profile['model']['id']
                provider_id = profile['provider']['backendId']
                configured = True
            except ProviderRouterError:
                pass
            if self.observed_adapter is not None and (not configured or self.observed_identity != self._observation_identity(provider_id)):
                self._invalidate_observation()
            adapter = self.observed_adapter if self.observed_provider == provider_id else None
            installed = bool(adapter and adapter.probe.installed)
            observed = adapter is not None
            blocked = provider_id == 'opencode'
            detail = ("OpenCode selection is saved, but execution is refused: isolated post-agent validation is not implemented. No Codex fallback is enabled."
                      if blocked else self.detail)
            return dict(configured=configured, executableInstalled=installed,
                        executableStatus=('installed' if installed else 'missing') if observed else 'unverified',
                        providerId=provider_id, executionRefusal=OPENCODE_REFUSAL if blocked else None,
                        connected=configured and not blocked and not os.path.lexists(self.disabled_path), model=model,
                        authenticationStatus='unavailable' if blocked or (observed and not installed) else self.authentication,
                        requestStatus=self.request, telemetryStatus='unavailable', detail=detail)

    def configure(self, model, provider_id=None):
        with self.lock:
            provider_id = self.selected_provider() if provider_id is None else provider_id
            if not isinstance(model, str) or not isinstance(provider_id, str) or provider_id not in PROVIDERS:
                raise ProviderRouterError('provider configuration is invalid')
            ProviderRouter.configure(self.profile_path, provider_id=provider_id, model_identifier=model, time_seconds=30, steps=2)
            if provider_id == 'opencode':
                self.disconnect()
            else:
                self.disabled_path.unlink(missing_ok=True)
            self.probe(provider_id)
            self.authentication = self.request = 'unverified'
            self.detail = 'Model saved. Authenticate using Codex in this runtime, then verify. StatePort never reads or copies credentials.'
            return self.status()

    def disconnect(self):
        with self.lock:
            self.disabled_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Do not delete the provider-owned login or another application's access.
            descriptor = os.open(self.disabled_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as handle:
                handle.write('StatePort provider work disabled\n')
            self.authentication = self.request = 'unverified'
            self.detail = 'Disconnected from StatePort. New provider work is refused; Codex owns account sign-out (codex logout).'
            return self.status()

    def verify(self):
        with self.lock:
            provider_id = self.selected_provider()
            adapter = self.probe(provider_id)
            status = self.status()
            if not status['connected'] or not status['executableInstalled']:
                self.request = 'failed'
                return self.status()
            # Discard all status stdout/stderr: CLI output may contain account metadata.
            try:
                result = run_process(ProcessSpec((adapter.probe.executable, 'login', 'status'),
                    self.profile_path.parent, timeout_seconds=5, max_output_bytes=16384,
                    environment=filtered_environment(allow=('PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'CODEX_HOME'))))
            except Exception:
                self.authentication = 'unavailable'
                self.request = 'failed'
                self.detail = 'Codex login status could not run in this runtime. Check the installed executable and runtime permissions.'
                return self.status()
            self.authentication = 'authenticated' if result.ok else 'unauthenticated'
            if not result.ok:
                self.request = 'failed'
                self.detail = 'Codex reports no usable login. Authenticate in the service runtime with codex login --device-auth, then verify again.'
                return self.status()
            self.staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            identifier = 'verify.' + uuid4().hex
            try:
                with TemporaryWorkspace(self.staging_root, prefix='probe-') as staging:
                    ProviderRouter(self.profile_path, adapter=adapter).invoke(
                        work_id=identifier, attempt_id=identifier, attempt_ordinal=1,
                        instance_id='provider-verification', conversation_id=identifier,
                        message_id=identifier, source_sequence=1,
                        objective='Reply with the word READY. Do not use tools or read files.',
                        context_digest='sha256:' + hashlib.sha256(b'provider-verification').hexdigest(),
                        staging_root=staging)
                self.request = 'succeeded'
                self.detail = 'One bounded request completed in this runtime. Login status is credential presence; billing and quota telemetry remain unavailable.'
            except Exception:
                # Never persist exception text, prompts, event streams, or account metadata.
                self.request = 'failed'
                self.detail = 'Login is present but the request failed. Check account access, model availability, network and quota using Codex, then retry.'
            return self.status()

    def login_status(self):
        # Pure projection of observed login state: a status read never probes,
        # reads a profile, or executes anything, exactly like status().
        with self.login_lock:
            state = dict(self.login_state)
        code_visible = state['phase'] == 'code'
        return {
            'active': bool(state['active']),
            'phase': state['phase'],
            'verificationUrl': state['verificationUrl'] if code_visible else None,
            'userCode': state['userCode'] if code_visible else None,
            'detail': state['detail'],
        }

    def start_device_login(self):
        # Start the provider-owned sign-in: the codex CLI owns credentials and
        # CODEX_HOME; StatePort only relays the non-secret URL and user code.
        with self.lock:
            provider_id = self.selected_provider()
            if provider_id != 'codex':
                raise ProviderLoginError('provider_login_unavailable',
                                         'Integrated sign-in is available only while the Codex provider is selected.')
            adapter = self.probe(provider_id)
            executable = adapter.probe.executable
            if not executable or not adapter.probe.installed:
                raise ProviderLoginError('provider_login_unavailable',
                                         'The Codex executable is not installed in this runtime.')
            with self.login_lock:
                if self.login_state['active']:
                    raise ProviderLoginError('provider_login_active',
                                             'A provider sign-in is already in progress. Complete or cancel it first.')
                state = {
                    'active': True, 'phase': 'pending', 'verificationUrl': None, 'userCode': None,
                    'detail': 'Waiting for the provider sign-in process to produce a verification code.',
                    'cancel_requested': False, 'process': None}
                self.login_state = state
            cwd = self.profile_path.parent
        # Spawned outside both locks: the flow never holds the status lock.
        threading.Thread(target=self._run_device_login, args=(state, executable, cwd),
                         name='stateport-provider-login', daemon=True).start()
        return self.login_status()

    def cancel_device_login(self):
        with self.login_lock:
            state = self.login_state
            if not state['active']:
                return self.login_status()
            state['cancel_requested'] = True
            process = state.get('process')
            if state['phase'] not in _LOGIN_TERMINAL_PHASES:
                state['phase'] = 'cancelled'
                state['detail'] = 'The provider sign-in flow was cancelled.'
                state['verificationUrl'] = None
                state['userCode'] = None
                state['active'] = False
                state['process'] = None
        if process is not None and process.poll() is None:
            _terminate_login_process(process)
        return self.login_status()

    def shutdown_device_login(self):
        # Service-shutdown hook: the login pump thread is a daemon, so an
        # in-flight provider sign-in process (own session) would otherwise
        # survive interpreter exit with nothing enforcing the flow bound.
        # The flow is marked terminal first so a finishing pump thread cannot
        # resurrect it, then the process group is terminated exactly like a
        # cancel.
        with self.login_lock:
            state = self.login_state
            state['cancel_requested'] = True
            process = state.get('process')
            if state['phase'] not in _LOGIN_TERMINAL_PHASES:
                state['phase'] = 'cancelled'
                state['detail'] = 'The provider sign-in flow was stopped at service shutdown.'
                state['verificationUrl'] = None
                state['userCode'] = None
                state['active'] = False
                state['process'] = None
        if process is not None and process.poll() is None:
            _terminate_login_process(process)

    def logout(self):
        # Sign-out stays provider-owned: run the bounded logout command and
        # discard every byte of output, exactly like the verify status probe.
        with self.lock:
            provider_id = self.selected_provider()
            adapter = self.probe(provider_id)
            status = self.status()
            if not status['connected'] or not status['executableInstalled']:
                self.request = 'failed'
                self.detail = 'Codex sign-out could not run because provider work is disconnected or the executable is missing.'
                return self.status()
            # Discard all logout stdout/stderr: CLI output may contain account metadata.
            try:
                result = run_process(ProcessSpec((adapter.probe.executable, 'logout'),
                    self.profile_path.parent, timeout_seconds=10, max_output_bytes=16384,
                    environment=filtered_environment(allow=('PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'CODEX_HOME'))))
            except Exception:
                self.authentication = 'unavailable'
                self.request = 'failed'
                self.detail = 'Codex sign-out could not run in this runtime. Check the installed executable and runtime permissions.'
                return self.status()
            if not result.ok:
                self.request = 'failed'
                self.detail = 'Codex sign-out did not complete in this runtime. Check account access with Codex, then retry.'
                return self.status()
            self.authentication = self.request = 'unverified'
            self.detail = 'Signed out in the provider runtime. StatePort never reads or copies credentials.'
            return self.status()

    def _finish_login(self, state, phase, detail):
        # Mark exactly one terminal state: an already-terminal flow (including
        # a cancel that won the race) is never overwritten.
        authenticated = phase == 'authenticated'
        with self.login_lock:
            if state['phase'] in _LOGIN_TERMINAL_PHASES and not state['active']:
                return
            if state['cancel_requested']:
                phase = 'cancelled'
                detail = 'The provider sign-in flow was cancelled.'
            state['phase'] = phase
            state['detail'] = detail
            state['verificationUrl'] = None
            state['userCode'] = None
            state['active'] = False
            state['process'] = None
        if authenticated:
            # Sign-in completed in the provider runtime: prior verify
            # observations are invalidated so the user re-verifies.
            with self.lock:
                self._invalidate_observation()
                self.detail = 'Device sign-in completed in the provider runtime. Verify authentication and a bounded request again.'

    def _run_device_login(self, state, executable, cwd):
        process = None
        try:
            try:
                process = subprocess.Popen(
                    (executable, 'login', '--device-auth'), cwd=cwd,
                    env=filtered_environment(allow=('PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'CODEX_HOME')),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=False, start_new_session=os.name == 'posix')
            except Exception:  # noqa: BLE001 - a failed spawn stays a generic phase, never exception text
                self._finish_login(state, 'failed', 'The provider sign-in process could not start in this runtime.')
                return
            with self.login_lock:
                state['process'] = process
            outcome, verification_url, user_code = self._pump_device_login(state, process)
            if outcome is None:
                returncode = _reap_login_process(process)
                if returncode == 0 and verification_url and user_code:
                    outcome = ('authenticated',
                               'Provider sign-in completed in the provider runtime. Verify authentication and a bounded request again.')
                else:
                    outcome = ('failed', 'The provider sign-in process failed before completing sign-in.')
            else:
                # The flow was decided by a deadline or a cancel while the
                # provider process may still be running; stop it now.
                _terminate_login_process(process)
            self._finish_login(state, *outcome)
        finally:
            if process is not None and process.poll() is None:
                _terminate_login_process(process)

    def _pump_device_login(self, state, process):
        """Consume the bounded login stream; retain only the URL and user code.

        Returns (outcome, verification_url, user_code); outcome is None while
        the stream ended without a decided terminal phase.
        """
        stdout = process.stdout.fileno()
        os.set_blocking(stdout, False)
        flow_deadline = time.monotonic() + self.login_flow_timeout_seconds
        code_deadline = time.monotonic() + self.login_code_wait_seconds
        buffer = bytearray()
        verification_url = None
        user_code = None
        outcome = None
        while outcome is None:
            now = time.monotonic()
            if now >= flow_deadline:
                outcome = ('expired', 'The provider sign-in flow expired before completion. Start sign-in again.')
                break
            if (verification_url is None or user_code is None) and now >= code_deadline:
                outcome = ('failed', 'The provider sign-in process did not produce a verification code in time.')
                break
            with self.login_lock:
                if state['cancel_requested']:
                    outcome = ('cancelled', 'The provider sign-in flow was cancelled.')
                    break
            waiting_for_code = verification_url is None or user_code is None
            bound = min(flow_deadline, code_deadline) if waiting_for_code else flow_deadline
            readable, _, _ = select.select([stdout], [], [], min(0.2, max(0.0, bound - now)))
            if stdout in readable:
                try:
                    chunk = os.read(stdout, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    break
                room = _LOGIN_OUTPUT_BOUND_BYTES - len(buffer)
                if room > 0:
                    buffer.extend(chunk[:room])
                if verification_url is None or user_code is None:
                    text = bytes(buffer).decode('utf-8', errors='replace')
                    if verification_url is None:
                        found = _VERIFICATION_URL_PATTERN.search(text)
                        if found:
                            verification_url = found.group(0)
                    if user_code is None:
                        found = _USER_CODE_PATTERN.search(text)
                        if found:
                            user_code = found.group(1)
                    if verification_url is not None and user_code is not None:
                        with self.login_lock:
                            if state['cancel_requested']:
                                outcome = ('cancelled', 'The provider sign-in flow was cancelled.')
                                break
                            state['verificationUrl'] = verification_url
                            state['userCode'] = user_code
                            state['phase'] = 'code'
                            state['detail'] = 'Open the verification URL and enter the code in the browser to complete sign-in.'
            elif process.poll() is not None and not select.select([stdout], [], [], 0.05)[0]:
                break
        return outcome, verification_url, user_code
