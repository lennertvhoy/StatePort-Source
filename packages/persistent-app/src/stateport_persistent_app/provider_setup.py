"""Nonsecret provider selection; enabled Codex authentication stays CLI-owned.

Official contract checked 2026-09-05: https://learn.chatgpt.com/docs/auth
and https://learn.chatgpt.com/docs/developer-commands?surface=cli .
Login status observes credential presence, never remote freshness or quota.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
import threading
from uuid import uuid4

from codex_adapter import CodexAdapter
from external_engine_runtime import ProcessSpec, TemporaryWorkspace, filtered_environment, run_process
from .provider_router import ProviderRouter, ProviderRouterError, PROVIDERS, OPENCODE_REFUSAL


class ProviderSetup:
    def __init__(self, config_root: Path, state_root: Path, *, adapter_factory=CodexAdapter):
        self.profile_path = config_root / 'provider-router.json'
        self.disabled_path = self.profile_path.with_suffix('.disabled')
        self.staging_root = state_root / 'provider-verification'
        self.adapter_factory = adapter_factory
        self.observed_adapter = None
        self.observed_provider = None
        self.observed_identity = None
        self.lock = threading.RLock()
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
