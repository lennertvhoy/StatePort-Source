"""Nonsecret Codex setup; authentication remains owned by the Codex CLI.

Official contract checked 2026-09-05: https://learn.chatgpt.com/docs/auth
and https://learn.chatgpt.com/docs/developer-commands?surface=cli .
Login status observes credential presence, never remote freshness or quota.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import threading
from uuid import uuid4

from codex_adapter import CodexAdapter
from external_engine_runtime import ProcessSpec, TemporaryWorkspace, filtered_environment, run_process
from .provider_router import ProviderRouter, ProviderRouterError


class ProviderSetup:
    def __init__(self, config_root: Path, state_root: Path, *, adapter_factory=CodexAdapter):
        self.profile_path = config_root / 'provider-router.json'
        self.disabled_path = self.profile_path.with_suffix('.disabled')
        self.staging_root = state_root / 'provider-verification'
        self.adapter_factory = adapter_factory
        self.lock = threading.RLock()
        self.authentication = 'unverified'
        self.request = 'unverified'
        self.detail = 'Select a model, authenticate using Codex in this runtime, then verify.'

    def status(self):
        with self.lock:
            adapter = self.adapter_factory()
            model = None
            configured = False
            try:
                profile = ProviderRouter(self.profile_path, adapter=adapter).runtime_profile
                model = profile['model']['id']
                configured = True
            except ProviderRouterError:
                pass
            installed = adapter.probe.installed
            return dict(configured=configured, executableInstalled=installed,
                        connected=configured and not self.disabled_path.exists(), model=model,
                        authenticationStatus=self.authentication if installed else 'unavailable',
                        requestStatus=self.request, telemetryStatus='unavailable',
                        detail=self.detail if installed else 'Codex is not installed in the StatePort service runtime. Host or workspace CLI presence does not authenticate this service.')

    def configure(self, model):
        with self.lock:
            if not isinstance(model, str):
                raise ProviderRouterError('model identifier is invalid')
            ProviderRouter.configure_codex(self.profile_path, model_identifier=model, time_seconds=30, steps=2)
            self.disabled_path.unlink(missing_ok=True)
            self.authentication = self.request = 'unverified'
            self.detail = 'Model saved. Run codex login --device-auth in the same runtime and operator account, then verify. StatePort never reads or copies credentials.'
            return self.status()

    def disconnect(self):
        with self.lock:
            self.disabled_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Do not delete the provider-owned login or another application's access.
            import os
            descriptor = os.open(self.disabled_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as handle:
                handle.write('StatePort provider work disabled\n')
            self.authentication = self.request = 'unverified'
            self.detail = 'Disconnected from StatePort. New provider work is refused; Codex owns account sign-out (codex logout).'
            return self.status()

    def verify(self):
        with self.lock:
            status = self.status()
            if not status['connected'] or not status['executableInstalled']:
                self.request = 'failed'
                return self.status()
            adapter = self.adapter_factory()
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
