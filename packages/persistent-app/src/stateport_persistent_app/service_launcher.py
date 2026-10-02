"""PersistentApp service launcher for the assistant-aware service entry."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

from stateport_persistent_app.app import PersistentApp as BasePersistentApp, ServiceError

# How long service_start waits for the child to publish a running runtime record.
# Measured cold first start on this host is 2.68-2.83s, so anything near the old
# 2.0s fixed iteration count failed the first launch after an install.
_READINESS_TIMEOUT_SECONDS = 30.0


class PersistentApp(BasePersistentApp):
    """Use the thin assistant-aware entry while preserving service semantics."""

    def service_start(
        self,
        *,
        port: int = 8790,
        open_browser: bool = False,
        repo_root: Path | None = None,
        actor_role: str = "local_user",
    ) -> dict[str, Any]:
        return self._with_service_lifecycle_lock(
            lambda: self._service_start_locked(
                port=port,
                open_browser=open_browser,
                repo_root=repo_root,
                actor_role=actor_role,
            )
        )

    def _service_start_locked(
        self,
        *,
        port: int,
        open_browser: bool,
        repo_root: Path | None,
        actor_role: str,
    ) -> dict[str, Any]:
        root, expected = self._service_start_request(
            port=port,
            repo_root=repo_root,
            actor_role=actor_role,
        )
        current = self.service_status()
        if current.get("status") == "running":
            self._require_service_identity(current, expected)
            self._require_matching_web_build(
                root, expected["gitHead"], expected["gitTree"]
            )
            if open_browser:
                import webbrowser

                webbrowser.open(current["url"])
            return current
        if current.get("status") == "stale-runtime":
            try:
                (self.layout.runtime_root / "service.json").unlink()
            except FileNotFoundError:
                pass
        self._require_matching_web_build(
            root, expected["gitHead"], expected["gitTree"]
        )
        self.layout.initialize()
        log_path = self.layout.logs_root / "service.log"
        command = [
            sys.executable,
            "-m",
            "stateport_persistent_app.service_resilient_entry",
            "--owned-service-marker",
            "stateport_persistent_app.service_process",
            "--port",
            str(port),
            "--repo-root",
            str(root),
            "--actor-role",
            actor_role,
            "--canonical-source-catalog",
            str(expected["canonicalSourceCatalog"]),
            "--expected-source-catalog-digest",
            str(expected["canonicalSourceCatalogDigest"]),
        ]
        env = dict(os.environ)
        source_paths = [
            str(Path(__file__).resolve().parents[1]),
            str(root / "packages/portable-execution/src"),
            str(root / "packages/application-experience/src"),
            str(root / "packages/conversation-service/src"),
            str(root / "packages/context-lifecycle/src"),
            str(root / "packages/goal-execution/src"),
            str(root / "packages/file-workspace-broker/src"),
            str(root / "packages/terminal-broker/src"),
            str(root / "packages/governed-runner/src"),
            str(root / "packages/execution-host/src"),
            str(root / "packages/release-contracts/src"),
            str(root / "packages/external-engine-runtime/src"),
            str(root / "packages/codex-adapter/src"),
            str(root / "packages/run-bundle/src"),
            str(root / "packages/sandbox-runtime/src"),
            str(root / "packages/statebench/src"),
            str(root / "packages/statedd-core/src"),
            str(root / "packages/template-validator/src"),
            str(root / "packages/instance-backup/src"),
            str(root / "packages/instance-catalog/src"),
            str(root / "packages/diagnostics/src"),
            str(root / "packages/opencode-adapter/src"),
            str(root / "packages/container-opencode/src"),
            str(root / "apps/runner/src"),
            str(root / "apps/telegram-adapter/src"),
        ]
        existing_pythonpath = env.get("PYTHONPATH")
        if existing_pythonpath:
            source_paths.append(existing_pythonpath)
        env["PYTHONPATH"] = os.pathsep.join(source_paths)
        with open(log_path, "ab") as log:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
                env=env,
                cwd=root,
            )
        # A cold first start has to import the whole service graph, and that
        # measured 2.68-2.83s on this host. The previous budget of 40 x 0.05s was
        # exactly 2.0s, so the first launch after an install deterministically
        # missed it and was killed while still starting up. 30s keeps more than
        # ten times the measured margin for slower office hardware while staying
        # bounded, so a genuinely hung service still fails rather than blocking.
        deadline = time.monotonic() + _READINESS_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(0.05)
            status = self.service_status()
            if status.get("status") == "running":
                try:
                    self._require_service_identity(status, expected)
                    if int(status.get("pid", -1)) != process.pid:
                        raise ServiceError(
                            "local service readiness came from an unexpected process"
                        )
                except (ServiceError, TypeError, ValueError):
                    self._terminate_spawned_service(process)
                    raise
                if open_browser:
                    import webbrowser

                    webbrowser.open(status["url"])
                return status
            if process.poll() is not None:
                break
        # Distinguish the two ways this fails. A child that is still importing has
        # written nothing to the log, so "inspect service logs" pointed at an empty
        # file and named no cause.
        still_starting = process.poll() is None
        self._terminate_spawned_service(process)
        if still_starting:
            raise ServiceError(
                f"local service did not become ready within {_READINESS_TIMEOUT_SECONDS:g}s and never "
                "wrote to the service log, so it most likely did not finish starting. Retry, and "
                "inspect the log only if a retry fails."
            )
        raise ServiceError(
            "local service did not become ready; it exited, so inspect the service log at "
            f"{log_path}"
        )


__all__ = ["PersistentApp"]
