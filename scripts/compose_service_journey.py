#!/usr/bin/env python3
"""Run the release-relevant Compose service journey locally.

Local equivalent of the ``compose-integration`` job in
``.github/workflows/validate.yml``: detect a container engine, build the
stack from this checkout with exact source provenance, start it, wait for
real health, validate the delivered endpoints, and tear down.  Heavy and
explicitly opt-in (``local_closure_gate.py --include-service-journey``).
Never publishes anything and never touches state outside the Compose
project it creates; teardown always runs.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEALTH_TIMEOUT_SECONDS = 180
BUILD_TIMEOUT_SECONDS = 1500
UP_TIMEOUT_SECONDS = 180


class JourneyError(RuntimeError):
    pass


def _run(
    argv: list[str],
    *,
    env: dict[str, str],
    timeout: int,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        cwd=str(ROOT),
        env=env,
        check=False,
        capture_output=capture,
        text=True,
        timeout=timeout,
    )
    return completed


def _must(argv: list[str], *, env: dict[str, str], timeout: int, what: str) -> str:
    completed = _run(argv, env=env, timeout=timeout)
    if completed.returncode:
        tail = (completed.stdout or "")[-2000:] + (completed.stderr or "")[-2000:]
        raise JourneyError(f"{what} failed ({completed.returncode}): {tail}")
    return completed.stdout or ""


def _detect_engine() -> list[str]:
    if shutil.which("podman") and _run(
        ["podman", "compose", "version"], env=dict(os.environ), timeout=30
    ).returncode == 0:
        return ["podman", "compose"]
    if shutil.which("podman") and shutil.which("podman-compose"):
        return ["podman-compose"]
    if shutil.which("docker") and _run(
        ["docker", "compose", "version"], env=dict(os.environ), timeout=30
    ).returncode == 0:
        return ["docker", "compose"]
    raise JourneyError("no container engine found (podman compose, podman-compose, docker compose)")


def _free_port() -> int:
    for _ in range(50):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if 45000 <= port <= 54999:
            return port
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _git(*args: str) -> str:
    return _must(["git", "-C", str(ROOT), *args], env=dict(os.environ), timeout=30, what="git").strip()


def _wait_http(url: str, *, timeout: int, what: str) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.read().decode()
        except OSError:
            time.sleep(2)
    raise JourneyError(f"{what} did not become healthy within {timeout}s")


def _wait_internal(
    compose: list[str], env: dict[str, str], service: str, port: int, path: str
) -> None:
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    argv = compose + [
        "exec", "-T", service, "/usr/local/bin/stateport-healthcheck",
        "--kind", "http", "--host", "127.0.0.1", "--port", str(port), "--path", path,
    ]
    while time.monotonic() < deadline:
        if _run(argv, env=env, timeout=30).returncode == 0:
            print(f"OK: {service} healthy inside the private Compose network")
            return
        time.sleep(2)
    raise JourneyError(f"{service} did not become healthy within {HEALTH_TIMEOUT_SECONDS}s")


def _exec_json(compose: list[str], env: dict[str, str], service: str, url: str) -> dict[str, object]:
    body = _must(
        compose + [
            "exec", "-T", service, "python3", "-c",
            f"import urllib.request; print(urllib.request.urlopen('{url}').read().decode())",
        ],
        env=env,
        timeout=60,
        what=f"{service} exec {url}",
    )
    data = json.loads(body)
    if not isinstance(data, dict):
        raise JourneyError(f"{service} {url} did not return an object")
    return data


def main() -> int:
    compose = _detect_engine()
    project = f"stateport-local-journey-{os.getpid()}"
    web_port = _free_port()
    commit = _git("rev-parse", "--verify", "HEAD")
    tree = _git("rev-parse", "--verify", f"{commit}^{{tree}}")
    epoch = _git("show", "-s", "--format=%ct", commit)
    created = datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ref = _run(
        ["git", "-C", str(ROOT), "symbolic-ref", "--quiet", "--short", "HEAD"],
        env=dict(os.environ), timeout=30,
    ).stdout.strip() or "detached"
    dirty = bool(_git("status", "--porcelain"))

    env = dict(os.environ)
    env.update(
        {
            "COMPOSE_PROJECT_NAME": project,
            "STATEPORT_WEB_PORT": str(web_port),
            "STATEPORT_BUILD_SOURCE_COMMIT": commit,
            "STATEPORT_BUILD_SOURCE_TREE": tree,
            "STATEPORT_BUILD_SOURCE_REF": ref,
            "STATEPORT_BUILD_SOURCE_DIRTY": "true" if dirty else "false",
            "STATEPORT_BUILD_SOURCE_DATE_EPOCH": epoch,
            "STATEPORT_BUILD_VERSION": f"0.0.0-local.{os.getpid()}",
            "STATEPORT_BUILD_CREATED": created,
            "STATEPORT_BUILD_ADAPTER": "local-closure-gate",
        }
    )
    print(f"journey: engine={' '.join(compose)} project={project} web_port={web_port}")
    try:
        _run(compose + ["down", "-v", "--remove-orphans"], env=env, timeout=60)
        _must(compose + ["build"], env=env, timeout=BUILD_TIMEOUT_SECONDS, what="compose build")
        _must(compose + ["up", "-d"], env=env, timeout=UP_TIMEOUT_SECONDS, what="compose up")

        _wait_http(
            f"http://127.0.0.1:{web_port}/health",
            timeout=HEALTH_TIMEOUT_SECONDS,
            what="stateport-web",
        )
        print("OK: stateport-web healthy on the one host-published port")
        _wait_internal(compose, env, "stateport-api", 8790, "/readyz")
        _wait_internal(compose, env, "stateport-worker", 8791, "/readyz")

        page = _wait_http(f"http://127.0.0.1:{web_port}/", timeout=60, what="stateport-web index")
        if "stateport" not in page.lower() and "<!doctype html" not in page.lower():
            raise JourneyError("web service response does not look like the production frontend")
        print("OK: web service returned production frontend")

        api_health = _exec_json(compose, env, "stateport-api", "http://127.0.0.1:8790/health")
        api_result = api_health.get("result")
        if not (
            api_health.get("ok") is True
            and isinstance(api_result, dict)
            and api_result.get("status") == "ok"
            and str(api_result.get("apiVersion", "")).startswith("stateport")
        ):
            raise JourneyError(f"API health response invalid: {api_health}")
        print("OK: API health response valid")

        worker_health = _exec_json(compose, env, "stateport-worker", "http://127.0.0.1:8791/health")
        worker_result = worker_health.get("result")
        if not (
            worker_health.get("ok") is True
            and isinstance(worker_result, dict)
            and worker_result.get("service") == "stateport-worker"
            and worker_result.get("status") == "standby"
            and worker_result.get("executionEnabled") is False
        ):
            raise JourneyError(f"worker health response invalid: {worker_health}")
        print("OK: worker health response valid")

        capabilities = _exec_json(compose, env, "stateport-api", "http://127.0.0.1:8790/v1/capabilities")
        cap_result = capabilities.get("result")
        if not (
            capabilities.get("ok") is True
            and isinstance(cap_result, dict)
            and "operations" in cap_result
            and str(cap_result.get("apiVersion", "")).startswith("stateport")
        ):
            raise JourneyError(f"API capabilities response invalid: {capabilities}")
        print("OK: API capabilities endpoint valid")
        print("JOURNEY PASS: Compose service journey validated the delivered product")
        return 0
    except JourneyError as exc:
        logs = _run(compose + ["logs", "--tail=100"], env=env, timeout=60)
        print(f"JOURNEY FAIL: {exc}", file=sys.stderr)
        print(f"=== Service logs ===\n{logs.stdout}", file=sys.stderr)
        return 1
    finally:
        _run(compose + ["down", "-v", "--remove-orphans"], env=env, timeout=60)


if __name__ == "__main__":
    raise SystemExit(main())
