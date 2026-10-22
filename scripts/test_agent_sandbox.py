#!/usr/bin/env python3
"""Deterministic tests for the agent sandbox (docs/design/agent-sandbox.md).

The sandbox is exercised with a FAKE harness binary: a small executable script
generated in a temp directory that speaks OpenCode's JSON event shape. It
edits files under ``/work``, tries a direct TCP connection, tries to read a
path outside ``/work`` and tries an HTTPS request through ``$HTTPS_PROXY``, so
the boundary is observed from inside the same sandbox shape agent work uses.

Nothing here reaches a real model. The one live row (a real free-model edit
through the pinned opencode) is opt-in through ``STATEPORT_LIVE_FREE_MODEL=1``
and is skipped by default.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tarfile
import threading
import time
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _src in [
    ROOT / "packages" / "codex-adapter" / "src",
    ROOT / "packages" / "execution-host" / "src",
    ROOT / "packages" / "external-engine-runtime" / "src",
    ROOT / "packages" / "persistent-app" / "src",
]:
    if str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

from stateport_persistent_app import agent_sandbox  # noqa: E402
from stateport_persistent_app.agent_sandbox import (  # noqa: E402
    OPENCODE_FREE_ROUTE_HOSTS,
    PINNED_OPENCODE_VERSION,
    SandboxRoute,
    cached_selftest,
    run_check_in_sandbox,
    run_harness_in_sandbox,
    run_in_sandbox,
    sandbox_available,
    selftest,
)

# The pinned opencode build this suite is written against. The digest is the
# sha256 of the ``package/bin/opencode`` member of the published tarball, so
# the live row verifies the bytes it is about to execute.
PINNED_OPENCODE_SHA256 = "179ca421d61eefeadfa0c50e084a6e79c1623734732f0f4593f81ccfd3ab7ee9"
PINNED_OPENCODE_TARBALL = (
    "https://registry.npmjs.org/opencode-linux-x64/-/opencode-linux-x64-1.19.3.tgz"
)
LIVE_MODEL_CANDIDATES = (
    "opencode/nemotron-3.5-lightning-free",
    "opencode/nemotron-3-ultra-free",
)
# A name that resolves to a loopback address. It carries a dot on purpose: the
# module refuses an allowlist entry that is not a dotted host name.
LOOPBACK_NAME = "localhost.localdomain"
# A name that is on the route's allowlist and is resolved by the injected
# resolver to the test's own host-side listener.
ALLOWED_NAME = "allowed.example.test"
DENIED_NAME = "denied.example.test"


# --------------------------------------------------------------------------- the fake harness


_FAKE_HARNESS = r'''#!{interpreter}
"""Fake OpenCode harness: speaks the JSON event shape and probes the boundary.

argv[0] is the harness path; ``--version`` answers the pinned version; a run
takes its probe specification as the LAST argument (a JSON object).
"""

import json
import os
import socket
import subprocess
import sys
import time


def _spec():
    raw = sys.argv[-1] if sys.argv else ""
    if raw.startswith("{"):
        try:
            value = json.loads(raw)
        except ValueError:
            return {}
        if isinstance(value, dict):
            return value
    return {}


def _connect(host, port, timeout=3.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "connected"
    except OSError as exc:
        return "refused:" + exc.__class__.__name__


def _proxy_connect(proxy_port, target):
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as conn:
            conn.sendall(("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n").encode("ascii"))
            conn.settimeout(10)
            data = b""
            while b"\r\n" not in data and len(data) < 4096:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            status = data.split(b"\r\n", 1)[0].decode("latin-1") or "closed"
            echoed = ""
            if "200" in status:
                # The proxy opens the tunnel only for TLS that names the CONNECT host: send a real ClientHello.
                import ssl
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname=target.rsplit(":", 1)[0])
                try:
                    tls.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                hello = outgoing.read()
                conn.sendall(hello)
                got = b""
                while len(got) < 16:
                    chunk = conn.recv(64)
                    if not chunk:
                        break
                    got += chunk
                echoed = "HELLO" if got and hello.startswith(got[:16]) else got.decode("latin-1", "replace")
            return {"status": status, "echo": echoed}
    except OSError as exc:
        return {"status": "error:" + exc.__class__.__name__, "echo": ""}


def _read(path):
    try:
        with open(path, "rb") as handle:
            return "read:" + handle.read(16).decode("utf-8", "replace")
    except OSError as exc:
        return "refused:" + exc.__class__.__name__


def _write(path, data):
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w") as handle:
            handle.write(data)
        return "written"
    except OSError as exc:
        return "refused:" + exc.__class__.__name__


def main():
    if "--version" in sys.argv:
        print("{version}")
        return 0
    spec = _spec()
    probe = {}
    # Edits under /work are the only edits the caller may observe.
    probe["workWrite"] = _write("/work/notes.md", "edited by the fake harness\n")
    probe["nestedWrite"] = _write("/work/sub/dir/nested.txt", "nested\n")
    # A private tmpfs and a read-only root: neither reaches the host.
    probe["tmpWrite"] = _write("/tmp/{escape}", "escape\n")
    probe["rootWrite"] = _write("/etc/{escape}", "escape\n")
    # A path outside /work is not visible at all.
    probe["outsideRead"] = _read(spec.get("outsidePath", "/etc/hostname"))
    # The sandbox has no network of its own.
    probe["directTcp"] = _connect("127.0.0.1", int(spec.get("directPort", 9)))
    # Egress exists only through the allowlisting proxy.
    proxy = os.environ.get("HTTPS_PROXY", "")
    proxy_port = int(proxy.rsplit(":", 1)[-1]) if proxy else 0
    probe["proxy"] = {}
    for target in spec.get("proxyTargets", []):
        probe["proxy"][target] = _proxy_connect(proxy_port, target)
    print(json.dumps({"type": "probe", "probe": probe}))
    print(json.dumps({"type": "text", "part": {"type": "text", "text": "fake harness finished"}}))
    if spec.get("floodBytes"):
        sys.stdout.write("x" * int(spec["floodBytes"]))
        sys.stdout.flush()
    if spec.get("spawnChild"):
        delay = int(spec.get("childSleep", 3))
        subprocess.Popen([
            sys.executable, "-c",
            "import time; time.sleep(" + str(delay) + "); open('/work/late.txt','w').write('late')",
        ])
    if spec.get("sleep"):
        time.sleep(int(spec["sleep"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _fake_harness(directory: Path, *, version: str = PINNED_OPENCODE_VERSION) -> Path:
    """Write the fake harness into ``directory`` and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "opencode"
    source = (
        _FAKE_HARNESS
        .replace("{interpreter}", os.path.realpath(sys.executable))
        .replace("{version}", version)
        .replace("{escape}", "stateport-sandbox-escape-canary.txt")
    )
    path.write_text(source, encoding="utf-8")
    path.chmod(0o700)
    return path


class _HostListener:
    """A host-side TCP listener: the only thing the sandbox may reach through the proxy."""

    def __init__(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(8)
        self.port = self._socket.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="stateport-sandbox-test", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except OSError:
                return
            with connection:
                self.connections += 1
                try:
                    connection.settimeout(5)
                    data = connection.recv(64)
                    connection.sendall(data)
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        try:
            self._socket.close()
        except OSError:
            pass


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    """An isolated sandbox runtime root, a fake harness and a fresh workdir."""
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv(agent_sandbox.RUNTIME_DIR_ENV, str(runtime))
    # The catalogue seed is a network fetch; the deterministic rows never need it.
    monkeypatch.setattr(agent_sandbox, "_catalogue_fetcher", lambda path: False)
    agent_sandbox._reset_probe_cache()
    workdir = tmp_path / "work"
    workdir.mkdir(mode=0o700)
    harness = _fake_harness(tmp_path / "bin")
    yield {
        "workdir": workdir,
        "harness": harness,
        "tmp_path": tmp_path,
        "route": SandboxRoute(
            harness="opencode",
            harness_binary=harness,
            model="opencode/fixture-model",
            allow_hosts=(ALLOWED_NAME,),
            credential_file=None,
            tools="none",
        ),
    }
    agent_sandbox._reset_probe_cache()


def _require_sandbox() -> None:
    available, reason = sandbox_available()
    if not available:
        pytest.skip(f"the agent sandbox is unavailable on this host: {reason}")


def _probe_of(run) -> dict:
    for event in run.events:
        if event.get("type") == "probe":
            probe = event.get("probe")
            if isinstance(probe, dict):
                return probe
    raise AssertionError(f"the fake harness reported no probe event: {run.events}")


# --------------------------------------------------------------------------- the boundary


def test_the_sandbox_is_available_on_this_host(sandbox) -> None:
    available, reason = sandbox_available()
    assert available, reason
    assert "bubblewrap" in reason


def test_edits_land_only_in_the_workdir(sandbox) -> None:
    """The harness changes /work and nothing else the caller can observe."""
    _require_sandbox()
    canary = sandbox["tmp_path"] / "outside-canary.txt"
    canary.write_text("host canary\n", encoding="utf-8")
    escape = Path("/tmp/stateport-sandbox-escape-canary.txt")
    assert not escape.exists()

    run = run_harness_in_sandbox(
        workdir=sandbox["workdir"],
        prompt=json.dumps({"outsidePath": str(canary), "directPort": 9}),
        route=sandbox["route"],
        timeout_seconds=60,
        output_limit_bytes=65536,
    )

    assert run.result.status == "completed", run.result.final_text
    probe = _probe_of(run)
    # The edit under /work is visible to the caller.
    assert probe["workWrite"] == "written"
    assert probe["nestedWrite"] == "written"
    assert (sandbox["workdir"] / "notes.md").read_text(encoding="utf-8") == "edited by the fake harness\n"
    assert (sandbox["workdir"] / "sub" / "dir" / "nested.txt").read_text(encoding="utf-8") == "nested\n"
    # The private tmpfs and the read-only root never reach the host.
    assert probe["tmpWrite"] == "written"
    assert not escape.exists(), "a write to the sandbox tmpfs leaked to the host"
    assert probe["rootWrite"].startswith("refused")
    # A path outside /work is not visible at all.
    assert probe["outsideRead"].startswith("refused")
    # The sandbox has no network of its own.
    assert probe["directTcp"].startswith("refused")


def test_the_timeout_kills_the_whole_process_group(sandbox) -> None:
    """A descendant that outlives the harness dies with the harness' process group."""
    _require_sandbox()
    run = run_harness_in_sandbox(
        workdir=sandbox["workdir"],
        prompt=json.dumps({"spawnChild": True, "childSleep": 3, "sleep": 30}),
        route=sandbox["route"],
        timeout_seconds=1,
        output_limit_bytes=65536,
    )

    assert run.result.status == "timeout", run.result.final_text
    assert run.process is not None and run.process.timed_out
    # The descendant would have written this file three seconds in.
    time.sleep(4)
    assert not (sandbox["workdir"] / "late.txt").exists(), (
        "a child of the harness survived the timeout; the process group was not killed"
    )


def test_the_output_cap_stops_the_run(sandbox) -> None:
    _require_sandbox()
    run = run_harness_in_sandbox(
        workdir=sandbox["workdir"],
        prompt=json.dumps({"floodBytes": 200000}),
        route=sandbox["route"],
        timeout_seconds=60,
        output_limit_bytes=8192,
    )

    assert run.result.status == "failed"
    assert run.process is not None and run.process.output_limited
    assert run.result.final_text.startswith("output_limit_exceeded")


# --------------------------------------------------------------------------- egress


def test_egress_admits_only_the_allowlisted_host(sandbox) -> None:
    """The proxy admits the route's host, refuses everything else and logs both."""
    _require_sandbox()
    listener = _HostListener()
    try:
        def resolver(host: str, port: int):
            if host == ALLOWED_NAME:
                return [(socket.AF_INET, ("127.0.0.1", listener.port))]
            return agent_sandbox._resolve_public(host, port)

        run = run_harness_in_sandbox(
            workdir=sandbox["workdir"],
            prompt=json.dumps({
                "directPort": listener.port,
                "proxyTargets": [
                    f"{ALLOWED_NAME}:443",
                    f"{DENIED_NAME}:443",
                    "127.0.0.1:443",
                ],
            }),
            route=sandbox["route"],
            timeout_seconds=60,
            output_limit_bytes=65536,
            _resolver=resolver,
        )
    finally:
        listener.close()

    assert run.result.status == "completed", run.result.final_text
    proxy = _probe_of(run)["proxy"]
    # The allowlisted host is reachable, through the proxy only.
    assert "200" in proxy[f"{ALLOWED_NAME}:443"]["status"]
    assert proxy[f"{ALLOWED_NAME}:443"]["echo"] == "HELLO"
    # A host that is not on the allowlist is refused.
    assert "403" in proxy[f"{DENIED_NAME}:443"]["status"]
    # An IP literal is refused before any name check.
    assert "403" in proxy["127.0.0.1:443"]["status"]
    # Only the allowlisted host reached the host side.
    assert listener.connections == 1

    entries = {entry["host"]: entry for entry in run.result.egress}
    assert entries[ALLOWED_NAME]["allowed"] is True
    assert entries[ALLOWED_NAME]["port"] == 443
    assert entries[ALLOWED_NAME]["bytes_up"] > 0
    assert entries[ALLOWED_NAME]["bytes_down"] > 0
    assert entries[DENIED_NAME]["allowed"] is False
    assert entries[DENIED_NAME]["reason"] == "host_not_allowlisted"
    assert entries["127.0.0.1"]["allowed"] is False
    assert entries["127.0.0.1"]["reason"] == "host_invalid"


def test_a_name_that_resolves_to_a_loopback_address_is_refused(sandbox) -> None:
    """A name on the allowlist that resolves to a private address is still refused."""
    _require_sandbox()
    route = SandboxRoute(
        harness=sandbox["route"].harness,
        harness_binary=sandbox["route"].harness_binary,
        model=sandbox["route"].model,
        allow_hosts=(LOOPBACK_NAME,),
        credential_file=None,
        tools="none",
    )
    run = run_harness_in_sandbox(
        workdir=sandbox["workdir"],
        prompt=json.dumps({"proxyTargets": [f"{LOOPBACK_NAME}:443"]}),
        route=route,
        timeout_seconds=60,
        output_limit_bytes=65536,
        _resolver=agent_sandbox._resolve_public,
    )

    assert run.result.status == "completed", run.result.final_text
    # The tunnel is accepted before name resolution (the TLS name is checked first), so the refusal shows as a
    # closed tunnel that never reached an upstream.
    probe = _probe_of(run)["proxy"][f"{LOOPBACK_NAME}:443"]
    assert probe["echo"] != "HELLO"
    entry = next(item for item in run.result.egress if item["host"] == LOOPBACK_NAME)
    assert entry["allowed"] is False
    # The name either resolves to a loopback address (refused by the resolver's
    # own policy) or does not resolve at all (refused before any connection).
    assert entry["reason"] in {"non_public_address", "dns_failed"}


def test_the_resolver_refuses_a_loopback_or_private_answer() -> None:
    """The module's own resolver never hands a private address to the proxy."""
    with pytest.raises(agent_sandbox._Deny) as refusal:
        agent_sandbox._resolve_public("localhost", 443)
    assert refusal.value.reason == "non_public_address"
    assert refusal.value.status.startswith(b"403")


# --------------------------------------------------------------------------- permissions


def test_the_tools_none_permission_denies_every_call() -> None:
    """``{"*":"deny"}`` alone makes the free tier answer 403, so read and bash
    stay REGISTERED and every call is denied by a rule no real input matches."""
    never = "\x00stateport-never-" + "0" * 32
    rules = json.loads(agent_sandbox._permission("none", never))

    assert rules["*"] == "deny"
    # The free tier needs read and bash to stay registered...
    assert set(rules) == {"*", "bash", "read"}
    for tool in ("bash", "read"):
        assert rules[tool]["*"] == "deny"
        # ...and the only allow rule matches a pattern with a NUL byte in it,
        # which no command or path can ever contain.
        assert list(rules[tool]) == ["*", never]
        assert never in rules[tool]
        assert "\x00" in never


def test_the_edit_permission_denies_the_network_tools() -> None:
    never = "\x00stateport-never-" + "0" * 32
    rules = json.loads(agent_sandbox._permission("edit", never))

    assert rules["*"] == "deny"
    for tool in ("read", "edit", "glob", "grep", "list", "bash"):
        assert rules[tool] == "allow"
    for tool in ("webfetch", "websearch", "external_directory"):
        assert rules[tool] == "deny"


# --------------------------------------------------------------------------- refusals


def test_a_missing_bubblewrap_refuses_with_sandbox_unavailable(sandbox, monkeypatch) -> None:
    real_which = agent_sandbox.shutil.which

    def fake_which(name, *args, **kwargs):
        if name == "bwrap":
            return None
        return real_which(name, *args, **kwargs)

    monkeypatch.setattr(agent_sandbox.shutil, "which", fake_which)
    agent_sandbox._reset_probe_cache()

    available, reason = sandbox_available()
    assert available is False
    assert "bubblewrap" in reason

    result = run_in_sandbox(
        workdir=sandbox["workdir"],
        prompt="hello",
        route=sandbox["route"],
        timeout_seconds=30,
        output_limit_bytes=65536,
    )
    assert result.status == "refused"
    assert result.refusal == "sandbox_unavailable"
    assert "bubblewrap" in result.final_text


def test_a_bad_workdir_refuses_with_workdir_invalid(sandbox) -> None:
    _require_sandbox()
    missing = sandbox["tmp_path"] / "does-not-exist"
    result = run_in_sandbox(
        workdir=missing,
        prompt="hello",
        route=sandbox["route"],
        timeout_seconds=30,
        output_limit_bytes=65536,
    )
    assert result.status == "refused"
    assert result.refusal == "workdir_invalid"

    # A protected directory is refused as well: the sandbox must never be
    # pointed at a shared system directory.
    protected = run_in_sandbox(
        workdir=Path("/tmp"),
        prompt="hello",
        route=sandbox["route"],
        timeout_seconds=30,
        output_limit_bytes=65536,
    )
    assert protected.status == "refused"
    assert protected.refusal == "workdir_invalid"


def test_a_bad_route_refuses_with_route_invalid(sandbox) -> None:
    for route in (
        SandboxRoute(
            harness="codex",
            harness_binary=sandbox["harness"],
            model="opencode/fixture-model",
            allow_hosts=(),
            credential_file=None,
            tools="none",
        ),
        SandboxRoute(
            harness="opencode",
            harness_binary=sandbox["harness"],
            model="opencode/fixture-model",
            allow_hosts=(),
            credential_file=None,
            tools="webfetch",
        ),
        SandboxRoute(
            harness="opencode",
            harness_binary=sandbox["harness"],
            model="not a model",
            allow_hosts=(),
            credential_file=None,
            tools="none",
        ),
        SandboxRoute(
            harness="opencode",
            harness_binary=sandbox["harness"],
            model="opencode/fixture-model",
            allow_hosts=("no-dot-host",),
            credential_file=None,
            tools="none",
        ),
        SandboxRoute(
            harness="opencode",
            harness_binary=Path("relative/opencode"),
            model="opencode/fixture-model",
            allow_hosts=(),
            credential_file=None,
            tools="none",
        ),
    ):
        result = run_in_sandbox(
            workdir=sandbox["workdir"],
            prompt="hello",
            route=route,
            timeout_seconds=30,
            output_limit_bytes=65536,
        )
        assert result.status == "refused", route
        assert result.refusal == "route_invalid", route


def test_an_unpinned_harness_binary_refuses_with_sandbox_unavailable(sandbox) -> None:
    """Only the pinned opencode build may run inside the sandbox."""
    _require_sandbox()
    other = _fake_harness(sandbox["tmp_path"] / "other-bin", version="1.18.30")
    route = SandboxRoute(
        harness="opencode",
        harness_binary=other,
        model="opencode/fixture-model",
        allow_hosts=(ALLOWED_NAME,),
        credential_file=None,
        tools="none",
    )
    result = run_in_sandbox(
        workdir=sandbox["workdir"],
        prompt="hello",
        route=route,
        timeout_seconds=30,
        output_limit_bytes=65536,
    )
    assert result.status == "refused"
    assert result.refusal == "sandbox_unavailable"
    assert PINNED_OPENCODE_VERSION in result.final_text


# --------------------------------------------------------------------------- the self-test


def test_selftest_reports_the_boundary_it_measured(sandbox) -> None:
    _require_sandbox()
    report = selftest(control_port=server_port())

    assert report["formatVersion"] == agent_sandbox.SELFTEST_FORMAT
    assert report["available"] is True, report["reason"]
    assert isinstance(report["checks"], list) and report["checks"]
    assert report["ok"] is True, report["checks"]
    assert report["sandboxDigest"].startswith("sha256:")
    assert report["bwrapVersion"]
    checked = {check["id"] for check in report["checks"]}
    assert checked >= {
        "control_plane_loopback_unreachable",
        "direct_egress_blocked",
        "proxy_refuses_unlisted_host",
        "proxy_refuses_ip_literal",
        "outside_paths_unreadable",
        "proc_shows_only_sandbox_processes",
        "environment_scrubbed",
        "system_tree_read_only",
    }
    for check in report["checks"]:
        assert set(check) == {"id", "passed", "detail"}
        assert check["passed"] is True, check


def test_cached_selftest_reuses_one_run(sandbox) -> None:
    _require_sandbox()
    port = server_port()
    first = cached_selftest(control_port=port, max_age_seconds=60.0)
    second = cached_selftest(control_port=port, max_age_seconds=60.0)
    assert first["measuredAt"] == second["measuredAt"]
    assert first["sandboxDigest"] == second["sandboxDigest"]


def server_port() -> int:
    """A port nothing listens on: the self-test must find it unreachable."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


# --------------------------------------------------------------------------- template checks


def test_the_chat_route_runs_the_harness_inside_the_sandbox(sandbox, monkeypatch) -> None:
    """The chat route of the provider router really executes in the sandbox.

    The router is the product's chat path: the durable assistant hands it the
    objective and the staging directory, and the answer comes back from the
    sandbox. The harness here is the fake one, so the assertion is about the
    boundary, not about a model.
    """
    _require_sandbox()
    from stateport_persistent_app.provider_router import ProviderRouter

    profile = sandbox["tmp_path"] / "provider.json"
    ProviderRouter.configure(
        profile, provider_id="opencode", model_identifier="opencode/fixture-model"
    )
    monkeypatch.setattr(
        "stateport_persistent_app.provider_router.resolve_harness_binary",
        lambda: sandbox["harness"],
    )
    router = ProviderRouter(profile, adapter=_FixtureAdapter())
    invocation = router.invoke(
        work_id="assistant.sandbox",
        attempt_id="attempt.assistant.sandbox.1",
        attempt_ordinal=1,
        instance_id="instance.study",
        conversation_id="conv.study",
        message_id="msg.study",
        source_sequence=1,
        objective="What should I study next?",
        context_digest="sha256:" + "a" * 64,
        staging_root=sandbox["workdir"],
    )

    assert invocation.assistant_text == "fake harness finished"
    # The harness ran on the caller's directory, and only there.
    assert (sandbox["workdir"] / "notes.md").is_file()
    assert not (sandbox["tmp_path"] / "notes.md").exists()


class _FixtureAdapter:
    """A managed-OpenCode adapter stand-in: the subject is the sandbox."""

    probe = type("Probe", (), {"installed": True})()

    def execute(self, *args, **kwargs):
        raise AssertionError("the chat route must not use the plain subprocess path")

    def capabilities(self):
        from execution_host.contracts import BackendCapabilities

        values = {
            name: "unsupported"
            for name in (
                "structuredEvents", "nonInteractiveExecution", "cancellation",
                "sessionResume", "repositoryInstructions", "customTools",
                "mcpEquivalent", "approvalIntegration", "sandboxSupport",
                "changedFileReporting", "tokenTelemetry", "costTelemetry",
            )
        }
        values.update(
            structuredEvents="supported", nonInteractiveExecution="supported",
            cancellation="supported", repositoryInstructions="supported",
            sandboxSupport="supported", changedFileReporting="supported",
        )
        return BackendCapabilities(
            "opencode", "opencode-cli", "1.19.3", "managed", values,
            ("operator_authenticated_unverified",),
            ("read_staging", "write_staging"),
            production_eligible=False,
        )


def test_run_check_in_sandbox_has_no_network_at_all(sandbox) -> None:
    """A template check runs with no proxy, no route and no network namespace."""
    _require_sandbox()
    listener = _HostListener()
    script = (
        "import json, os, socket\n"
        "result = {}\n"
        "try:\n"
        "    socket.create_connection(('127.0.0.1', %d), timeout=3).close()\n"
        "    result['direct'] = 'connected'\n"
        "except OSError as exc:\n"
        "    result['direct'] = 'refused:' + exc.__class__.__name__\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 443), timeout=3).close()\n"
        "    result['internet'] = 'connected'\n"
        "except OSError as exc:\n"
        "    result['internet'] = 'refused:' + exc.__class__.__name__\n"
        "result['proxy'] = os.environ.get('HTTPS_PROXY')\n"
        "try:\n"
        "    open('/work/should-not-be-writable', 'w').write('x')\n"
        "    result['workWrite'] = 'written'\n"
        "except OSError as exc:\n"
        "    result['workWrite'] = 'refused:' + exc.__class__.__name__\n"
        "print(json.dumps(result))\n"
    ) % listener.port
    try:
        result = run_check_in_sandbox(
            workdir=sandbox["workdir"],
            argv=["python3", "-c", script],
            timeout_seconds=60,
            output_limit_bytes=65536,
        )
    finally:
        listener.close()

    assert result.status == "completed", result.final_text
    assert result.egress == ()
    observed = json.loads(result.final_text.strip().splitlines()[-1])
    assert observed["direct"].startswith("refused")
    assert observed["internet"].startswith("refused")
    assert observed["proxy"] is None
    assert observed["workWrite"].startswith("refused")
    assert listener.connections == 0
    assert not (sandbox["workdir"] / "should-not-be-writable").exists()


# --------------------------------------------------------------------------- the live row


def _download_pinned_opencode(directory: Path) -> Path:
    """Fetch the pinned tarball and verify the binary member's digest."""
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / "opencode-linux-x64.tgz"
    if not archive.is_file():
        request = urllib.request.Request(
            PINNED_OPENCODE_TARBALL, headers={"User-Agent": "stateport-sandbox-test/1"}
        )
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - fixed https URL
            archive.write_bytes(response.read())
    import hashlib

    with tarfile.open(archive) as bundle:
        member = bundle.extractfile("package/bin/opencode")
        assert member is not None
        digest = hashlib.sha256(member.read()).hexdigest()
    assert digest == PINNED_OPENCODE_SHA256, digest
    with tarfile.open(archive) as bundle:
        extracted = bundle.extractfile("package/bin/opencode")
        assert extracted is not None
        binary = directory / "opencode"
        binary.write_bytes(extracted.read())
    binary.chmod(0o700)
    return binary


@pytest.mark.skipif(
    os.environ.get("STATEPORT_LIVE_FREE_MODEL", "").strip() not in {"1", "true", "yes"},
    reason="the live free-model row is opt-in (STATEPORT_LIVE_FREE_MODEL=1)",
)
def test_a_real_free_model_edit_runs_in_the_sandbox(sandbox) -> None:
    """One real free-model edit through the pinned opencode, end to end."""
    _require_sandbox()
    binary = _download_pinned_opencode(sandbox["tmp_path"] / "download")
    notes = sandbox["workdir"] / "notes.md"
    notes.write_text("# Notes\n\nteh quick brown fox jumps over teh lazy dog.\n", encoding="utf-8")

    model = None
    listing = subprocess_run(
        [str(binary), "models"], cwd=sandbox["tmp_path"], timeout=180
    )
    available = {
        line.strip() for line in listing.splitlines() if line.strip().endswith("-free")
    }
    for candidate in LIVE_MODEL_CANDIDATES:
        if candidate in available:
            model = candidate
            break
    assert model is not None, f"no free model in the catalogue: {sorted(available)[:10]}"

    route = SandboxRoute(
        harness="opencode",
        harness_binary=binary,
        model=model,
        allow_hosts=OPENCODE_FREE_ROUTE_HOSTS,
        credential_file=None,
        tools="edit",
    )
    # The live row uses the real catalogue fetch.
    agent_sandbox._catalogue_fetcher = agent_sandbox._refresh_catalogue
    result = run_in_sandbox(
        workdir=sandbox["workdir"],
        prompt="Fix the typo in notes.md: replace 'teh' with 'the'. Do not change anything else.",
        route=route,
        timeout_seconds=300,
        output_limit_bytes=1 << 20,
    )
    assert result.status == "completed", result.final_text
    assert "the quick brown fox" in notes.read_text(encoding="utf-8")
    print(
        "live free-model edit:",
        json.dumps(
            {
                "model": model,
                "durationSeconds": result.duration_seconds,
                "events": result.events,
                "tokens": result.tokens,
                "egress": list(result.egress),
                "notes": notes.read_text(encoding="utf-8"),
                "finalText": result.final_text[:400],
            },
            sort_keys=True,
        ),
    )


def subprocess_run(argv, *, cwd, timeout) -> str:
    import subprocess

    return subprocess.run(
        argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    ).stdout


def _client_hello(server_name: str | None) -> bytes:
    """The first bytes a real TLS client sends (Python's own TLS stack, no network)."""

    import ssl

    context = ssl.create_default_context()
    if server_name is None:
        context.check_hostname = False
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_hostname=server_name)
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    return outgoing.read()


def test_the_proxy_reads_the_server_name_a_tls_client_asks_for() -> None:
    from stateport_persistent_app import agent_sandbox as sandbox

    hello = _client_hello("opencode.ai")
    assert sandbox._client_hello_complete(hello)
    assert sandbox._client_hello_sni(hello) == "opencode.ai"
    assert sandbox._client_hello_sni(_client_hello("Developers.Cloudflare.com")) == "developers.cloudflare.com"
    assert sandbox._client_hello_sni(_client_hello(None)) is None
    # A ClientHello split across TCP reads is complete only once every byte is in.
    assert not sandbox._client_hello_complete(hello[:20])


@pytest.mark.parametrize("data", [b"GET / HTTP/1.1\r\nHost: opencode.ai\r\n\r\n", b"\x17\x03\x03\x00\x05hello",
                                  b"\x16\x03\x01\x00\x04\x02\x00\x00\x00"])
def test_the_proxy_refuses_anything_but_a_tls_client_hello(data: bytes) -> None:
    from stateport_persistent_app import agent_sandbox as sandbox

    with pytest.raises(sandbox._Deny):
        sandbox._client_hello_sni(data)
