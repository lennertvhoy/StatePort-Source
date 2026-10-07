"""The restart leg must adopt the FIRST start's durable execution identity.

Measured 2026-09-27T05:36Z and again at 05:49Z: the resumed service child called
`tempfile.mkdtemp` for its execution-daemon root, so it booted a different
execution host with a different random suffix and an empty workload ledger,
while `live-core.spec.ts` still held the workload ids captured from the first
start. The journey therefore read `['absent','absent','absent']` and looked
like a product restart-survival failure when nothing had been lost: the
fixture had discarded the durable state, so survival was excluded by
construction rather than measured.

These tests pin the DECISION the repair makes, not the daemon boot that
follows it, so they need no Podman, no container and no service.
"""
from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "apps" / "web" / "tests" / "live-core-fixture.py"


# apps/web/tests/live-core-fixture.py publishes the daemon's bindings, format,
# control socket and grant identity with bare os.environ assignments inside
# _application_workspace_daemon (lines 735-743 and 751-752). Those writes are
# invisible to the monkeypatch.setitem calls that restore every sys.modules stub
# above, so without this guard the stubbed format "stub/format" — which is
# neither .../v1 nor .../v2 — survives for the rest of the session, and
# stateport_persistent_app.execution_host_proxy._bindings() then rejects it on
# its first line. Measured: this file followed by
# scripts/test_execution_host_proxy.py is 57 failed where the proxy alone is 97
# passed, and the failures are the correct fail-closed guard
# workspace_bindings_invalid where execution_unavailable was expected.
#
# MEASURED 2026-09-27, and this comment previously overclaimed: it said "The list
# is every key the fixture writes" while the list held SEVEN of the NINE keys
# live-core-fixture.py assigns with a bare os.environ[...] . The two missing ones
# are below, and both are read by product code, so each was a live residual of
# the exact class this guard exists to close:
#   STATEPORT_WORKSPACE_AUTHORITY_DIRECTORY  execution_host_proxy.py:244
#   STATEPORT_REPOSITORY_ROOTS              repository_import.py:134
# The first is read by the very module whose poisoned format this guard was
# written to protect. The lesson is the one the sentence above already tells: the
# earlier controller attempt snapshotted five of eight and still leaked two, and
# a list that asserts completeness while being incomplete is the same failure
# wearing a claim of having been learned.
#
# A correction to my own first attempt at this, recorded because the test below
# caught it immediately: I first added a third key, STATEPORT_UI_ENGINE_ENV, on
# the strength of a grep that counted os.environ["KEY"] without requiring an
# assignment. That key is only ever READ, at live-core-fixture.py:637, never
# written, so it was a read I miscounted as a write. Both the number and the
# list are now derived from the fixture by the test at the end of this file, so
# neither can drift again without something going red.
_LIVE_CORE_ENV_KEYS = (
    "STATEPORT_APPLICATION_WORKSPACE_BINDINGS",
    "STATEPORT_APPLICATION_WORKSPACE_BINDINGS_FORMAT",
    "STATEPORT_EXECUTION_SOCKET",
    "STATEPORT_EXECUTION_GRANT_ID",
    "STATEPORT_EXECUTION_GRANT_DIGEST",
    "STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE",
    "STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST",
    "STATEPORT_WORKSPACE_AUTHORITY_DIRECTORY",
    "STATEPORT_REPOSITORY_ROOTS",
)


@pytest.fixture(autouse=True)
def _isolate_live_core_daemon_environment():
    """Restore every environment key the live-core fixture writes directly."""
    saved = {key: os.environ.get(key) for key in _LIVE_CORE_ENV_KEYS}
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _load_fixture():
    import importlib.util

    spec = importlib.util.spec_from_file_location("live_core_fixture_under_test", FIXTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Never leave the exec'd fixture, or the real packages it imported against
    # our stubs stay cached for whatever runs next.
    sys.modules.pop("live_core_fixture_under_test", None)
    return module


def _install_stubs(monkeypatch, *, recorded_root: Path | None):
    """Stub only what the identity decision touches, so no daemon is booted."""
    booted: dict[str, object] = {}

    class DaemonHandle:
        def __init__(self, root, socket_root=None):
            self.root = Path(root)
            self.socket_root = Path(socket_root) if socket_root else None
            self.socket_path = str(self.socket_root / "s.sock")
            self.state_dir = self.root / "state"
            self.env = dict

        def boot(self):
            booted["root"] = self.root

        def stop(self):
            return None

    def _governed_engine_environment(root, environment):
        booted["governed_root"] = Path(root)
        return environment, {"scope": "stub"}

    def _workspace_spec(workload_id, parameters=None):
        return {"workloadId": workload_id, "parameters": parameters or {}}

    def _grant_document(grant_id, spec):
        # Deterministic in the spec, exactly as the real one is, so a resumed
        # start recomputing the digest is a real check and not a tautology.
        return {"grantId": grant_id, "workloadId": spec["workloadId"], "parameters": spec.get("parameters", {})}

    def _provision_grant(handle, spec):
        doc = _grant_document("grant-" + spec["workloadId"], spec)
        grants_dir = handle.state_dir / "grants"
        grants_dir.mkdir(parents=True, exist_ok=True)
        (grants_dir / f"{doc['grantId']}.json").write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
        return doc

    daemon = types.ModuleType("test_execution_host_daemon")
    daemon.DaemonHandle = DaemonHandle
    daemon._workspace_spec = _workspace_spec
    daemon._provision_grant = _provision_grant
    daemon._grant_document = _grant_document
    daemon._governed_engine_environment = _governed_engine_environment
    daemon.WORKLOAD_IMAGE = "stub/image"

    workspaces = types.ModuleType("execution_host.application_workspaces")
    workspaces.FORMAT = "stub/format"
    workspaces.TRANSPORT_FORMAT = "stub/transport"
    workspaces.catalog_identity = lambda entry: "digest"
    # The ordinary cleanup imports this at entry; a stub keeps the test off the
    # real engine while still exercising the full removal path.
    workspaces.read_binding_transport = lambda manifest: []

    contract = types.ModuleType("execution_host.daemon_contract")
    contract.canonical_digest = lambda value: "digest"
    contract.validate_workload_spec = lambda spec: spec
    contract.workspace_template_for_image = lambda image: {"image": image}

    proxy = types.ModuleType("stateport_persistent_app.execution_host_proxy")
    proxy.ExecutionHostProxy = object

    def _prepare_workspace_source_seed(entry, spec):
        spec["parameters"]["sourceSeed"] = {"reviewDigest": "seed-" + spec["workloadId"]}
        return spec

    proxy.prepare_workspace_source_seed = _prepare_workspace_source_seed

    for name, module in (
        ("test_execution_host_daemon", daemon),
        ("execution_host.application_workspaces", workspaces),
        ("execution_host.daemon_contract", contract),
        ("stateport_persistent_app.execution_host_proxy", proxy),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    # EVERY stub must go through monkeypatch, or it survives the test and
    # poisons the next suite. A bare sys.modules.setdefault here left a stub
    # `execution_host` package behind, which broke 14 tests in the adjacent
    # controller suite when the suites ran together while every suite passed in
    # isolation. The leak was only exposed once a test made the fixture do more
    # real work, so it is recorded rather than merely fixed.
    monkeypatch.setitem(sys.modules, "execution_host", types.ModuleType("execution_host"))
    monkeypatch.setitem(sys.modules, "execution_host.application_workspaces", workspaces)
    monkeypatch.setitem(sys.modules, "execution_host.daemon_contract", contract)

    # The fixture's own cleanup reaches for the container engine; stub it so the
    # test can run the REAL function end to end without Podman.
    engine = types.ModuleType("execution_host.engine")
    engine.MANAGED_LABEL_KEY = "managed"
    engine.WORKLOAD_LABEL = "workload"
    engine.KIND_LABEL = "kind"

    class PodmanCliEngine:
        def __init__(self, *args, **kwargs):
            self.calls: list[str] = []

        def list_workloads(self):
            return []

        @staticmethod
        def _workspace_volume_claims(spec):
            return []

    engine.PodmanCliEngine = PodmanCliEngine
    monkeypatch.setitem(sys.modules, "execution_host.engine", engine)
    execution_host = sys.modules["execution_host"]
    monkeypatch.setattr(execution_host, "application_workspaces", workspaces, raising=False)
    monkeypatch.setattr(execution_host, "daemon_contract", contract, raising=False)
    monkeypatch.setattr(execution_host, "engine", engine, raising=False)
    return booted


def _app(data_root: Path):
    app = types.SimpleNamespace()
    app.layout = types.SimpleNamespace(data_root=data_root, config_root=data_root / "config")
    app.catalog = types.SimpleNamespace(
        get=lambda instance_id: {"applicationId": "app-" + instance_id, "instanceId": instance_id}
    )
    return app


def _templates():
    return [{"instanceId": "actual-projectstate-v6"}, {"instanceId": "actual-studystate"}]


def _write_record(data_root: Path, daemon_root: Path, workloads: dict[str, str]):
    record = data_root / "ui-workspace-fixture.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(
        json.dumps({"daemonRoot": str(daemon_root), "workloads": workloads}), encoding="utf-8"
    )
    return record


def _run(module, app, *, resume, monkeypatch, tmp_path):
    monkeypatch.setenv("STATEPORT_UI_ENGINE_ENV", "{}")
    monkeypatch.delenv("STATEPORT_UI_NO_DEFAULT_GRANT", raising=False)
    return module._application_workspace_daemon(
        app, Path(__file__).resolve().parents[1], types.SimpleNamespace(), _templates(), resume=resume
    )


def _first_start(module, app, monkeypatch):
    """Run a REAL fresh start so the durable side effects exist.

    A resumed start now READS the grant the first start left in the daemon
    state, so a test that hand-writes the record without the first start's
    durable grant is no longer modelling the sequence it claims to test. This
    performs the first start for real, with the same stubs, which is both
    simpler and a stronger model: the record, the daemon root and the grants
    are all produced by the code under test rather than by the test.
    """
    monkeypatch.setenv("STATEPORT_UI_ENGINE_ENV", "{}")
    monkeypatch.delenv("STATEPORT_UI_NO_DEFAULT_GRANT", raising=False)
    app.layout.data_root.mkdir(parents=True, exist_ok=True)
    cleanup = module._application_workspace_daemon(
        app, ROOT, types.SimpleNamespace(), _templates(), resume=False
    )
    record = json.loads((app.layout.data_root / "ui-workspace-fixture.json").read_text(encoding="utf-8"))
    return record["daemonRoot"], record["workloads"], cleanup

def test_resume_adopts_the_first_start_root_and_ids(monkeypatch, tmp_path):
    module = _load_fixture()
    data_root = tmp_path / "data"
    app = _app(data_root)
    _install_stubs(monkeypatch, recorded_root=None)
    first_root, recorded, _ = _first_start(module, app, monkeypatch)
    first_root = Path(first_root)
    booted = _install_stubs(monkeypatch, recorded_root=first_root)

    cleanup = _run(module, app, resume=True, monkeypatch=monkeypatch, tmp_path=tmp_path)
    try:
        # The SAME durable execution host, not a fresh random one.
        assert booted["root"] == first_root
        assert cleanup is not None
        manifest = json.loads((first_root / "application-bindings.json").read_text(encoding="utf-8"))
        bindings = {row["workload"]["workloadId"] for row in manifest["bindings"]}
        # The adopted identity, read from the record rather than re-derived.
        # The adopted identity is the one the REAL first start recorded, not a
        # hand-written constant, so this asserts adoption rather than a literal.
        assert recorded["actual-projectstate-v6"] in bindings
        # And nothing minted a new random suffix for the recorded instance.
        assert not any(name.startswith("ui-actual-projectstate-v6-") and name != recorded["actual-projectstate-v6"]
                       for name in bindings)
    finally:
        if callable(cleanup):
            # Deliberately NOT invoked: the fixture's cleanup shells out to podman
            # and reaps containers, which is the governed run's job, not this
            # unit's. Every dependency here is a stub, so nothing real leaks.
            pass


def test_resume_refuses_when_no_durable_record_exists(monkeypatch, tmp_path):
    module = _load_fixture()
    _install_stubs(monkeypatch, recorded_root=None)
    with pytest.raises(RuntimeError, match="no durable workspace fixture record"):
        _run(module, _app(tmp_path / "empty"), resume=True, monkeypatch=monkeypatch, tmp_path=tmp_path)


def test_resume_refuses_when_the_recorded_root_is_gone(monkeypatch, tmp_path):
    module = _load_fixture()
    data_root = tmp_path / "data"
    _write_record(data_root, tmp_path / "sp-ui-daemon-vanished", {})
    _install_stubs(monkeypatch, recorded_root=None)
    with pytest.raises(RuntimeError, match="recorded by the first start is absent"):
        _run(module, _app(data_root), resume=True, monkeypatch=monkeypatch, tmp_path=tmp_path)


def test_resume_refuses_rather_than_minting_for_an_unrecorded_instance(monkeypatch, tmp_path):
    """Adopting an identity must not degrade into inventing one."""
    module = _load_fixture()
    data_root = tmp_path / "data"
    app = _app(data_root)
    _install_stubs(monkeypatch, recorded_root=None)
    _first_start(module, app, monkeypatch)
    # Drop one instance from the durable record, so the refusal under test is the
    # unrecorded-identity one rather than the durable-grant one that now fires
    # first for an instance whose grant is absent.
    record_path = data_root / "ui-workspace-fixture.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["workloads"].pop("actual-studystate", None)
    record_path.write_text(json.dumps(record), encoding="utf-8")
    _install_stubs(monkeypatch, recorded_root=Path(record["daemonRoot"]))
    with pytest.raises(RuntimeError, match="names no workload for actual-studystate"):
        _run(module, app, resume=True, monkeypatch=monkeypatch, tmp_path=tmp_path)


def test_fresh_start_still_mints_its_own_identity(monkeypatch, tmp_path):
    """A first boot must NOT be made to adopt a record it never wrote."""
    module = _load_fixture()
    booted = _install_stubs(monkeypatch, recorded_root=None)
    data_root = tmp_path / "data"
    data_root.mkdir()

    cleanup = _run(module, _app(data_root), resume=False, monkeypatch=monkeypatch, tmp_path=tmp_path)
    try:
        root = booted["root"]
        assert root.name.startswith("sp-ui-daemon-")
        manifest = json.loads((root / "application-bindings.json").read_text(encoding="utf-8"))
        bindings = {row["workload"]["workloadId"] for row in manifest["bindings"]}
        # Derived from the fresh directory name, exactly as before the repair.
        assert "ui-actual-projectstate-v6-" + root.name.removeprefix("sp-ui-daemon-") in bindings
    finally:
        if callable(cleanup):
            # Deliberately NOT invoked: the fixture's cleanup shells out to podman
            # and reaps containers, which is the governed run's job, not this
            # unit's. Every dependency here is a stub, so nothing real leaks.
            pass


def _both_workloads():
    """A record naming every instance, as the first start writes."""
    return {
        "actual-projectstate-v6": "ui-actual-projectstate-v6-esbbb2uf",
        "actual-studystate": "ui-actual-studystate-esbbb2uf",
    }


def _write_resume_marker(data_root: Path):
    marker = data_root / "resume-expected.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"preserveForResume": True}), encoding="utf-8")
    return marker


def test_a_resumed_stop_preserves_the_workloads_and_consumes_the_marker(monkeypatch, tmp_path):
    """The stop the journey will resume must not reap what the leg asserts on.

    Without this the fixture's own cleanup force-removes the owned containers and
    volumes on SIGTERM, so the resumed daemon adopts nothing and the leg reads
    ['absent','absent','absent'] for subjects this harness had just deleted.
    """
    module = _load_fixture()
    data_root = tmp_path / "data"
    app = _app(data_root)
    _install_stubs(monkeypatch, recorded_root=None)
    first_root, _recorded, _ = _first_start(module, app, monkeypatch)
    marker = _write_resume_marker(data_root)
    _install_stubs(monkeypatch, recorded_root=Path(first_root))

    def _no_subprocess(*args, **kwargs):  # pragma: no cover - the guard is the assertion
        raise AssertionError("the preserved path reached the container engine")

    monkeypatch.setattr(module.subprocess, "run", _no_subprocess)

    cleanup = _run(module, _app(data_root), resume=True, monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert callable(cleanup)
    cleanup()
    # One-shot: the teardown at the end of the case must still clean up fully.
    assert not marker.exists()


def test_without_the_marker_the_ordinary_cleanup_still_reaches_the_engine(monkeypatch, tmp_path):
    """The complementary proof: without the signal nothing is skipped.

    If this ever stops reaching podman, the ordinary teardown has silently become
    a no-op and every case would leak its containers.
    """
    module = _load_fixture()
    data_root = tmp_path / "data"
    app = _app(data_root)
    _install_stubs(monkeypatch, recorded_root=None)
    first_root, _recorded, _ = _first_start(module, app, monkeypatch)
    assert not (data_root / "resume-expected.json").exists()
    _install_stubs(monkeypatch, recorded_root=Path(first_root))

    reached: list[list[str]] = []

    def _podman_absent(command, **kwargs):
        reached.append(list(command))
        # returncode 1 is "container not present", so the ordinary path runs to
        # completion without touching a real engine.
        return types.SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", _podman_absent)

    cleanup = _run(module, _app(data_root), resume=True, monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert callable(cleanup)
    cleanup()
    assert reached, "the ordinary cleanup stopped reaching the container engine"
    assert any("exists" in step for call in reached for step in call)


def test_the_preserved_path_precedes_every_removal_call():
    """Structural guard: the early return cannot sit after a removal."""
    import ast

    tree = ast.parse(FIXTURE.read_text(encoding="utf-8"))
    outer = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_application_workspace_daemon"
    )
    cleanup = next(
        node for node in ast.walk(outer)
        if isinstance(node, ast.FunctionDef) and node.name == "cleanup"
    )
    returns = [node.lineno for node in ast.walk(cleanup) if isinstance(node, ast.Return)]
    removals = [
        node.lineno for node in ast.walk(cleanup)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"run", "rm"}
    ]
    assert returns, "the preserved path must return before touching the engine"
    assert removals, "the ordinary path must still remove containers and volumes"
    assert min(returns) < min(removals), (
        f"the preserved return at line {min(returns)} does not precede the first "
        f"removal at line {min(removals)}"
    )


# ── governed-containers.conf must survive a resumed start in a reused root ──
#
# Measured 2026-09-27T06:06Z: with the daemon root correctly reused, the resumed
# child died at test_execution_host_daemon.py:95 with
#   FileExistsError: .../sp-ui-daemon-z4xpeym7/governed-containers.conf
# because the overlay was created with exclusive mode "x". The restart leg never
# reached its assertions. The exclusive create is deliberate anti-clobber, so the
# repair admits reuse only under exact verification.


def _daemon_module(monkeypatch):
    """Load the REAL daemon module, isolated from the stubs the tests above install.

    `_install_stubs` leaves a bare, non-package `execution_host` in sys.modules
    (its setdefault is not undone by monkeypatch), so without this purge these
    tests would pass alone and fail in the suite, against a stub instead of the
    code they claim to cover. monkeypatch restores the previous entries at
    teardown, so the purge does not leak the other way either.
    """
    import importlib.util

    for key in [k for k in sys.modules if k == "execution_host" or k.startswith("execution_host.")]:
        monkeypatch.delitem(sys.modules, key, raising=False)
    monkeypatch.delitem(sys.modules, "test_execution_host_daemon", raising=False)
    path = Path(__file__).resolve().parents[1] / "scripts" / "test_execution_host_daemon.py"
    spec = importlib.util.spec_from_file_location("daemon_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _overlay_env(monkeypatch, root: Path):
    module = _daemon_module(monkeypatch)
    monkeypatch.setattr(module, "_booked_scope", lambda: "stub-scope")
    return module, module._governed_engine_environment(root, {})


EXPECTED_OVERLAY = '[containers]\ncgroups="split"\n'


def test_first_boot_creates_the_overlay_exclusively(monkeypatch, tmp_path):
    _, (environment, scope) = _overlay_env(monkeypatch, tmp_path)
    overlay = tmp_path / "governed-containers.conf"
    assert overlay.read_text(encoding="utf-8") == EXPECTED_OVERLAY
    assert environment["CONTAINERS_CONF_OVERRIDE"] == str(overlay)
    assert scope == "stub-scope"


def test_resumed_start_reuses_an_identical_overlay(monkeypatch, tmp_path):
    """The case that killed the run: the overlay already exists and is correct."""
    (tmp_path / "governed-containers.conf").write_text(EXPECTED_OVERLAY, encoding="utf-8")
    _, (environment, _) = _overlay_env(monkeypatch, tmp_path)
    assert (tmp_path / "governed-containers.conf").read_text(encoding="utf-8") == EXPECTED_OVERLAY
    assert environment["CONTAINERS_CONF_OVERRIDE"] == str(tmp_path / "governed-containers.conf")


def test_resumed_start_refuses_an_edited_overlay(monkeypatch, tmp_path):
    """Reuse must not become adoption: differing content is refused, not replaced."""
    (tmp_path / "governed-containers.conf").write_text('[containers]\ncgroups="no-conmon"\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="differs from the fixture's own"):
        _overlay_env(monkeypatch, tmp_path)
    # And the planted content is left exactly as it was, not silently rewritten.
    assert (tmp_path / "governed-containers.conf").read_text(encoding="utf-8") == '[containers]\ncgroups="no-conmon"\n'


def test_resumed_start_refuses_a_symlinked_overlay(monkeypatch, tmp_path):
    """The exclusive create also refused symlinks; reuse must not start following them."""
    elsewhere = tmp_path / "elsewhere.conf"
    elsewhere.write_text(EXPECTED_OVERLAY, encoding="utf-8")
    (tmp_path / "governed-containers.conf").symlink_to(elsewhere)
    with pytest.raises(RuntimeError, match="is not a regular file"):
        _overlay_env(monkeypatch, tmp_path)


def test_a_resumed_start_refuses_when_the_durable_grant_is_missing(monkeypatch, tmp_path):
    """The resumed start must READ the grant, not re-provision it.

    Re-provisioning wrote identical bytes to the identical path, so the
    observable outcome was indistinguishable while a product-side grant loss
    was silently masked. This fails on any code that provisions on resume.
    """
    module = _load_fixture()
    first_root = tmp_path / "sp-ui-daemon-esbbb2uf"
    first_root.mkdir()
    data_root = tmp_path / "data"
    _write_record(data_root, first_root, _both_workloads())
    _install_stubs(monkeypatch, recorded_root=first_root)
    with pytest.raises(RuntimeError, match="no durable grant"):
        _run(module, _app(data_root), resume=True, monkeypatch=monkeypatch, tmp_path=tmp_path)


def test_the_resume_branch_never_reprovisions_a_grant():
    """Structural guard on the property above, so it cannot regress silently."""
    import ast

    tree = ast.parse(FIXTURE.read_text(encoding="utf-8"))
    calls = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    # One provisioning call exists, on the fresh-start path only.
    assert calls.count("_provision_grant") == 1, (
        "the fixture must provision a grant exactly once, on a fresh start"
    )
    source = FIXTURE.read_text(encoding="utf-8")
    assert "grant survival is unmeasured rather than assumed" in source, (
        "the durable-grant refusal must be present and named"
    )


def test_the_restart_flags_are_computed_and_not_asserted():
    """The two booleans may not be hard-coded, and may not be typed as `true`.

    An independent reconstruction withdrew the claim that the restart object is
    measured rather than hard-coded because these two were literals. This fails
    if either regresses to a constant, and the type is `boolean` so a constant
    cannot masquerade as a measurement at the type level either.
    """
    spec = ROOT / "apps" / "web" / "tests" / "live-core.spec.ts"
    source = spec.read_text(encoding="utf-8")
    for field in ("measured", "resumedDurableFixtureState"):
        assert f"{field}: true" not in source, f"{field} is hard-coded true again"
        assert f"{field}: boolean" in source, f"{field} must be typed boolean"
    # And both must be derived from named observations, not invented.
    assert "resumePreserved!.preserved" in source
    assert "previousExitResult !== null" in source
    assert "service.url !== previousUrl" in source


def test_the_restart_log_assertion_cannot_pass_on_a_previous_runs_file():
    """The bare existsSync was satisfied by any leftover file.

    startService opens service-restarted.log in APPEND mode, so a file from an
    earlier run made the assertion unfalsifiable. It must now compare an
    observable captured BEFORE the stop, so only this restart can satisfy it.
    """
    spec = ROOT / "apps" / "web" / "tests" / "live-core.spec.ts"
    source = spec.read_text(encoding="utf-8")
    assert "restartLogMtimeBefore" in source, (
        "the pre-restart observable must be captured, or the assertion is unfalsifiable"
    )
    assert "statSync(restartLogPath).mtimeMs > restartLogMtimeBefore" in source, (
        "the assertion must compare the mtime against the value captured before the stop"
    )
    assert "existsSync(path.join(ARTIFACT_ROOT, 'service-restarted.log'))" not in source, (
        "the bare existsSync on the restart log must be gone"
    )
    # And the capture must happen before the stop, not after the restart.
    capture = source.index("const restartLogMtimeBefore")
    stop = source.index("await stopChild(previousChild)", capture)
    restart = source.index("service = await startService(true)", stop)
    assert capture < stop < restart, "the observable must be captured before the stop and asserted after the restart"


def test_the_daemon_environment_guard_covers_every_key_the_fixture_writes():
    """The guard's key list must be DERIVED from the fixture, not hand-kept.

    This exists because the list was hand-kept and was wrong: it held seven of
    the ten keys live-core-fixture.py assigns with a bare ``os.environ[...]``,
    while a comment beside it claimed the list was every key. One of the three
    omissions, ``STATEPORT_WORKSPACE_AUTHORITY_DIRECTORY``, is read by
    ``execution_host_proxy.py:244`` -- the same module whose poisoned format this
    guard was added to protect.

    Deriving both sides from the source means a future key added to the fixture
    fails here instead of quietly reopening the leak. A guard that is only as
    complete as the last time somebody remembered to check is the defect this
    guard was written to remove, one level up.
    """
    import re

    fixture = FIXTURE.read_text(encoding="utf-8")
    written = set(re.findall(r'os\.environ\["([A-Z_]+)"\]\s*=', fixture))
    guarded = set(_LIVE_CORE_ENV_KEYS)

    unguarded = written - guarded
    assert not unguarded, (
        "the live-core fixture assigns these keys with a bare os.environ[...] and "
        "the daemon environment guard does not restore them, so they outlive the "
        f"test that wrote them: {sorted(unguarded)}"
    )

    stale = guarded - written
    assert not stale, (
        "_LIVE_CORE_ENV_KEYS lists keys the fixture no longer writes, so the guard "
        f"is carrying dead entries: {sorted(stale)}"
    )
