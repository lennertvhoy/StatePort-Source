#!/usr/bin/env python3
import sys
import tempfile
from subprocess import CompletedProcess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/container-runner/src"))
from container_runner import ContainerExecutor, ExecutionPlan, ExecutorError
import container_runner.executor as executor_module


RUNNER_IMAGE = "stateport/runner@sha256:" + ("1" * 64)


def test_plan_requires_isolation_and_is_non_mutating() -> None:
    plan = ExecutionPlan("/templates", "/instances/i1", "/tmp/run-1", "lease-1")
    data = plan.to_dict()
    assert data["template"]["readOnly"] is True
    assert data["network"]["enabled"] is False
    assert data["instance"]["writable"] is False
    assert data["apply"] is False
    assert data["security"]["runAsNonRoot"] is True
    assert ExecutionPlan.from_dict(data) == plan


def test_persisted_plan_parser_rejects_relaxed_or_unknown_controls() -> None:
    safe = ExecutionPlan("/templates", "/instances/i1", "/tmp/run-1", "lease-1").to_dict()
    unsafe_values = []
    for section, field, value in (
        ("network", "enabled", True),
        ("security", "rootReadOnly", False),
        ("template", "readOnly", False),
        ("instance", "writable", True),
    ):
        candidate = {key: dict(item) if isinstance(item, dict) else item for key, item in safe.items()}
        candidate[section][field] = value
        unsafe_values.append(candidate)
    with_unknown = {**safe, "privileged": True}
    unsafe_values.append(with_unknown)
    for candidate in unsafe_values:
        try:
            ExecutionPlan.from_dict(candidate)
        except ValueError:
            pass
        else:
            raise AssertionError("persisted plan must not relax or extend isolation controls")


def test_plan_rejects_network_and_path_collisions() -> None:
    for plan in (
        ExecutionPlan("/same", "/same", "/runtime", "lease"),
        ExecutionPlan("/template", "/instance", "/template", "lease"),
        ExecutionPlan("/template", "/instance", "/instance", "lease"),
        ExecutionPlan("/t", "/i", "/r", "lease", network_enabled=True),
    ):
        try:
            plan.validate()
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe execution plan must fail closed")


def test_plan_rejects_runtime_overlap_with_template_or_instance() -> None:
    plans = (
        ExecutionPlan("/workspace/template", "/workspace/instance", "/workspace/template/runtime", "lease"),
        ExecutionPlan("/workspace/runtime/template", "/workspace/instance", "/workspace/runtime", "lease"),
        ExecutionPlan("/workspace/template", "/workspace/instance", "/workspace/instance/runtime", "lease"),
        ExecutionPlan("/workspace/template", "/workspace/runtime/instance", "/workspace/runtime", "lease"),
    )
    for plan in plans:
        try:
            plan.validate()
        except ValueError as exc:
            assert "runtime path must not overlap" in str(exc)
        else:
            raise AssertionError("runtime must not overlap template or instance paths")


def test_executor_builds_fixed_isolation_command_and_stays_disabled() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        template = root / "template"
        instance = root / "instance"
        runtime = root / "runtime"
        template.mkdir()
        instance.mkdir()
        plan = ExecutionPlan(str(template), str(instance), str(runtime), "lease-1")
        command = ContainerExecutor(engine="docker", image="stateport/test:local").build_command(plan, ["python3", "-m", "runner"])
        assert "--network=none" in command and "--cap-drop=ALL" in command
        assert "--read-only" in command and "--user" in command
        assert "--name" in command
        assert "--pids-limit" in command and "--memory" in command
        assert "--cpus" in command and "--ulimit" in command
        podman_command = ContainerExecutor(engine="podman", image="stateport/test:local").build_command(plan, ["python3"])
        assert "--userns=keep-id" in podman_command
        assert any("dst=/stateport/template,readonly,relabel=shared" in item for item in podman_command)
        assert any("dst=/stateport/instance,readonly,relabel=private" in item for item in podman_command)
        try:
            ContainerExecutor(engine="docker").execute(plan, ["python3"], approval_id="approval-1")
        except ExecutorError as exc:
            assert "disabled" in str(exc)
        else:
            raise AssertionError("executor must be disabled by default")
        try:
            ContainerExecutor(engine="docker").build_command(plan, ["--privileged"])
        except ExecutorError:
            pass
        else:
            raise AssertionError("command must not override isolation")
        for invalid_user in ("0:0", "0:1000", "root", "1000"):
            try:
                ContainerExecutor(engine="docker", user=invalid_user)
            except ExecutorError:
                pass
            else:
                raise AssertionError("executor user must be a non-root numeric uid:gid")
        for invalid_image in ("--privileged", "-v", "bad image"):
            try:
                ContainerExecutor(engine="docker", image=invalid_image)
            except ExecutorError:
                pass
            else:
                raise AssertionError("executor image must not be parsed as an engine option")
        try:
            ContainerExecutor(
                engine="docker",
                image="stateport/runner:local",
                allow_execution=True,
            )
        except ExecutorError as exc:
            assert "immutable" in str(exc)
        else:
            raise AssertionError("enabled execution must require an immutable image")


def test_executor_rejects_symlinked_mount_parents() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        template = root / "template"
        instance = root / "instance"
        real_runtime_parent = root / "real-runtime"
        template.mkdir()
        instance.mkdir()
        real_runtime_parent.mkdir()
        (root / "runtime-parent").symlink_to(real_runtime_parent, target_is_directory=True)
        plan = ExecutionPlan(str(template), str(instance), str(root / "runtime-parent" / "runtime"), "lease-1")
        try:
            ContainerExecutor(engine="docker").build_command(plan, ["python3"])
        except ExecutorError:
            pass
        else:
            raise AssertionError("executor must reject symlinked mount parents")


def test_executor_preserves_preexisting_runtime_and_cleans_only_its_own() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        template = root / "template"
        instance = root / "instance"
        runtime = root / "runtime"
        template.mkdir()
        instance.mkdir()
        runtime.mkdir()
        marker = runtime / "caller-owned.txt"
        marker.write_text("preserve", encoding="utf-8")
        plan = ExecutionPlan(str(template), str(instance), str(runtime), "lease-1")
        executor = ContainerExecutor(
            engine="docker", image=RUNNER_IMAGE, allow_execution=True
        )
        original_which = executor_module.shutil.which
        original_run = executor_module.subprocess.run
        original_bounded = executor._run_bounded
        executor_module.shutil.which = lambda engine: f"/usr/bin/{engine}"
        executor._run_bounded = lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("preexisting runtime must be rejected before process execution")
        )
        try:
            try:
                executor.execute(plan, ["python3"], approval_id="approval-1")
            except ExecutorError as exc:
                assert "must not already exist" in str(exc)
            else:
                raise AssertionError("preexisting runtime must fail closed")
            assert marker.read_text(encoding="utf-8") == "preserve"

            marker.unlink()
            runtime.rmdir()
            try:
                executor.execute(plan, ["--privileged"], approval_id="approval-2")
            except ExecutorError:
                pass
            else:
                raise AssertionError("invalid commands must fail")
            assert not runtime.exists()

            executor._run_bounded = lambda argv: CompletedProcess(
                args=argv, returncode=0, stdout="ok", stderr=""
            )
            executor_module.subprocess.run = lambda *args, **kwargs: CompletedProcess(
                args=args[0], returncode=1, stdout="", stderr="No such container"
            )
            result = executor.execute(plan, ["python3"], approval_id="approval-3")
            assert result.returncode == 0
            assert not runtime.exists()
        finally:
            executor_module.shutil.which = original_which
            executor_module.subprocess.run = original_run
            executor._run_bounded = original_bounded


def test_executor_attempts_named_container_cleanup_after_timeout() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        template = root / "template"
        instance = root / "instance"
        runtime = root / "runtime"
        template.mkdir()
        instance.mkdir()
        plan = ExecutionPlan(str(template), str(instance), str(runtime), "lease-timeout")
        executor = ContainerExecutor(
            engine="docker",
            image=RUNNER_IMAGE,
            allow_execution=True,
            timeout_seconds=1,
        )
        original_which = executor_module.shutil.which
        original_run = executor_module.subprocess.run
        original_bounded = executor._run_bounded
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            if tuple(argv[1:3]) == ("container", "inspect"):
                return CompletedProcess(argv, 1, "", "No such container")
            return CompletedProcess(argv, 0, "", "")

        executor_module.shutil.which = lambda engine: f"/usr/bin/{engine}"
        executor_module.subprocess.run = fake_run
        executor._run_bounded = lambda argv: (_ for _ in ()).throw(
            ExecutorError("container execution timed out")
        )
        try:
            try:
                executor.execute(plan, ["python3"], approval_id="approval-timeout")
            except ExecutorError as exc:
                assert "timed out" in str(exc)
            else:
                raise AssertionError("executor timeout must fail")
            assert any(call[1:3] == ("rm", "--force") for call in calls)
            assert not runtime.exists()
        finally:
            executor_module.shutil.which = original_which
            executor_module.subprocess.run = original_run
            executor._run_bounded = original_bounded


def test_executor_retains_runtime_when_orphan_cleanup_is_unconfirmed() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        template = root / "template"
        instance = root / "instance"
        runtime = root / "runtime"
        template.mkdir()
        instance.mkdir()
        executor = ContainerExecutor(
            engine="docker",
            image=RUNNER_IMAGE,
            allow_execution=True,
            timeout_seconds=1,
        )
        plan = ExecutionPlan(str(template), str(instance), str(runtime), "lease-orphan")
        original_which = executor_module.shutil.which
        original_run = executor_module.subprocess.run
        original_bounded = executor._run_bounded
        executor_module.shutil.which = lambda engine: f"/usr/bin/{engine}"
        executor._run_bounded = lambda argv: (_ for _ in ()).throw(
            ExecutorError("container execution timed out")
        )
        executor_module.subprocess.run = lambda argv, **kwargs: CompletedProcess(
            argv, 1, "", "daemon unavailable"
        )
        try:
            try:
                executor.execute(plan, ["python3"], approval_id="approval-orphan")
            except ExecutorError as exc:
                assert "cleanup could not be confirmed" in str(exc)
            else:
                raise AssertionError("unconfirmed cleanup must fail closed")
            assert runtime.is_dir()
        finally:
            executor_module.shutil.which = original_which
            executor_module.subprocess.run = original_run
            executor._run_bounded = original_bounded


def test_executor_caps_each_captured_output_stream() -> None:
    executor = ContainerExecutor(engine="docker", image=RUNNER_IMAGE)
    try:
        executor._run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1100000)"]
        )
    except ExecutorError as exc:
        assert "output exceeded" in str(exc)
    else:
        raise AssertionError("executor output must be bounded before loading in memory")


if __name__ == "__main__":
    test_plan_requires_isolation_and_is_non_mutating()
    test_persisted_plan_parser_rejects_relaxed_or_unknown_controls()
    test_plan_rejects_network_and_path_collisions()
    test_plan_rejects_runtime_overlap_with_template_or_instance()
    test_executor_builds_fixed_isolation_command_and_stays_disabled()
    test_executor_rejects_symlinked_mount_parents()
    test_executor_preserves_preexisting_runtime_and_cleans_only_its_own()
    test_executor_attempts_named_container_cleanup_after_timeout()
    test_executor_retains_runtime_when_orphan_cleanup_is_unconfirmed()
    test_executor_caps_each_captured_output_stream()
    print("PASS")
