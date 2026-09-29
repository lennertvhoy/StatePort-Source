from __future__ import annotations

import json
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from threading import Thread

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = spec_from_file_location("build_release_images", ROOT / "scripts/build_release_images.py")
assert spec and spec.loader
if spec.name in sys.modules:
    # Reuse the one registered copy. scripts/assemble_release_index.py imports
    # build_release_images normally, so executing the file here unconditionally would
    # leave the process holding two copies, and the 29 rebindings below could land on
    # the one assemble_release_index does not read.
    build_release_images = sys.modules[spec.name]
else:
    build_release_images = module_from_spec(spec)
    sys.modules[spec.name] = build_release_images
    spec.loader.exec_module(build_release_images)


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(204 if self.path == "/readyz" else 404)
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


def test_release_image_definitions_are_nonroot_hardened_and_typed() -> None:
    image_set = build_release_images.validate_definitions()
    assert image_set["registry"]["compatibilityFloor"] == "podman-5.0.0"
    for image_id, image in image_set["images"].items():
        assert image["runtimeUser"] not in {"0", "0:0", "root"}
        text = (ROOT / image["containerfile"]).read_text()
        assert "org.opencontainers.image.revision" in text
        assert "io.stateport.source.tree" in text
        assert "USER " + image["runtimeUser"] in text
        if image["role"] == "runtime-service":
            assert "HEALTHCHECK" in text
    assert image_set["componentPlacements"] == {
        "stateport-preview-gateway": {
            "imageId": "stateport-web",
            "trustDomain": "control",
            "processModel": "same-origin-web-process",
            "engineSocketAccess": "none",
            "networkAuthority": "authenticated-stateport-route-only",
            "readiness": "packaging-boundary-only-runtime-delivered-by-slice-c",
        },
        "stateport-updater": {
            "imageId": "stateport-worker",
            "trustDomain": "maintenance",
            "processModel": "separate-maintenance-service-shared-immutable-image",
            "engineSocketAccess": "none",
            "mutationAuthority": "typed-signed-update-plan-only",
            "readiness": "packaging-boundary-only-runtime-delivered-by-updater-slice",
        },
    }
    host = image_set["images"]["stateport-execution-host"]
    assert host["role"] == "stable-host-service"
    assert host["runtimeUser"] == "65532:65532"
    assert host["readOnlyRootCompatible"] is True
    host_containerfile = (ROOT / host["containerfile"]).read_text()
    assert 'CMD ["python3", "-m", "stateport_execution_host"]' in host_containerfile
    for control_plane in ("/run/podman/podman.sock", "/var/run/docker.sock", "/run/docker.sock"):
        assert control_plane not in host_containerfile
    assert re.findall(r"/[A-Za-z0-9._/-]*(?:podman|docker)\.sock", host_containerfile) == [
        "/run/stateport-engine/podman.sock"
    ]
    assert "stateport-execution-host" not in image_set.get("blockedComponents", {})
    assert "podman.sock" not in (ROOT / "apps/web/Dockerfile").read_text()
    assert "podman.sock" not in (ROOT / "apps/worker/Dockerfile").read_text()


def test_every_shipped_image_declares_read_only_root_compatibility() -> None:
    # Regression (2026-08-02): the release assembler hard-requires
    # readOnlyRootCompatible and stamps readOnlyRoot: true into the signed
    # release index for every shipped image, so a `false` declaration blocks
    # assembly and, worse, would make the signed contract lie if bypassed.
    # stateport-dev-workspace carried a stale `false` even though its proven
    # runtime shape (--read-only plus tmpfs /tmp and writable home/workspace
    # volumes, the shape the execution enforcer and adapters already use)
    # passes a full shell workflow smoke with root writes refused.
    image_set = build_release_images.validate_definitions()
    for image_id, image in image_set["images"].items():
        assert image["readOnlyRootCompatible"] is True, image_id


def test_packaged_health_probe_is_executable_bounded_and_supports_http_and_unix(
    tmp_path: Path,
) -> None:
    probe = ROOT / "images/bin/stateport-healthcheck"
    # Git versions only the executable bit (100755), never 0o555, so a clean
    # checkout materializes 0o755. The version-controlled guarantee is the
    # index mode; the shipped read-only guarantee is the Dockerfile chmod.
    index_mode = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-s", "images/bin/stateport-healthcheck"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[0]
    assert index_mode == "100755"
    assert stat.S_IMODE(probe.stat().st_mode) & 0o100
    for dockerfile in ROOT.glob("apps/*/Dockerfile"):
        text = dockerfile.read_text(encoding="utf-8")
        if "COPY images/bin/stateport-healthcheck" in text:
            assert "chmod 0555 /usr/local/bin/stateport-healthcheck" in text, dockerfile
    subprocess.run(["/bin/sh", "-n", str(probe)], check=True)

    unix_path = tmp_path / "health.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(unix_path))
        subprocess.run(
            [str(probe), "--kind", "unix-socket", "--path", str(unix_path)],
            check=True,
        )

    server = ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        subprocess.run(
            [
                str(probe),
                "--kind",
                "http",
                "--host",
                "127.0.0.1",
                "--port",
                str(server.server_port),
                "--path",
                "/readyz",
            ],
            check=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    refused = subprocess.run(
        [
            str(probe),
            "--kind",
            "http",
            "--host",
            "example.invalid",
            "--port",
            "80",
            "--path",
            "/",
        ],
        check=False,
    )
    assert refused.returncode == 2


def test_agent_run_wrapper_is_executable_shell_clean_and_pinned_in_dev_workspace() -> None:
    # The dev-workspace image ships the image-side OpenCode entrypoint. It must
    # stay a world-readable executable (git only versions the 100755 bit), pass
    # a POSIX syntax check, be copied and chmod'ed 0555 by the recipe, and be
    # declared as packaged content for that profile.
    wrapper = ROOT / "images/bin/stateport-agent-run"
    index_mode = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-s", "images/bin/stateport-agent-run"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[0]
    assert index_mode == "100755"
    assert stat.S_IMODE(wrapper.stat().st_mode) & 0o100
    subprocess.run(["/bin/sh", "-n", str(wrapper)], check=True)

    recipe = (ROOT / "images/stateport-dev-workspace/Containerfile").read_text(encoding="utf-8")
    assert "COPY images/bin/stateport-agent-run /usr/local/bin/stateport-agent-run" in recipe
    assert "chmod 0555 /usr/local/bin/stateport-agent-run" in recipe
    content = yaml.safe_load((ROOT / "images/packaged-content.v1.yaml").read_text(encoding="utf-8"))
    assert "images/bin/stateport-agent-run" in content["profiles"]["stateport-dev-workspace"][
        "finalImageSources"
    ]


def test_build_plan_is_double_build_digest_only_and_podman_493_compatible() -> None:
    image_set = build_release_images.validate_definitions()
    identity = build_release_images.SourceIdentity(
        "b" * 40, "c" * 40, "0.2.0-alpha.1", "2026-08-01T00:00:00Z", 1785542400
    )
    context = Path("/tmp/stateport-test-release-context")
    digests = Path("/tmp/stateport-test-release-digests")
    commands = build_release_images.build_commands(
        image_set,
        identity,
        registry="127.0.0.1:5000",
        context_root=context,
        digest_root=digests,
    )
    builds = [
        command
        for command in commands
        if Path(command[0]).name == "podman" and command[1] == "build"
    ]
    assert len(builds) == len(image_set["images"]) * 2
    assert all(
        "--no-cache" in command
        and "--pull=never" in command
        and "--platform" in command
        and "--timestamp" in command
        and command[command.index("--format") + 1] == "docker"
        for command in builds
    )
    assert all("io.stateport.release.build" not in " ".join(command) for command in builds)
    pushes = [
        command
        for command in commands
        if Path(command[0]).name == "podman" and command[1] == "push"
    ]
    assert len(pushes) == len(builds)
    assert all("--tls-verify=false" in command for command in pushes)
    for command in pushes:
        digest_file = Path(command[command.index("--digestfile") + 1])
        assert digest_file.is_relative_to(digests)
        assert not digest_file.is_relative_to(ROOT)
    pulls = build_release_images.base_pull_commands()
    assert len(pulls) == len(
        yaml.safe_load((ROOT / "config/container-base-images.yaml").read_text())["images"]
    )
    assert all("@sha256:" in command[-1] and "--platform" in command for command in pulls)
    definition_paths = [
        ROOT / "scripts/build_release_images.py",
        *(ROOT / item["containerfile"] for item in image_set["images"].values()),
    ]
    all_text = "\n".join(path.read_text() for path in definition_paths)
    assert "podman quadlet install" not in all_text
    for root in (ROOT / "images", ROOT / "release"):
        if root.exists():
            assert not any(
                path.suffix in {".pod", ".build", ".artifact"} for path in root.rglob("*")
            )


def test_locked_build_inputs_preflight_accepts_exact_repository_bytes() -> None:
    inputs = build_release_images.verify_locked_build_inputs()
    assert inputs["locks"]
    assert inputs["definitions"]


def test_locked_build_inputs_preflight_refuses_drifted_definition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = yaml.safe_load(
        (ROOT / "config/container-build-inputs.yaml").read_text(encoding="utf-8")
    )
    first_definition = sorted(inputs["definitions"])[0]
    inputs["definitions"][first_definition] = "sha256:" + "0" * 64
    drifted = tmp_path / "container-build-inputs.yaml"
    drifted.write_text(yaml.safe_dump(inputs, sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(build_release_images, "BUILD_INPUTS", drifted)
    with pytest.raises(
        build_release_images.ReleaseBuildError,
        match=f"locked definition drifted: {re.escape(first_definition)}",
    ):
        build_release_images.verify_locked_build_inputs()


def test_locked_build_inputs_preflight_refuses_missing_lock_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = yaml.safe_load(
        (ROOT / "config/container-build-inputs.yaml").read_text(encoding="utf-8")
    )
    first_lock = sorted(inputs["locks"])[0]
    inputs["locks"][first_lock]["path"] = str(tmp_path / "absent-lock-file.txt")
    missing = tmp_path / "container-build-inputs.yaml"
    missing.write_text(yaml.safe_dump(inputs, sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(build_release_images, "BUILD_INPUTS", missing)
    with pytest.raises(
        build_release_images.ReleaseBuildError,
        match=f"build-input lock {first_lock} is missing",
    ):
        build_release_images.verify_locked_build_inputs()


def test_builder_requires_an_external_content_addressed_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(build_release_images.BUILDER_DESCRIPTOR_ENV, raising=False)
    with pytest.raises(build_release_images.ReleaseBuildError, match="exact builder artifact"):
        build_release_images._load_builder_descriptor()

    descriptor = tmp_path / "builder.json"
    descriptor.write_text(
        '{"formatVersion":"stateport.release-builder-descriptor/v1",'
        '"name":"podman","executablePath":"/usr/bin/podman",'
        '"executableDigest":"sha256:' + "a" * 64 + '",'
        '"version":"5.8.4","artifact":{"uri":"operator://podman",'
        '"digest":"sha256:' + "a" * 64 + '"}}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv(build_release_images.BUILDER_DESCRIPTOR_ENV, str(descriptor))
    value, digest = build_release_images._load_builder_descriptor()
    assert value["artifact"]["uri"] == "operator://podman"
    assert digest == "sha256:" + hashlib.sha256(descriptor.read_bytes()).hexdigest()


def test_build_refuses_when_declared_healthcheck_is_lost(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    containerfile = tmp_path / "Dockerfile"
    containerfile.write_text(
        "FROM example/base@sha256:" + "a" * 64 + '\nHEALTHCHECK --interval=10s CMD ["true"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(build_release_images, "_run", lambda *_args, **_kwargs: "null")
    with pytest.raises(
        build_release_images.ReleaseBuildError, match="lost its declared HEALTHCHECK"
    ):
        build_release_images._verify_declared_healthcheck("registry.test/image:tag", containerfile)
    monkeypatch.setattr(
        build_release_images,
        "_run",
        lambda *_args, **_kwargs: '{"Test":["CMD","true"]}',
    )
    build_release_images._verify_declared_healthcheck("registry.test/image:tag", containerfile)
    containerfile.write_text("FROM example/base@sha256:" + "a" * 64 + "\n", encoding="utf-8")
    monkeypatch.setattr(
        build_release_images,
        "_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("no inspect")),
    )
    build_release_images._verify_declared_healthcheck("registry.test/image:tag", containerfile)


def test_source_identity_refuses_untracked_context_contamination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(arguments: list[str], **_kwargs: object) -> str:
        if arguments[:3] == ["git", "status", "--porcelain=v1"]:
            assert "--untracked-files=all" in arguments
            return "?? injected-source.py"
        raise AssertionError(arguments)

    monkeypatch.setattr(build_release_images, "_run", fake_run)
    with pytest.raises(build_release_images.ReleaseBuildError, match="including untracked"):
        build_release_images.source_identity("0.2.0-alpha.1")


def test_source_identity_accepts_exact_frozen_ancestor_and_records_controller(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "--quiet", "--initial-branch=main"], cwd=repository, check=True
    )
    (repository / "payload.txt").write_text("payload\n", encoding="utf-8")
    subprocess.run(["git", "add", "payload.txt"], cwd=repository, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=StatePort test",
            "-c",
            "user.email=stateport-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "payload",
        ],
        cwd=repository,
        check=True,
    )
    payload_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (repository / "control.txt").write_text("later control state\n", encoding="utf-8")
    subprocess.run(["git", "add", "control.txt"], cwd=repository, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=StatePort test",
            "-c",
            "user.email=stateport-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "control",
        ],
        cwd=repository,
        check=True,
    )
    controller_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    identity, controller = build_release_images._release_identities(
        "0.2.0-alpha.1", payload_commit, repository=repository
    )

    assert identity.commit == payload_commit
    assert identity.tree != controller.tree
    assert controller.commit == controller_commit
    assert controller.payloadRelationship == "payload-is-ancestor"


def test_source_identity_refuses_nonancestor_or_abbreviated_payload(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "--quiet", "--initial-branch=main"], cwd=repository, check=True
    )
    (repository / "payload.txt").write_text("payload\n", encoding="utf-8")
    subprocess.run(["git", "add", "payload.txt"], cwd=repository, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=StatePort test",
            "-c",
            "user.email=stateport-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "controller",
        ],
        cwd=repository,
        check=True,
    )
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    sibling = subprocess.run(
        ["git", "commit-tree", tree, "-m", "unrelated"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        env={
            "GIT_AUTHOR_NAME": "StatePort test",
            "GIT_AUTHOR_EMAIL": "stateport-test@example.invalid",
            "GIT_COMMITTER_NAME": "StatePort test",
            "GIT_COMMITTER_EMAIL": "stateport-test@example.invalid",
        },
    ).stdout.strip()

    with pytest.raises(
        build_release_images.ReleaseBuildError, match="must be an ancestor"
    ):
        build_release_images.source_identity(
            "0.2.0-alpha.1", sibling, repository=repository
        )
    with pytest.raises(
        build_release_images.ReleaseBuildError, match="one exact full commit"
    ):
        build_release_images.source_identity(
            "0.2.0-alpha.1", sibling[:12], repository=repository
        )


def test_registry_is_loopback_http_explicit_health_checked_and_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    class _Socket:
        def __enter__(self) -> "_Socket":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def setsockopt(self, *_args: object) -> None:
            return None

        def bind(self, address: tuple[str, int]) -> None:
            assert address == ("127.0.0.1", 5000)

    class _Response:
        status = 200

        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(build_release_images.socket, "socket", lambda *_args: _Socket())
    monkeypatch.setattr(build_release_images, "urlopen", lambda *_args, **_kwargs: _Response())
    monkeypatch.setattr(build_release_images, "_container_exists", lambda _name: False)
    registry_observation = {
        "imageId": "registry-image-id",
        "digest": build_release_images.REGISTRY_IMAGE.rsplit("@", 1)[1],
        "observedDigests": [
            build_release_images.REGISTRY_IMAGE.rsplit("@", 1)[1],
            "sha256:" + "d" * 64,
        ],
        "os": "linux",
        "architecture": "amd64",
        "variant": None,
    }
    monkeypatch.setattr(
        build_release_images, "_image_observation", lambda _reference: registry_observation
    )

    def fake_run(arguments: list[str], **kwargs: object) -> str:
        commands.append(arguments)
        return "container-id" if "run" in arguments and kwargs.get("capture") else ""

    monkeypatch.setattr(build_release_images, "_run", fake_run)
    identity = build_release_images.SourceIdentity(
        "b" * 40, "c" * 40, "0.2.0-alpha.1", "2026-08-01T00:00:00Z", 1785542400
    )
    record = build_release_images.start_local_registry(
        "127.0.0.1:5000",
        identity,
        storage=tmp_path / "registry-data",
        cgroup_parent="/test-governor-parent",
        registry_base={
            "baseId": "registry-2",
            "reference": build_release_images.REGISTRY_IMAGE,
            "indexDigest": build_release_images.REGISTRY_IMAGE.rsplit("@", 1)[1],
            "platformManifestDigest": "sha256:" + "d" * 64,
            "imageId": "registry-image-id",
            "verification": "exact-index-and-platform-manifest",
        },
    )
    registry_run = next(command for command in commands if "run" in command)
    assert registry_run[1:3] == ["--cgroup-manager=cgroupfs", "run"]
    assert registry_run[registry_run.index("--cgroup-parent") + 1] == "/test-governor-parent"
    stopped = build_release_images.stop_local_registry(record)
    assert record["transport"] == "insecure-http-loopback-only"
    assert record["retention"] == "running-until-explicit-proof-cleanup"
    assert stopped["cleanup"] == "container-removed"
    assert any(build_release_images.REGISTRY_IMAGE in command for command in commands)
    assert any(
        "--volume" in command and "/var/lib/registry:Z" in " ".join(command) for command in commands
    )
    assert any(command[1:3] == ["stop", "--time"] for command in commands)
    assert any(command[1:3] == ["rm", record["name"]] for command in commands)
    with pytest.raises(build_release_images.ReleaseBuildError, match="loopback"):
        build_release_images.validate_registry_endpoint("registry.example:5000")


def test_build_rejects_registry_before_podman_or_context_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(build_release_images, "source_identity", lambda _version: calls.append("identity"))
    monkeypatch.setattr(build_release_images, "verify_podman_builder", lambda: calls.append("podman"))
    monkeypatch.setattr(build_release_images, "prepare_output_root", lambda *_args, **_kwargs: calls.append("output"))
    with pytest.raises(build_release_images.ReleaseBuildError, match="loopback"):
        build_release_images.build_release(
            version="0.1.0-alpha.4", registry="registry.example:5000", output_root=tmp_path
        )
    assert calls == []


def test_successful_build_retains_registry_until_explicit_cleanup_and_exports_archives() -> None:
    source = (ROOT / "scripts/build_release_images.py").read_text(encoding="utf-8")
    assert '"cleanup": "pending-explicit-proof-cleanup"' in source
    assert "def cleanup_release_registry" in source
    assert "retained-verified-oci-archives" in source
    assert "oci-archive:" in source


def test_build_receipt_binds_accepted_reference_to_second_observed_build() -> None:
    # Regression: the writer once omitted acceptedReference while the evidence
    # collector required it bound to the second build, so evidence collection
    # could never succeed against a real receipt.
    writer = (ROOT / "scripts/build_release_images.py").read_text(encoding="utf-8")
    assert '"acceptedReference": proof_reference' in writer
    assert 'proof_reference = observations[1]["digestReference"]' in writer
    collector = (ROOT / "scripts/collect_release_evidence.py").read_text(encoding="utf-8")
    assert 'accepted_reference = str(image.get("acceptedReference"))' in collector
    assert 'accepted_reference.rsplit("@", 1)[-1] != second_digest' in collector


def test_pull_compose_is_exact_digest_pinned_without_engine_socket_or_public_side_ports() -> None:
    references = {
        image_id: f"127.0.0.1:5000/stateport-alpha/{image_id}@sha256:{character * 64}"
        for image_id, character in zip(
            ("stateport-api", "stateport-web", "stateport-worker"), ("a", "b", "c"), strict=True
        )
    }
    rendered = build_release_images.render_pull_compose(references)
    compose = yaml.safe_load(rendered)
    assert set(compose["services"]) == set(references)
    assert all(
        compose["services"][name]["image"] == reference for name, reference in references.items()
    )
    assert all("build" not in service for service in compose["services"].values())
    assert all(
        service["logging"]
        == {"driver": "json-file", "options": {"max-size": "1m", "max-file": "3"}}
        for service in compose["services"].values()
    )
    assert all(
        service["healthcheck"]["test"][1] == "/usr/local/bin/stateport-healthcheck"
        for service in compose["services"].values()
    )
    assert "podman.sock" not in rendered and "/var/run/docker.sock" not in rendered
    assert "127.0.0.1:${STATEPORT_WEB_PORT:-8080}:8080" in rendered


def test_source_compose_bounds_every_service_log_and_uses_packaged_health_probe() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    assert set(compose["services"]) == {
        "stateport-api",
        "stateport-web",
        "stateport-worker",
    }
    for service in compose["services"].values():
        assert service["logging"] == {
            "driver": "json-file",
            "options": {"max-size": "1m", "max-file": "3"},
        }
        assert service["healthcheck"]["test"][1] == ("/usr/local/bin/stateport-healthcheck")


def test_playwright_image_matches_repository_lock_and_defaults_headless() -> None:
    package = yaml.safe_load((ROOT / "images/image-set.v1.yaml").read_text())
    assert package["images"]["stateport-playwright"]["role"] == "optional-profile"
    text = (ROOT / "images/stateport-playwright/Containerfile").read_text()
    assert "v1.62.1-noble@sha256:" in text
    assert "STATEPORT_BROWSER_MODE=headless" in text
    assert 'CMD ["node"' in text
    lock = yaml.safe_load((ROOT / "images/stateport-playwright/package-lock.json").read_text())
    versions = {
        package["version"]
        for path, package in lock["packages"].items()
        if path.endswith("playwright-core")
    }
    assert versions == {"1.62.1"}


def test_retained_archive_push_uses_registry_push_manifest_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression: Podman re-serializes manifest and config on every push, so
    # the retained OCI archive only retains the accepted registry manifest
    # digest when both pushes pin the same --format docker serialization.
    accepted = "sha256:" + "b" * 64
    pushes: list[list[str]] = []

    def fake_run(arguments: list[str], **_kwargs: object) -> str:
        if arguments[1:2] == ["push"]:
            pushes.append(list(arguments))
            digest_path = Path(arguments[arguments.index("--digestfile") + 1])
            digest_path.write_text(accepted + "\n", encoding="ascii")
            archive_arg = next((arg for arg in arguments if arg.startswith("oci-archive:")), None)
            if archive_arg is not None:
                Path(archive_arg.removeprefix("oci-archive:").rsplit(":", 2)[0]).write_bytes(
                    b"fake-archive"
                )
        return ""

    monkeypatch.setattr(build_release_images, "_run", fake_run)
    monkeypatch.setattr(
        build_release_images,
        "_image_observation",
        lambda _reference: {"imageId": "sha256:" + "c" * 64, "observedDigests": [accepted]},
    )
    monkeypatch.setattr(
        build_release_images,
        "verify_oci_archive",
        lambda archive, *, expected_manifest_digest: {
            "archiveDigest": build_release_images.sha256_file(archive),
            "manifestDigest": expected_manifest_digest,
            "configDigest": "sha256:" + "d" * 64,
            "layerDigests": ["sha256:" + "e" * 64],
            "platform": "linux/amd64",
            "verification": "fake",
        },
    )
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile.web").write_text(
        "FROM example/base@sha256:" + "a" * 64 + "\n", encoding="utf-8"
    )
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    identity = build_release_images.SourceIdentity(
        commit="f" * 40,
        tree="0" * 40,
        version="0.0.0-test",
        created="2026-01-01T00:00:00Z",
        source_date_epoch=1,
    )
    images, accepted_references = build_release_images._execute_image_builds(
        {"images": {"stateport-web": {"containerfile": "Dockerfile.web"}}},
        identity,
        registry="127.0.0.1:5000",
        context=context,
        output=output,
    )
    registry_pushes = [cmd for cmd in pushes if any(a.startswith("docker://") for a in cmd)]
    archive_pushes = [cmd for cmd in pushes if any(a.startswith("oci-archive:") for a in cmd)]
    assert len(registry_pushes) == 2
    assert len(archive_pushes) == 1
    formats = {cmd[cmd.index("--format") + 1] for cmd in registry_pushes + archive_pushes}
    assert formats == {"docker"}
    authority = images["stateport-web"]["releaseAuthority"]
    assert authority["manifestDigest"] == accepted
    assert accepted_references["stateport-web"].endswith("@" + accepted)


def test_governor_cgroup_requires_bounded_service_membership(tmp_path: Path) -> None:
    parent = "/user.slice/user-1000.slice/user@1000.service/stateport.slice/stateport-heavy.slice/stateport-heavy-123-456.service"
    proc = tmp_path / "membership"
    controls = tmp_path / "cgroups" / parent.lstrip("/")
    controls.mkdir(parents=True)
    (controls / "memory.max").write_text("8589934592\n")
    (controls / "cpu.max").write_text("70000 100000\n")
    proc.write_text(f"0::{parent}\n")
    assert build_release_images.governor_cgroup_parent(proc_cgroup=proc, cgroup_root=tmp_path / "cgroups") == parent
    for invalid in (
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/terminal.scope\n",
        "0::/user.slice/user-1000.slice/user@1000.service/stateport.slice/stateport-heavy.slice\n",
        f"0::{parent}/../escape\n",
        "1:memory:/legacy\n",
        "1:bogus_controller:/\n",
        "two 0::  lines do not exist\n0::{parent}\n",
    ):
        proc.write_text(invalid)
        with pytest.raises(build_release_images.ReleaseBuildError, match="governor"):
            build_release_images.governor_cgroup_parent(proc_cgroup=proc, cgroup_root=tmp_path / "cgroups")
    # An additive legacy controller line from an independent controller mount
    # (net_cls from a VPN daemon) must not defeat the bounded-service check.
    proc.write_text(f"0::{parent}\n1:net_cls:/\n")
    assert build_release_images.governor_cgroup_parent(proc_cgroup=proc, cgroup_root=tmp_path / "cgroups") == parent
    proc.write_text(f"0::{parent}\n")
    for name, invalid, valid in (("memory.max", "max", "8589934592"), ("cpu.max", "max 100000", "70000 100000")):
        (controls / name).write_text(invalid)
        with pytest.raises(build_release_images.ReleaseBuildError, match="finite"):
            build_release_images.governor_cgroup_parent(proc_cgroup=proc, cgroup_root=tmp_path / "cgroups")
        (controls / name).write_text(valid)


def test_protected_build_refuses_outside_governor_before_podman(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def refuse() -> str:
        raise build_release_images.ReleaseBuildError("not in governor")
    calls: list[str] = []
    monkeypatch.setattr(build_release_images, "governor_cgroup_parent", refuse)
    monkeypatch.setattr(build_release_images, "verify_podman_builder", lambda: calls.append("podman"))
    monkeypatch.setattr(build_release_images, "_release_identities", lambda *_args: calls.append("identity"))
    with pytest.raises(build_release_images.ReleaseBuildError, match="governor"):
        build_release_images.build_release(version="0.1.0-alpha.17", registry="127.0.0.1:5000", output_root=tmp_path)
    assert calls == []


def test_governed_build_commands_keep_run_children_under_service() -> None:
    parent = "/user.slice/user-1000.slice/user@1000.service/stateport.slice/stateport-heavy.slice/stateport-heavy-123-456.service"
    identity = build_release_images.SourceIdentity("b" * 40, "c" * 40, "0.1.0-alpha.17", "2026-09-05T00:00:00Z", 1788566400)
    commands = build_release_images.build_commands(
        build_release_images.validate_definitions(), identity, registry="127.0.0.1:5000",
        context_root=Path("/tmp/context"), digest_root=Path("/tmp/digests"), cgroup_parent=parent,
    )
    builds = [command for command in commands if "build" in command]
    assert len(builds) == 14
    child_paths = [command[command.index("--cgroup-parent") + 1] for command in builds]
    assert len(set(child_paths)) == 14
    assert all(re.fullmatch(re.escape(parent) + r"/stateport-build-[0-9a-f]{24}", child) for child in child_paths)
    for command in builds:
        assert command[1:3] == ["--cgroup-manager=cgroupfs", "build"]
        assert "--isolation=oci" in command
        assert "--network=private" in command


def test_build_cgroup_child_is_stable_per_create_only_digest_slot() -> None:
    parent = "/bounded.service"
    slot = Path("/external/run1/digests/web-build1.digest")
    child = build_release_images.build_cgroup_path(parent, digest_file=slot)
    assert child == build_release_images.build_cgroup_path(parent, digest_file=slot)
    assert child.startswith(parent + "/stateport-build-")
    assert child != build_release_images.build_cgroup_path(parent, digest_file=Path("/external/run2/digests/web-build1.digest"))


def test_opencode_platform_binary_is_pinned_lock_verified_and_version_asserted() -> None:
    # Regression guard for the maintained-upstream OpenCode install: each image
    # that ships the coding agent fetches the exact pinned platform tarball,
    # cross-checks the audited lock entry and sha512 SRI before extraction,
    # verifies the extracted binary's sha256, and fails unless it reports the
    # pinned version. Any drift in a pin, the lock, or the install step fails here.
    inputs = yaml.safe_load((ROOT / "config/provider-runtime-inputs.yaml").read_text())
    opencode = inputs["opencode"]
    lock = json.loads((ROOT / "config/opencode-runtime/package-lock.json").read_text())
    assert opencode["version"] == "1.18.31"
    assert opencode["verification"]["observedVersion"] == "1.18.31"
    cases = (
        (
            "apps/web/Dockerfile",
            "musl",
            "opencode-linux-x64-musl",
            'test "$(/usr/local/bin/opencode --version)" = "1.18.31"',
        ),
        (
            "images/stateport-dev-workspace/Containerfile",
            "glibc",
            "opencode-linux-x64",
            'test "$(opencode --version)" = "$STATEPORT_OPENCODE_VERSION"',
        ),
    )
    for recipe, flavor, package, version_assertion in cases:
        platform = opencode["platforms"][flavor]
        assert platform["package"] == package
        entry = lock["packages"]["node_modules/" + package]
        # The lock entry the build cross-checks must equal the reviewed pin.
        assert entry["resolved"] == platform["tarball"]
        assert entry["integrity"] == platform["integrity"]
        text = (ROOT / recipe).read_text(encoding="utf-8")
        assert "config/opencode-runtime/package-lock.json" in text
        assert "STATEPORT_OPENCODE_VERSION=" + opencode["version"] in text
        assert "STATEPORT_OPENCODE_LOCK_PACKAGE=" + package in text
        assert "STATEPORT_OPENCODE_TARBALL=" + platform["tarball"] in text
        assert "STATEPORT_OPENCODE_SRI=" + platform["integrity"] in text
        assert "STATEPORT_OPENCODE_BINARY_MEMBER=" + platform["binaryMember"] in text
        assert (
            "STATEPORT_OPENCODE_BINARY_SHA256=" + platform["observedBinarySha256"] in text
        )
        assert "/usr/local/bin/opencode" in text
        assert "chmod 0555" in text
        # Fail-closed install: the lock URL/SRI must match the pin, the pinned
        # SRI must match the downloaded bytes, and the binary sha256 must match.
        assert '"node_modules/"+platformPackage' in text
        assert "lock platform tarball differs from the pin" in text
        assert "lock platform integrity differs from the pin" in text
        assert "tarball integrity differs from the pin" in text
        assert version_assertion in text
    web = (ROOT / "apps/web/Dockerfile").read_text(encoding="utf-8")
    assert 'io.stateport.provider.executables="opencode"' in web
    # The web base omits the C++ runtime the musl OpenCode binary links
    # against, so both packages must be installed and exactly pinned.
    for package in ("libstdc++=15.2.0-r2", "libgcc=15.2.0-r2"):
        assert package in web


# --------------------------------------------------------------------------
# the builder BINARY is anchored to a committed digest, not to its own descriptor
# --------------------------------------------------------------------------
#
# Added 2026-09-28 after independent verification of 86218b34. Every digest check the
# builder gate performs is between the executable and the operator-supplied
# descriptor, and that descriptor is unsigned, uncommitted and supplied by the same
# party as the executable. A 41-byte stand-in plus a descriptor hashing itself
# satisfies all of them, so `verify_podman_builder` had no committed anchor at all
# and, per the same verification, no test called it: a probe recorded a call count of
# 0 while the suite reported 35 passed. These tests call it for real.


def _builder_inputs(monkeypatch: pytest.MonkeyPatch, **builder: object) -> dict:
    """A minimal build-inputs mapping, with builder fields overridable per test."""
    base: dict = {
        "name": "podman",
        "observedVersion": "6.1.1",
        "observedExecutableDigest": "sha256:" + "11" * 32,
        "compatibilityFloor": "5.0.0",
    }
    base.update(builder)
    return {"builder": base}


def _descriptor_for(path: Path, digest: str, version: str = "6.1.1") -> dict:
    return {
        "formatVersion": "stateport.release-builder-descriptor/v1",
        "name": "podman",
        "executablePath": str(path),
        "executableDigest": digest,
        "version": version,
        "artifact": {"uri": "arch://extra-x86_64/podman-6.1.1-1", "digest": digest},
    }


def test_builder_binary_must_match_the_committed_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A descriptor that hashes ITSELF is not enough: the committed digest decides.

    This is the exact bypass the verification demonstrated. Executable, descriptor
    digest and artifact digest all agree with each other and are wholly
    operator-controlled, so without the committed comparison they prove only that the
    descriptor describes whatever was handed over.
    """
    import hashlib
    import json

    stand_in = tmp_path / "podman"
    stand_in.write_text("#!/bin/sh\nexit 0\n")
    stand_in.chmod(0o755)
    real = "sha256:" + hashlib.sha256(stand_in.read_bytes()).hexdigest()

    descriptor = tmp_path / "builder.json"
    descriptor.write_text(json.dumps(_descriptor_for(stand_in, real)))
    monkeypatch.setenv(build_release_images.BUILDER_DESCRIPTOR_ENV, str(descriptor))
    monkeypatch.setattr(build_release_images, "PODMAN", str(stand_in))
    monkeypatch.setattr(
        build_release_images, "BUILD_INPUTS", tmp_path / "inputs.yaml"
    )
    monkeypatch.setattr(
        build_release_images,
        "_load_yaml",
        lambda _p: _builder_inputs(monkeypatch, observedExecutableDigest="sha256:" + "22" * 32),
    )
    monkeypatch.setattr(
        build_release_images,
        "_run",
        lambda *a, **k: json.dumps({"Client": {"Version": "6.1.1"}}),
    )

    with pytest.raises(
        build_release_images.ReleaseBuildError, match="committed, reviewed builder"
    ):
        build_release_images.verify_podman_builder()


def test_builder_gate_refuses_when_no_committed_digest_is_declared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing anchor must refuse, not silently skip the check."""
    import hashlib
    import json

    stand_in = tmp_path / "podman"
    stand_in.write_text("#!/bin/sh\nexit 0\n")
    stand_in.chmod(0o755)
    real = "sha256:" + hashlib.sha256(stand_in.read_bytes()).hexdigest()
    descriptor = tmp_path / "builder.json"
    descriptor.write_text(json.dumps(_descriptor_for(stand_in, real)))
    monkeypatch.setenv(build_release_images.BUILDER_DESCRIPTOR_ENV, str(descriptor))
    monkeypatch.setattr(build_release_images, "PODMAN", str(stand_in))
    monkeypatch.setattr(build_release_images, "BUILD_INPUTS", tmp_path / "inputs.yaml")
    monkeypatch.setattr(
        build_release_images,
        "_load_yaml",
        lambda _p: {
            "builder": {"name": "podman", "observedVersion": "6.1.1", "compatibilityFloor": "5.0.0"}
        },
    )
    monkeypatch.setattr(
        build_release_images,
        "_run",
        lambda *a, **k: json.dumps({"Client": {"Version": "6.1.1"}}),
    )

    with pytest.raises(
        build_release_images.ReleaseBuildError, match="no committed builder executable digest"
    ):
        build_release_images.verify_podman_builder()


def test_committed_builder_digest_matches_the_real_host_builder() -> None:
    """The committed anchor must equal the digest of the builder it claims to pin.

    Guards the value itself, so a re-pin cannot be a copy-paste of a stale digest
    and the field cannot rot unnoticed the way observedVersion did for 57 days.
    """
    import hashlib

    import yaml as _yaml

    inputs = _yaml.safe_load(
        (Path(build_release_images.__file__).resolve().parent.parent
         / "config" / "container-build-inputs.yaml").read_text()
    )
    declared = str(inputs["builder"]["observedExecutableDigest"])
    assert declared.startswith("sha256:") and len(declared) == len("sha256:") + 64
    # Resolve the builder the way the GATE resolves it, not via a hardcoded path.
    # A hardcoded /usr/bin/podman made this host-coupled and could never detect that
    # the file the build would actually run is a different one; using the module's
    # own resolution means this test and the gate cannot disagree about which file
    # is meant, and it honours STATEPORT_PODMAN_PATH the same way the gate does.
    resolved = Path(build_release_images.PODMAN)
    if resolved.is_symlink() or not resolved.is_file():
        pytest.skip(f"no regular builder binary at the resolved path {resolved}")
    actual = "sha256:" + hashlib.sha256(resolved.read_bytes()).hexdigest()
    assert declared == actual, (
        f"the committed builder digest does not match the builder the build would "
        f"run ({resolved}); the host Podman was upgraded and the builder must be "
        f"re-pinned by a human"
    )


# --------------------------------------------------------------------------
# the compatibility floor is enforced, not decorative
# --------------------------------------------------------------------------
#
# Added 2026-09-28. `compatibilityFloor` was emitted into the plan and the receipt but
# compared by nothing: `grep -n Floor scripts/build_release_images.py` found only three
# emission sites and no comparison, and a 0.0.1 stand-in builder sailed straight past
# 5.0.0. The honest scope of this check is narrower than it looks, and the tests say so:
# because `observedVersion` is compared for exact equality against a committed value,
# a substituted binary cannot reach the floor check at all. What the floor catches is a
# COMMITTED CONFIGURATION ERROR -- a build-inputs edit that declares an observedVersion
# below its own floor -- which would otherwise build and sign a release with a builder
# the project had already declared unsupported.


@pytest.mark.parametrize(
    ("version", "floor", "expected"),
    [
        ("6.1.1", "5.0.0", True),
        ("5.0.0", "5.0.0", True),   # exactly at the floor is sufficient
        ("4.9.9", "5.0.0", False),
        ("6.2.0-dev", "5.0.0", True),  # pre-release suffix is not a downgrade
        ("0.0.1", "5.0.0", False),     # the value the bypass actually used
        ("10.0.0", "9.0.0", True),     # numeric, not lexicographic
        ("9.0.0", "10.0.0", False),    # the case a string compare would get wrong
        ("6.1", "5.0.0", True),        # short form padded with zeros
        ("6.1.1", "", None),           # unparsable floor refuses rather than passes
        ("not-a-version", "5.0.0", None),
    ],
)
def test_version_at_least_is_numeric_and_fails_closed(
    version: str, floor: str, expected: bool | None
) -> None:
    assert build_release_images._version_at_least(version, floor) is expected


def test_builder_below_the_committed_floor_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A committed observedVersion under its own floor must refuse the build."""
    import hashlib
    import json

    stand_in = tmp_path / "podman"
    stand_in.write_text("#!/bin/sh\nexit 0\n")
    stand_in.chmod(0o755)
    real = "sha256:" + hashlib.sha256(stand_in.read_bytes()).hexdigest()

    descriptor = tmp_path / "builder.json"
    descriptor.write_text(json.dumps(_descriptor_for(stand_in, real, version="4.9.9")))
    monkeypatch.setenv(build_release_images.BUILDER_DESCRIPTOR_ENV, str(descriptor))
    monkeypatch.setattr(build_release_images, "PODMAN", str(stand_in))
    monkeypatch.setattr(build_release_images, "BUILD_INPUTS", tmp_path / "inputs.yaml")
    monkeypatch.setattr(
        build_release_images,
        "_load_yaml",
        lambda _p: {
            "builder": {
                "name": "podman",
                "observedVersion": "4.9.9",
                "observedExecutableDigest": real,
                "compatibilityFloor": "5.0.0",
            }
        },
    )
    monkeypatch.setattr(
        build_release_images,
        "_run",
        lambda *a, **k: json.dumps({"Client": {"Version": "4.9.9"}}),
    )

    with pytest.raises(build_release_images.ReleaseBuildError, match="below the committed"):
        build_release_images.verify_podman_builder()


# --------------------------------------------------------------------------
# the verified builder must be the builder that actually gets executed
# --------------------------------------------------------------------------
#
# Added 2026-09-28 after a second independent verification, which showed the first F1
# fix raised the cost of the DESCRIPTOR attack while leaving the PATH attack open: the
# gate hashed the descriptor's path while the build executed the module-level PODMAN
# resolved from PATH, and the only guard between them tested STATEPORT_PODMAN_PATH,
# which nothing in the repository sets. The verifier demonstrated it end to end -- an
# honest descriptor verified /usr/bin/podman, PATH supplied a substituted binary, every
# committed check passed, and the substituted binary built the images. The first three
# tests above had to be given an explicit PODMAN because this check now runs first.


def _builder_gate_stubs(monkeypatch, stand_in, real, version="6.1.1"):
    """Wire verify_podman_builder's collaborators for a synthetic builder binary."""
    import json

    monkeypatch.setattr(build_release_images, "PODMAN", str(stand_in))
    monkeypatch.setattr(
        build_release_images, "_load_yaml", lambda _p: _builder_inputs(
            monkeypatch, observedExecutableDigest=real
        )
    )

    def fake_run(_argv, **_kwargs):
        return json.dumps(
            {"Client": {"Version": version},
             "host": {"os": "linux", "arch": "amd64", "cgroupVersion": "v2",
                      "security": {"rootless": True}},
             "store": {"graphDriverName": "overlay"}}
        )

    monkeypatch.setattr(build_release_images, "_run", fake_run)


def _synthetic_builder(tmp_path, name, body="#!/bin/sh\nexit 0\n"):
    import hashlib

    path = tmp_path / name
    path.write_text(body)
    path.chmod(0o755)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_builder_refuses_when_path_resolves_to_a_different_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact substitution that survived the first fix must be refused."""
    import json

    honest, real = _synthetic_builder(tmp_path, "honest-podman")
    attacker, _ = _synthetic_builder(
        tmp_path, "attacker-podman", "#!/bin/sh\necho SUBSTITUTED-BUILDER-ACTUALLY-RAN\n"
    )

    descriptor = tmp_path / "builder.json"
    descriptor.write_text(json.dumps(_descriptor_for(honest, real)))
    monkeypatch.setenv(build_release_images.BUILDER_DESCRIPTOR_ENV, str(descriptor))
    monkeypatch.delenv("STATEPORT_PODMAN_PATH", raising=False)
    monkeypatch.setattr(build_release_images, "BUILD_INPUTS", tmp_path / "inputs.yaml")
    # PODMAN is what the build executes; the descriptor names a different file.
    monkeypatch.setattr(build_release_images, "PODMAN", str(attacker))
    monkeypatch.setattr(
        build_release_images, "_load_yaml", lambda _p: _builder_inputs(
            monkeypatch, observedExecutableDigest=real
        )
    )
    monkeypatch.setattr(
        build_release_images, "_run",
        lambda *a, **k: json.dumps({"Client": {"Version": "6.1.1"}}),
    )

    with pytest.raises(
        build_release_images.ReleaseBuildError, match="not the verified builder"
    ):
        build_release_images.verify_podman_builder()


def test_builder_accepts_an_honest_path_resolving_to_the_verified_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The new check must not refuse an honest host where both sides agree."""
    import json

    honest, real = _synthetic_builder(tmp_path, "honest-podman")
    descriptor = tmp_path / "builder.json"
    descriptor.write_text(json.dumps(_descriptor_for(honest, real)))
    monkeypatch.setenv(build_release_images.BUILDER_DESCRIPTOR_ENV, str(descriptor))
    monkeypatch.delenv("STATEPORT_PODMAN_PATH", raising=False)
    monkeypatch.setattr(build_release_images, "BUILD_INPUTS", tmp_path / "inputs.yaml")
    _builder_gate_stubs(monkeypatch, honest, real)

    value = build_release_images.verify_podman_builder()
    assert value["executablePath"] == str(honest)
    assert value["executableDigest"] == real


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("٦.١.١", None),   # Arabic-Indic digits satisfy isdigit() but are not ascii
        ("1." * 40 + "1", None),  # oversized after v-prefix stripping; int() would raise
    ],
)
def test_version_parsing_refuses_without_crashing(
    version: str, expected: bool | None
) -> None:
    """Unparsable input must return None, never raise and never pass."""
    assert build_release_images._version_at_least(version, "5.0.0") is expected


# --------------------------------------------------------------------------
# PATH-precedence symlink alias, and the two gaps the second pass found
# --------------------------------------------------------------------------
#
# Added 2026-09-28 after a second independent verification pass, which found a bypass
# that survived the realpath fix. The gate validated and hashed `executable`, the
# descriptor's path, but never hashed or type-checked `PODMAN`, which is what all
# fourteen exec sites actually run. A PATH-precedence SYMLINK pointing at the honest
# file satisfied realpath equality, was never hashed, and could be repointed after the
# check to swap the builder for a thirty-minute build whose provenance already named
# the honest digest. The governor's own PATH begins in user-owned directories, so this
# was reachable rather than theoretical.


def test_builder_refuses_a_symlinked_path_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A symlink that resolves to the honest file is still an alias, not the builder."""
    import json

    honest, real = _synthetic_builder(tmp_path, "honest-podman")
    alias = tmp_path / "bin"
    alias.mkdir()
    link = alias / "podman"
    link.symlink_to(honest)  # resolves to the honest file at check time

    descriptor = tmp_path / "builder.json"
    descriptor.write_text(json.dumps(_descriptor_for(honest, real)))
    monkeypatch.setenv(build_release_images.BUILDER_DESCRIPTOR_ENV, str(descriptor))
    monkeypatch.delenv("STATEPORT_PODMAN_PATH", raising=False)
    monkeypatch.setattr(build_release_images, "BUILD_INPUTS", tmp_path / "inputs.yaml")
    _builder_gate_stubs(monkeypatch, honest, real)
    # set AFTER the stubs, which pin PODMAN to the honest file themselves.
    monkeypatch.setattr(build_release_images, "PODMAN", str(link))

    with pytest.raises(build_release_images.ReleaseBuildError, match="symlink"):
        build_release_images.verify_podman_builder()


def test_realpath_comparison_is_pinned_and_cannot_be_replaced_by_string_equality(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guards the realpath normalisation itself, which no other test pins.

    Second-pass finding: replacing `realpath(PODMAN) != realpath(executable)` with
    plain string equality left the ENTIRE suite green, so the normalisation could be
    deleted as cosmetic. A non-canonical spelling of the same honest file is accepted
    only while realpath is in use, which is what makes this test fail if it is not.
    """
    import json
    import os

    honest, real = _synthetic_builder(tmp_path, "honest-podman")
    descriptor = tmp_path / "builder.json"
    descriptor.write_text(json.dumps(_descriptor_for(honest, real)))
    monkeypatch.setenv(build_release_images.BUILDER_DESCRIPTOR_ENV, str(descriptor))
    monkeypatch.delenv("STATEPORT_PODMAN_PATH", raising=False)
    monkeypatch.setattr(build_release_images, "BUILD_INPUTS", tmp_path / "inputs.yaml")
    _builder_gate_stubs(monkeypatch, honest, real)

    non_canonical = os.path.join(str(tmp_path), "..", os.path.basename(str(tmp_path)),
                                 "honest-podman")
    assert non_canonical != str(honest), "the spelling must differ textually"
    assert os.path.realpath(non_canonical) == str(honest), "but name the same file"
    monkeypatch.setattr(build_release_images, "PODMAN", non_canonical)

    value = build_release_images.verify_podman_builder()
    assert value["executableDigest"] == real


def test_builder_gate_is_called_before_images_are_executed() -> None:
    """The success path must call the gate before executing any image command.

    Second-pass finding: deleting the only call to verify_podman_builder from the
    success path left the whole suite green, because both existing monkeypatch sites
    assert `calls == []` and therefore only ever exercise REFUSAL paths. Reaching the
    gate at runtime needs the full governor harness, so this pins the ordering in the
    source instead: the call must exist, and must precede image execution. Deleting
    the call, or moving it after execution, fails here.
    """
    source = Path(build_release_images.__file__).read_text()
    body = source[source.index("def build_release("):]
    verify_at = body.index("verify_podman_builder()")
    assert "build_release_images.verify_podman_builder" not in body, (
        "the gate must be called as a module attribute so tests can intercept it"
    )
    for marker in ("_execute_image_builds", "podman", "imageCommands"):
        if marker in body:
            assert verify_at < body.index(marker), (
                f"the builder gate must run before {marker} is reached"
            )
            break
    else:
        raise AssertionError("no image execution site found after the gate")
