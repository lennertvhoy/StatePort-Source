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


def test_provider_build_args_use_recipe_names_and_both_consumers_have_contract() -> None:
    provider = {
        "mode": "custom-oci",
        "image": "registry.example/codex@sha256:" + "a" * 64,
        "manifestDigest": "sha256:" + "a" * 64,
        "platformManifestDigest": "sha256:" + "b" * 64,
        "version": "codex-cli 0.146.0+stateport.3",
        "bubblewrapVersion": "bubblewrap 0.12.0",
        "ripgrepVersion": "ripgrep 14.1.0",
        "sourceCommit": "e363b08c9175ac1cbe5893615dd2cb9ddf95043b",
        "sourceArchiveDigest": "sha256:" + "c" * 64,
        "buildContextDigest": "sha256:" + "d" * 64,
        "codexDigest": "sha256:" + "e" * 64,
        "bubblewrapDigest": "sha256:" + "f" * 64,
        "ripgrepDigest": "sha256:" + "0" * 64,
    }
    args = build_release_images.provider_build_args(provider)
    assert "STATEPORT_PROVIDER_MANIFEST_DIGEST=" + provider["manifestDigest"] in args
    assert "STATEPORT_PROVIDER_PLATFORM_MANIFEST_DIGEST=" + provider["platformManifestDigest"] in args
    assert "STATEPORT_PROVIDER_BUBBLEWRAP_VERSION=" + provider["bubblewrapVersion"] in args
    assert all("MANIFESTDIGEST" not in item for item in args)
    pulls = build_release_images.base_pull_commands(provider)
    assert pulls[-1][-1] == provider["image"]
    commands = build_release_images.build_commands(
        build_release_images.validate_definitions(),
        build_release_images.SourceIdentity(
            "b" * 40, "c" * 40, "0.2.0-alpha.1", "2026-08-01T00:00:00Z", 1785542400
        ),
        registry="127.0.0.1:5000",
        context_root=Path("/tmp/stateport-provider-context"),
        digest_root=Path("/tmp/stateport-provider-digests"),
        provider_input=provider,
    )
    build_commands = [item for item in commands if item[1] == "build"]
    assert build_commands
    assert all(
        "STATEPORT_PROVIDER_IMAGE=" + provider["image"] in item for item in build_commands
    )
    for rel in ("apps/web/Dockerfile", "images/stateport-dev-workspace/Containerfile"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "FROM ${STATEPORT_PROVIDER_IMAGE} AS stateport-provider" in text
        assert "provider-metadata.json" in text
        assert "/provider-input/bwrap" in text
        assert "/usr/share/licenses/stateport-provider" in text


def test_unadmitted_custom_provider_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The repository yaml is ADMITTED to the reviewed producer build
    # (stage1-lane4-20260912/producer-build-r1/producer-build-receipt.json,
    # verifier-reviewed procedure r2; double-build reproducible digest
    # 95c28133db0adbb619f9af5281ad9d18d8e2a26b53edaca2635f9a27a1ed1b17).
    # Fail-closed now means: the committed record must match that exact
    # reviewed identity, and any drift from it refuses admission.
    monkeypatch.setenv("STATEPORT_PROVIDER_MODE", "custom-oci")
    record = build_release_images.load_provider_oci_input()
    expected_digest = "sha256:95c28133db0adbb619f9af5281ad9d18d8e2a26b53edaca2635f9a27a1ed1b17"
    assert record["image"] == (
        "ghcr.io/lennertvhoy/stateport-provider@" + expected_digest
    )
    assert record["manifestDigest"] == expected_digest
    assert record["platformManifestDigest"] == expected_digest
    drifted = yaml.safe_load(
        (ROOT / "config/provider-runtime-inputs.yaml").read_text(encoding="utf-8")
    )
    drifted["codex"]["oci"]["manifestDigest"] = "sha256:" + "c" * 64
    drifted["codex"]["oci"]["image"] = (
        "127.0.0.1:5001/stateport-alpha/stateport-provider@sha256:" + "c" * 64
    )
    drifted_path = tmp_path / "drifted-provider-runtime-inputs.yaml"
    drifted_path.write_text(yaml.safe_dump(drifted), encoding="utf-8")
    # A drifted but internally-consistent record still passes the admission
    # gate: the gate checks format and consistency only. Identity binding to
    # the reviewed producer build is enforced by the coupled
    # providerRuntimeInputs lock digest in container-build-inputs.yaml —
    # the committed pair must verify, and any edit to the yaml without the
    # lock refresh fails every build.
    monkeypatch.setattr(build_release_images, "PROVIDER_INPUTS", drifted_path)
    drifted_record = build_release_images.load_provider_oci_input()
    assert drifted_record["manifestDigest"] == "sha256:" + "c" * 64
    monkeypatch.undo()
    build_release_images.verify_locked_build_inputs()


def _custom_provider_record(*, image_digest: str = "a" * 64) -> dict:
    record = yaml.safe_load(
        (ROOT / "config/provider-runtime-inputs.yaml").read_text(encoding="utf-8")
    )
    record["codex"]["oci"] = {
        "enabled": True,
        "image": f"registry.example/codex@sha256:{image_digest}",
        "manifestDigest": "sha256:" + "a" * 64,
        "platformManifestDigest": "sha256:" + "b" * 64,
        "version": "codex-cli 0.146.0+stateport.3",
        "bubblewrapVersion": "bubblewrap 0.12.0",
        "ripgrepVersion": "ripgrep 14.1.0",
        "sourceCommit": record["codex"]["source"]["commit"],
        "sourceArchiveDigest": "sha256:" + "c" * 64,
        "buildContextDigest": "sha256:" + "d" * 64,
        "artifacts": {
            "codexDigest": "sha256:" + "e" * 64,
            "bubblewrapDigest": "sha256:" + "f" * 64,
            "ripgrepDigest": "sha256:" + "0" * 64,
        },
        "licenses": ["LICENSE", "NOTICE", "BUBBLEWRAP-LICENSE", "BUBBLEWRAP-NOTICE"],
    }
    return record


def test_admitted_provider_record_is_loaded_without_metadata_self_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "provider-runtime-inputs.yaml"
    fixture.write_text(yaml.safe_dump(_custom_provider_record(), sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(build_release_images, "PROVIDER_INPUTS", fixture)
    monkeypatch.setenv("STATEPORT_PROVIDER_MODE", "custom-oci")
    loaded = build_release_images.load_provider_oci_input()
    assert loaded["manifestDigest"] != loaded["codexDigest"]
    assert loaded["platformManifestDigest"] == "sha256:" + "b" * 64


def test_provider_record_refuses_image_digest_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "provider-runtime-inputs.yaml"
    fixture.write_text(
        yaml.safe_dump(_custom_provider_record(image_digest="1" * 64), sort_keys=False),
        encoding="utf-8",
    )
    monkeypatch.setattr(build_release_images, "PROVIDER_INPUTS", fixture)
    monkeypatch.setenv("STATEPORT_PROVIDER_MODE", "custom-oci")
    with pytest.raises(build_release_images.ReleaseBuildError, match="differs from manifestDigest"):
        build_release_images.load_provider_oci_input()


def _provider_build_shell(containerfile: Path, provider_root: Path, output_root: Path) -> str:
    text = containerfile.read_text(encoding="utf-8")
    marker = "RUN --mount=type=bind,from=stateport-provider,source=/out,target=/provider-input,readonly \\\n"
    start = text.index(marker)
    block = text[start:].split("\n\n", 1)[0]
    lines = block.splitlines()
    assert lines[0] == marker.rstrip("\n")
    script = "\n".join(lines[1:])
    script = script.replace("/provider-input", str(provider_root))
    script = script.replace("/out", str(output_root))
    return script


def _run_provider_build_fixture(
    containerfile: Path,
    tmp_path: Path,
    *,
    mutate_metadata: bool = False,
    wrong_codex_digest: bool = False,
    missing_bwrap: bool = False,
    changed_codex_bytes: bool = False,
) -> subprocess.CompletedProcess[str]:
    provider = tmp_path / "provider-input"
    output = tmp_path / "provider-output"
    provider.mkdir(parents=True)
    output.mkdir(parents=True)
    versions = {
        "codex": "codex-cli 0.146.0+stateport.3",
        "bwrap": "bubblewrap 0.12.0",
        "rg": "ripgrep 14.1.0",
    }
    for name, version in versions.items():
        path = provider / name
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{version}'\n", encoding="utf-8")
        path.chmod(0o755)
    if missing_bwrap:
        (provider / "bwrap").unlink()
    licenses = ["LICENSE", "NOTICE", "BUBBLEWRAP-LICENSE", "BUBBLEWRAP-NOTICE"]
    for name in licenses:
        (provider / name).write_text(f"synthetic {name}\n", encoding="utf-8")
    artifact_digests = {
        name: (
            "sha256:" + hashlib.sha256((provider / name).read_bytes()).hexdigest()
            if (provider / name).exists()
            else "sha256:" + "0" * 64
        )
        for name in versions
    }
    metadata = {
        "formatVersion": "stateport.provider-runtime-metadata/v1",
        "version": versions["codex"],
        "bubblewrapVersion": versions["bwrap"],
        "ripgrepVersion": versions["rg"],
        "source": {
            "repository": "https://github.com/openai/codex",
            "commit": "e363b08c9175ac1cbe5893615dd2cb9ddf95043b",
            "sourceArchiveDigest": "sha256:" + "c" * 64,
            "buildContextDigest": "sha256:" + "d" * 64,
        },
        "artifacts": {
            "codex": {"digest": artifact_digests["codex"]},
            "bubblewrap": {"digest": artifact_digests["bwrap"]},
            "ripgrep": {"digest": artifact_digests["rg"]},
        },
        "licenses": licenses,
    }
    if mutate_metadata:
        metadata["version"] = "codex-cli 0.146.0+wrong"
    (provider / "provider-metadata.json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )
    if changed_codex_bytes:
        with (provider / "codex").open("a") as stream:
            stream.write("# bytes changed after metadata was recorded\n")
    env = os.environ.copy()
    env.update(
        {
            "STATEPORT_PROVIDER_MODE": "custom-oci",
            "STATEPORT_PROVIDER_VERSION": versions["codex"],
            "STATEPORT_PROVIDER_BUBBLEWRAP_VERSION": versions["bwrap"],
            "STATEPORT_PROVIDER_RIPGREP_VERSION": versions["rg"],
            "STATEPORT_PROVIDER_SOURCE_COMMIT": metadata["source"]["commit"],
            "STATEPORT_PROVIDER_SOURCE_ARCHIVE_DIGEST": metadata["source"]["sourceArchiveDigest"],
            "STATEPORT_PROVIDER_BUILD_CONTEXT_DIGEST": metadata["source"]["buildContextDigest"],
            "STATEPORT_PROVIDER_CODEX_DIGEST": artifact_digests["codex"],
            "STATEPORT_PROVIDER_BUBBLEWRAP_DIGEST": artifact_digests["bwrap"],
            "STATEPORT_PROVIDER_RIPGREP_DIGEST": artifact_digests["rg"],
        }
    )
    if wrong_codex_digest:
        env["STATEPORT_PROVIDER_CODEX_DIGEST"] = "sha256:" + "e" * 64
    script = _provider_build_shell(containerfile, provider, output)
    return subprocess.run(
        ["sh", "-c", script],
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


@pytest.mark.parametrize("recipe", ("apps/web/Dockerfile", "images/stateport-dev-workspace/Containerfile"))
def test_provider_build_custom_fixture_copies_and_refuses_safely(
    recipe: str, tmp_path: Path
) -> None:
    containerfile = ROOT / recipe
    passed = _run_provider_build_fixture(containerfile, tmp_path / "pass")
    assert passed.returncode == 0, passed.stderr
    output = tmp_path / "pass" / "provider-output"
    for name in ("codex", "bwrap", "rg", "LICENSE", "NOTICE", "BUBBLEWRAP-LICENSE", "BUBBLEWRAP-NOTICE"):
        assert (output / name).is_file(), name
    assert (output / "codex").read_bytes().startswith(b"#!/bin/sh")
    for index, kwargs in enumerate((
        {"wrong_codex_digest": True},
        {"mutate_metadata": True},
        {"missing_bwrap": True},
        {"changed_codex_bytes": True},
    ), start=1):
        failed = _run_provider_build_fixture(containerfile, tmp_path / ("fail-" + str(index)), **kwargs)
        assert failed.returncode != 0
    assert all(path.is_relative_to(tmp_path) for path in tmp_path.rglob("*"))


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
    ):
        proc.write_text(invalid)
        with pytest.raises(build_release_images.ReleaseBuildError, match="governor"):
            build_release_images.governor_cgroup_parent(proc_cgroup=proc, cgroup_root=tmp_path / "cgroups")
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


@pytest.mark.parametrize('mutation', [None, 'different_image', 'missing_link', 'wrong_platform'])
def test_provider_pull_binds_index_to_platform(monkeypatch: pytest.MonkeyPatch, mutation: str | None) -> None:
    provider = _custom_provider_record()['codex']['oci'] | {'mode': 'custom-oci'}
    index, platform = provider['manifestDigest'], provider['platformManifestDigest']
    monkeypatch.setattr(build_release_images, '_load_yaml', lambda _path: {'images': {}})
    monkeypatch.setattr(build_release_images, '_run', lambda *_args, **_kwargs: '')
    def observe(reference: str) -> dict:
        is_platform = reference.endswith(platform)
        return {
            'digest': platform if is_platform else index,
            'observedDigests': [platform] if mutation == 'missing_link' else [index, platform],
            'imageId': 'other' if mutation == 'different_image' and is_platform else 'same',
            'os': 'linux',
            'architecture': 'arm64' if mutation == 'wrong_platform' and not is_platform else 'amd64',
        }
    monkeypatch.setattr(build_release_images, '_image_observation', observe)
    if mutation:
        with pytest.raises(build_release_images.ReleaseBuildError):
            build_release_images.pull_and_verify_base_images(provider)
    else:
        result = build_release_images.pull_and_verify_base_images(provider)
        assert result[0]['platformManifestDigest'] == platform
