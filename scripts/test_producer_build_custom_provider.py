"""Unit tests for scripts/producer_build_custom_provider.py (procedure r2 D1-D7).

Every subprocess entry point is mocked: no podman, no registry, no openssl,
and no network is touched. Filesystem effects stay inside pytest tmp_path,
including the certs.d trust root, which is injected through the ``home``
parameter.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
_scripts = str(ROOT / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from importlib.util import module_from_spec, spec_from_file_location  # noqa: E402

import build_release_images as bri  # noqa: E402
import release_safe_io  # noqa: E402

_spec = spec_from_file_location(
    "producer_build_custom_provider", ROOT / "scripts/producer_build_custom_provider.py"
)
assert _spec and _spec.loader
producer = module_from_spec(_spec)
sys.modules[_spec.name] = producer
_spec.loader.exec_module(producer)


HEAD = "e" * 40
EPOCH = 1789000000
CONTAINER_ID = "a" * 64
PROVIDER_IMAGE_ID = "sha256:" + "c" * 64
PUSHED_DIGEST = "sha256:" + "b" * 64
BASE_IMAGE_ID = "sha256:" + "d" * 64
CGROUP_PARENT = (
    "/user.slice/user-1000.slice/user@1000.service/stateport.slice/"
    "stateport-heavy.slice/stateport-heavy-123-456.service"
)
FAKE_CRT = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
FAKE_KEY = "fake-key-material-not-a-real-key\n"
CONTEXT_FILES = (
    "BUBBLEWRAP-LICENSE",
    "BUBBLEWRAP-NOTICE",
    "Containerfile",
    "LICENSE",
    "NOTICE",
    "bwrap",
    "codex",
    "provider-metadata.json",
    "rg",
)
EXECUTABLES = {"bwrap", "codex", "rg"}
REGISTRY = "127.0.0.1:5001"


def base_config_entry() -> dict:
    return bri._load_yaml(bri.BASE_IMAGES)["images"]["registry-2"]


def make_context(tmp_path: Path) -> tuple[Path, Path]:
    """Build a 9-file context plus a matching provider receipt."""

    context = tmp_path / "provider-real-context"
    context.mkdir()
    files: dict[str, dict[str, object]] = {}
    for name in CONTEXT_FILES:
        content = f"payload-of-{name}\n".encode("utf-8")
        target = context / name
        target.write_bytes(content)
        target.chmod(0o555 if name in EXECUTABLES else 0o444)
        observed = target.stat()
        files[name] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": observed.st_size,
            "mode": "0o" + format(stat.S_IMODE(observed.st_mode), "04o"),
        }
    receipt_path = tmp_path / "provider-real-context-receipt.json"
    receipt_path.write_text(
        json.dumps(
            {
                "formatVersion": producer.CONTEXT_RECEIPT_FORMAT,
                "context": {"path": str(context), "files": files},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return context, receipt_path


def fake_image_observation(reference: object) -> dict:
    ref = str(reference)
    entry = base_config_entry()
    if ref == bri.REGISTRY_IMAGE:
        return {
            "imageId": BASE_IMAGE_ID,
            "digest": entry["indexDigest"],
            "observedDigests": [entry["indexDigest"], entry["platformManifestDigest"]],
            "os": "linux",
            "architecture": "amd64",
            "variant": None,
        }
    if ref.endswith("@" + entry["platformManifestDigest"]):
        return {
            "imageId": BASE_IMAGE_ID,
            "digest": entry["platformManifestDigest"],
            "observedDigests": [entry["indexDigest"], entry["platformManifestDigest"]],
            "os": "linux",
            "architecture": "amd64",
            "variant": None,
        }
    if ref.endswith(":producer-r1"):
        return {
            "imageId": PROVIDER_IMAGE_ID,
            "digest": PUSHED_DIGEST,
            "observedDigests": [PUSHED_DIGEST],
            "os": "linux",
            "architecture": "amd64",
            "variant": None,
        }
    raise AssertionError(f"unexpected image observation: {ref}")


class _FakeSocket:
    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def setsockopt(self, *_args: object) -> None:
        return None

    def bind(self, address: tuple[str, int]) -> None:
        assert address == ("127.0.0.1", 5001)


def install_fake_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(producer.socket, "socket", lambda *_args: _FakeSocket())


def happy_run(
    calls: list[list[str]],
    *,
    pushed_digest: str = PUSHED_DIGEST,
    head: str = HEAD,
    epoch: str = str(EPOCH),
):
    """A fake ``bri._run`` covering git, openssl, podman and builder probes."""

    def _run(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        calls.append(argv)
        if argv[0].endswith("git"):
            if argv[1:3] == ["rev-parse", "HEAD"]:
                return head
            if argv[1:3] == ["rev-parse", "--verify"]:
                return head
            if argv[1:2] == ["status"]:
                return ""
            if argv[1:3] == ["show", "-s"]:
                return epoch
            raise AssertionError(f"unexpected git call: {argv}")
        if argv[0].endswith("openssl"):
            for flag, content in (("-keyout", FAKE_KEY), ("-out", FAKE_CRT)):
                if flag in argv:
                    Path(argv[argv.index(flag) + 1]).write_text(content, encoding="ascii")
            return ""
        if argv[1:2] == ["version"] and "--format" in argv:
            return json.dumps({"Client": {"Version": "6.1.0"}})
        if argv[1:2] == ["info"] and "--format" in argv:
            return json.dumps(
                {
                    "host": {
                        "os": "linux",
                        "arch": "amd64",
                        "cgroupVersion": "v2",
                        "security": {"rootless": True},
                    },
                    "store": {"graphDriverName": "overlay"},
                }
            )
        if argv[0].endswith("podman"):
            if argv[1:3] == ["container", "inspect"]:
                if argv[-1] == CONTAINER_ID:
                    return json.dumps(
                        [
                            {
                                "Id": CONTAINER_ID,
                                "Image": BASE_IMAGE_ID,
                                "Labels": dict(producer.MANAGED_REGISTRY_LABELS),
                            }
                        ]
                    )
                raise AssertionError(f"unexpected inspect target: {argv}")
            if "run" in argv:
                return CONTAINER_ID
            if argv[1:2] == ["push"]:
                digest_file = Path(argv[argv.index("--digestfile") + 1])
                digest_file.write_text(pushed_digest + "\n", encoding="ascii")
                return ""
            if argv[1:2] in (["stop"], ["rm"]) or "build" in argv:
                return ""
            raise AssertionError(f"unexpected podman call: {argv}")
        raise AssertionError(f"unexpected command: {argv}")

    return _run


def builder_descriptor(tmp_path: Path) -> Path:
    executable = tmp_path / "podman-under-test"
    executable.write_bytes(b"#!/bin/false\n")
    executable.chmod(0o755)
    digest = "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
    descriptor = {
        "formatVersion": "stateport.release-builder-descriptor/v1",
        "executablePath": str(executable),
        "executableDigest": digest,
        "name": "podman",
        "version": "6.1.0",
        "artifact": {"uri": "https://example.invalid/podman", "digest": digest},
    }
    path = tmp_path / "builder-descriptor.json"
    path.write_text(json.dumps(descriptor), encoding="utf-8")
    return path


def base_record_ok() -> dict:
    entry = base_config_entry()
    return {
        "baseId": "registry-2",
        "reference": entry["reference"],
        "indexDigest": entry["indexDigest"],
        "platformManifestDigest": entry["platformManifestDigest"],
        "platform": "linux/amd64",
        "imageId": BASE_IMAGE_ID,
        "observedDigests": [entry["indexDigest"], entry["platformManifestDigest"]],
        "verification": "exact-index-and-platform-manifest",
    }


def tls_record(tmp_path: Path) -> dict:
    tls_dir = tmp_path / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    ca = tls_dir / "ca.crt"
    ca.write_text(FAKE_CRT, encoding="ascii")
    server = tls_dir / "server.crt"
    server.write_text(FAKE_CRT, encoding="ascii")
    return {
        "directory": str(tls_dir),
        "caCert": str(ca),
        "caKey": str(tls_dir / "ca.key"),
        "serverCert": str(server),
        "serverKey": str(tls_dir / "server.key"),
        "caCertDigest": bri.sha256_file(ca),
        "serverCertDigest": bri.sha256_file(server),
        "subjectAltName": "IP:127.0.0.1,DNS:localhost",
        "validityDays": 2,
        "scope": "per-run-loopback-registry-only",
    }


# ---------------------------------------------------------------------------
# D7/P3: context verification


def test_context_verification_accepts_exact_nine_files(tmp_path: Path) -> None:
    context, receipt_path = make_context(tmp_path)
    record = producer.verify_context(context, receipt_path)
    assert record["fileCount"] == 9
    assert set(record["files"]) == set(CONTEXT_FILES)
    assert record["files"]["codex"]["mode"] == "0o555"
    assert record["files"]["Containerfile"]["mode"] == "0o444"
    assert record["receiptDigest"].startswith("sha256:")


@pytest.mark.parametrize(
    "mutation", ["tamper", "missing", "extra", "mode", "subdir", "symlink", "eight"]
)
def test_context_verification_refuses_drift(tmp_path: Path, mutation: str) -> None:
    context, receipt_path = make_context(tmp_path)
    if mutation == "tamper":
        target = context / "NOTICE"
        target.chmod(0o644)
        target.write_bytes(b"tampered\n")
        target.chmod(0o444)
    elif mutation == "missing":
        (context / "rg").unlink()
    elif mutation == "extra":
        (context / "unreviewed.sh").write_bytes(b"extra\n")
    elif mutation == "mode":
        (context / "codex").chmod(0o444)
    elif mutation == "subdir":
        (context / "nested").mkdir()
    elif mutation == "symlink":
        link = tmp_path / "outside"
        link.write_bytes(b"outside\n")
        (context / "bwrap").unlink()
        (context / "bwrap").symlink_to(link)
    elif mutation == "eight":
        receipt = json.loads(receipt_path.read_text())
        del receipt["context"]["files"]["rg"]
        receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(producer.ProducerBuildError):
        producer.verify_context(context, receipt_path)


def test_context_verification_refuses_unsupported_receipt(tmp_path: Path) -> None:
    context, receipt_path = make_context(tmp_path)
    receipt = json.loads(receipt_path.read_text())
    receipt["formatVersion"] = "stateport.provider-real-context-receipt/v0"
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(producer.ProducerBuildError, match="formatVersion"):
        producer.verify_context(context, receipt_path)


# ---------------------------------------------------------------------------
# D6: digestfile validation (reused read path)


def test_observed_digest_accepts_valid_and_locks_mode(tmp_path: Path) -> None:
    digest_file = tmp_path / "push.digest"
    digest_file.write_text(PUSHED_DIGEST + "\n", encoding="ascii")
    digest_file.chmod(0o640)
    assert bri._read_observed_digest(digest_file) == PUSHED_DIGEST
    assert stat.S_IMODE(digest_file.stat().st_mode) == 0o400


@pytest.mark.parametrize("kind", ["oversize", "invalid", "symlink", "missing"])
def test_observed_digest_refuses_unsafe_output(tmp_path: Path, kind: str) -> None:
    digest_file = tmp_path / "push.digest"
    if kind == "oversize":
        digest_file.write_text("sha256:" + "b" * 64 + "\n" + "x" * 200, encoding="ascii")
    elif kind == "invalid":
        digest_file.write_text("sha256:" + "Z" * 64 + "\n", encoding="ascii")
    elif kind == "symlink":
        outside = tmp_path / "outside"
        outside.write_text(PUSHED_DIGEST, encoding="ascii")
        digest_file.symlink_to(outside)
    with pytest.raises(bri.ReleaseBuildError):
        bri._read_observed_digest(digest_file)


# ---------------------------------------------------------------------------
# D6: double-build argv and digest equality


def test_double_build_commands_are_byte_identical_with_required_flags() -> None:
    context = Path("/external/provider-real-context")
    command_one = producer.producer_build_command(
        registry=REGISTRY, context=context, epoch=EPOCH, cgroup_parent=CGROUP_PARENT
    )
    command_two = producer.producer_build_command(
        registry=REGISTRY, context=context, epoch=EPOCH, cgroup_parent=CGROUP_PARENT
    )
    assert command_one == command_two
    assert command_one[1:3] == ["--cgroup-manager=cgroupfs", "build"]
    assert command_one[command_one.index("--cgroup-parent") + 1].startswith(
        CGROUP_PARENT + "/stateport-build-"
    )
    assert "--isolation=oci" in command_one
    for flag in ("--no-cache", "--pull=never", "--network=private"):
        assert flag in command_one
    assert command_one[command_one.index("--format") + 1] == "docker"
    assert command_one[command_one.index("--platform") + 1] == "linux/amd64"
    assert command_one[command_one.index("--timestamp") + 1] == str(EPOCH)
    assert command_one[command_one.index("-f") + 1] == str(context / "Containerfile")
    assert command_one[command_one.index("-t") + 1] == (
        f"{REGISTRY}/{producer.PROVIDER_REPOSITORY}:{producer.PRODUCER_TAG_NAME}"
    )
    assert command_one[-1] == str(context)


def test_push_command_pins_tls_and_docker_format(tmp_path: Path) -> None:
    command = producer.producer_push_command(REGISTRY, tmp_path / "d.digest")
    assert command[1] == "push"
    assert "--tls-verify=false" in command
    assert command[command.index("--format") + 1] == "docker"
    assert command[-1] == f"docker://{REGISTRY}/{producer.PROVIDER_REPOSITORY}:producer-r1"


def test_double_build_enforces_pushed_digest_equality(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    digests = iter([PUSHED_DIGEST, "sha256:" + "9" * 64])

    def _run(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        calls.append(argv)
        if argv[1:2] == ["push"]:
            Path(argv[argv.index("--digestfile") + 1]).write_text(
                next(digests) + "\n", encoding="ascii"
            )
        return ""

    monkeypatch.setattr(bri, "_run", _run)
    digest_root = tmp_path / "digests"
    digest_root.mkdir()
    with pytest.raises(
        producer.ProducerBuildError, match="not OCI-digest reproducible"
    ):
        producer.execute_double_build(
            build_command=["podman", "build"],
            registry=REGISTRY,
            digest_root=digest_root,
        )
    pushes = [argv for argv in calls if argv[1:2] == ["push"]]
    assert len(pushes) == 2
    assert (tmp_path / "digests/producer-r1-build1.digest").exists()
    assert (tmp_path / "digests/producer-r1-build2.digest").exists()


def test_double_build_records_both_identical_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    digest_root = tmp_path / "digests"
    digest_root.mkdir()
    observations, pushed = producer.execute_double_build(
        build_command=producer.producer_build_command(
            registry=REGISTRY,
            context=Path("/external/ctx"),
            epoch=EPOCH,
            cgroup_parent=CGROUP_PARENT,
        ),
        registry=REGISTRY,
        digest_root=digest_root,
    )
    assert pushed == PUSHED_DIGEST
    assert observations[0]["command"] == observations[1]["command"]
    assert [entry["ordinal"] for entry in observations] == [1, 2]
    assert {entry["pushedDigest"] for entry in observations} == {PUSHED_DIGEST}


# ---------------------------------------------------------------------------
# D3: EPOCH derivation


def test_epoch_derives_from_head_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    record = producer.derive_epoch(None)
    assert record["head"] == HEAD
    assert record["epoch"] == EPOCH
    assert record["epochDerivationCommand"] == ["git", "show", "-s", "--format=%ct", HEAD]
    assert any(argv[1:3] == ["rev-parse", "HEAD"] for argv in calls)


def test_epoch_accepts_only_admitted_head(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def divergent_run(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        calls.append(argv)
        if argv[1:3] == ["rev-parse", "--verify"]:
            return "f" * 40  # the named head resolves, but is not the current HEAD
        return happy_run(calls)(arguments)

    monkeypatch.setattr(bri, "_run", happy_run(calls))
    assert producer.derive_epoch(HEAD)["head"] == HEAD
    with pytest.raises(producer.ProducerBuildError, match="full SHA-1"):
        producer.derive_epoch(HEAD[:12])
    monkeypatch.setattr(bri, "_run", divergent_run)
    with pytest.raises(producer.ProducerBuildError, match="differs"):
        producer.derive_epoch("f" * 40)


def test_epoch_refuses_dirty_tree_or_bad_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def dirty_run(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        if argv[1:2] == ["status"]:
            return " M scripts/build_release_images.py\n"
        return happy_run(calls)(arguments)

    monkeypatch.setattr(bri, "_run", dirty_run)
    with pytest.raises(producer.ProducerBuildError, match="clean committed tree"):
        producer.derive_epoch(None)

    def bad_epoch_run(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        if argv[1:3] == ["show", "-s"]:
            return "not-a-number"
        return happy_run(calls)(arguments)

    monkeypatch.setattr(bri, "_run", bad_epoch_run)
    with pytest.raises(producer.ProducerBuildError, match="numeric committer timestamp"):
        producer.derive_epoch(None)


# ---------------------------------------------------------------------------
# D5: governor membership and output-root guards


def test_producer_refuses_outside_governor_before_any_podman_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def refuse() -> str:
        raise bri.ReleaseBuildError("not inside a governor service")

    calls: list[str] = []
    monkeypatch.setattr(bri, "governor_cgroup_parent", refuse)
    monkeypatch.setattr(bri, "verify_podman_builder", lambda: calls.append("podman"))
    context, receipt_path = make_context(tmp_path)
    with pytest.raises(bri.ReleaseBuildError, match="governor"):
        producer.producer_build(
            context=context,
            context_receipt=receipt_path,
            output_root=tmp_path / "out",
            registry=REGISTRY,
        )
    assert calls == []


def test_output_root_must_be_new_and_outside_repository(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    with pytest.raises(Exception, match="outside the repository"):
        bri.prepare_output_root(repository / "evidence", repository=repository)
    existing = tmp_path / "existing-root"
    existing.mkdir()
    with pytest.raises(Exception, match="new directory"):
        bri.prepare_output_root(existing, repository=repository)
    created = bri.prepare_output_root(tmp_path / "fresh-root", repository=repository)
    assert created.is_dir()
    assert stat.S_IMODE(created.stat().st_mode) == 0o700


# ---------------------------------------------------------------------------
# D4: registry base verification


def test_registry_base_verification_binds_config_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bri, "_image_observation", fake_image_observation)
    record = producer.verify_registry_base()
    entry = base_config_entry()
    assert record["baseId"] == "registry-2"
    assert record["reference"] == bri.REGISTRY_IMAGE
    assert record["indexDigest"] == entry["indexDigest"]
    assert record["platformManifestDigest"] == entry["platformManifestDigest"]
    assert record["imageId"] == BASE_IMAGE_ID
    assert record["verification"] == "exact-index-and-platform-manifest"


@pytest.mark.parametrize(
    "mutation",
    ["missing_entry", "reference_drift", "missing_platform", "image_mismatch", "wrong_arch"],
)
def test_registry_base_verification_refuses_mutations(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    entry = base_config_entry()
    if mutation == "missing_entry":
        monkeypatch.setattr(bri, "_load_yaml", lambda _path: {"images": {}})
    elif mutation == "reference_drift":
        monkeypatch.setattr(
            bri,
            "_load_yaml",
            lambda _path: {
                "images": {
                    "registry-2": {
                        **entry,
                        "reference": "docker.io/library/registry:2",
                    }
                }
            },
        )
        with pytest.raises(producer.ProducerBuildError, match="pinned release registry"):
            producer.verify_registry_base()
        return
    else:
        observations = {
            bri.REGISTRY_IMAGE: fake_image_observation(bri.REGISTRY_IMAGE),
            entry["reference"].rsplit("@", 1)[0]
            + "@"
            + entry["platformManifestDigest"]: fake_image_observation(
                entry["reference"].rsplit("@", 1)[0]
                + "@"
                + entry["platformManifestDigest"]
            ),
        }
        if mutation == "missing_platform":
            observations[bri.REGISTRY_IMAGE]["observedDigests"] = [entry["indexDigest"]]
        elif mutation == "image_mismatch":
            observations[
                entry["reference"].rsplit("@", 1)[0]
                + "@"
                + entry["platformManifestDigest"]
            ]["imageId"] = "sha256:" + "0" * 64
        elif mutation == "wrong_arch":
            observations[bri.REGISTRY_IMAGE]["architecture"] = "arm64"
        monkeypatch.setattr(bri, "_image_observation", lambda ref: observations[str(ref)])
    with pytest.raises(producer.ProducerBuildError):
        producer.verify_registry_base()


# ---------------------------------------------------------------------------
# D4: registry lifecycle


def test_registry_start_runs_pinned_image_with_tls_and_records_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    monkeypatch.setattr(bri, "_image_observation", fake_image_observation)
    monkeypatch.setattr(producer, "_wait_registry_health", lambda *_a, **_k: True)
    storage = tmp_path / "registry-storage"
    storage.mkdir(mode=0o700)
    record = producer.start_producer_registry(
        REGISTRY,
        name="stateport-producer-registry-test",
        storage=storage,
        tls=tls_record(tmp_path),
        base_record=base_record_ok(),
        cgroup_parent=CGROUP_PARENT,
    )
    run_command = next(argv for argv in calls if "run" in argv)
    assert run_command[1:3] == ["--cgroup-manager=cgroupfs", "run"]
    assert run_command[run_command.index("--cgroup-parent") + 1] == CGROUP_PARENT
    assert "--pull=never" in run_command
    assert run_command[run_command.index("--publish") + 1] == f"{REGISTRY}:5000"
    joined = " ".join(run_command)
    assert bri.REGISTRY_IMAGE in joined
    assert any("/var/lib/registry:Z" in part for part in run_command)
    assert any("/certs:Z" in part for part in run_command)
    assert "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.crt" in run_command
    assert "REGISTRY_HTTP_TLS_KEY=/certs/server.key" in run_command
    assert run_command[run_command.index("--label") + 1] == "io.stateport.managed=true"
    assert record["containerId"] == CONTAINER_ID
    assert record["endpoint"] == REGISTRY
    assert record["storageIdentity"]["path"] == str(storage)
    assert record["healthEndpoint"] == f"https://{REGISTRY}/v2/"
    assert record["baseVerification"]["platformManifestDigest"] == (
        base_config_entry()["platformManifestDigest"]
    )
    assert record["imageId"] == BASE_IMAGE_ID
    assert record["imageObservation"]["imageId"] == BASE_IMAGE_ID


def test_registry_start_reobserves_live_image_right_before_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    events: list[str] = []
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(producer, "_wait_registry_health", lambda *_a, **_k: True)

    def observed(reference: object) -> dict:
        events.append("observe")
        return fake_image_observation(reference)

    def run(arguments: list[str], **kwargs: object) -> str:
        events.append("run")
        return happy_run(calls)(arguments, **kwargs)

    monkeypatch.setattr(bri, "_image_observation", observed)
    monkeypatch.setattr(bri, "_run", run)
    storage = tmp_path / "registry-storage"
    storage.mkdir(mode=0o700)
    record = producer.start_producer_registry(
        REGISTRY,
        name="stateport-producer-registry-test",
        storage=storage,
        tls=tls_record(tmp_path),
        base_record=base_record_ok(),
        cgroup_parent=None,
    )
    assert events.index("observe") < events.index("run")
    assert record["imageId"] == BASE_IMAGE_ID


def test_registry_start_refuses_live_image_drift_before_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    monkeypatch.setattr(producer, "_wait_registry_health", lambda *_a, **_k: True)
    drifted = fake_image_observation(bri.REGISTRY_IMAGE)
    drifted["imageId"] = "sha256:" + "0" * 64
    monkeypatch.setattr(bri, "_image_observation", lambda _reference: drifted)
    with pytest.raises(producer.ProducerBuildError, match="pre-pulled qualified"):
        producer.start_producer_registry(
            REGISTRY,
            name="stateport-producer-registry-test",
            storage=tmp_path / "registry-storage",
            tls=tls_record(tmp_path),
            base_record=base_record_ok(),
            cgroup_parent=None,
        )
    assert calls == []


def test_registry_start_force_removes_container_when_unhealthy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    monkeypatch.setattr(bri, "_image_observation", fake_image_observation)
    monkeypatch.setattr(producer, "_wait_registry_health", lambda *_a, **_k: False)
    storage = tmp_path / "registry-storage"
    storage.mkdir(mode=0o700)
    with pytest.raises(producer.ProducerBuildError, match="healthy"):
        producer.start_producer_registry(
            REGISTRY,
            name="stateport-producer-registry-test",
            storage=storage,
            tls=tls_record(tmp_path),
            base_record=base_record_ok(),
            cgroup_parent=CGROUP_PARENT,
        )
    removal = next(argv for argv in calls if argv[1:2] == ["rm"])
    assert removal == [str(bri.PODMAN), "rm", "--force", CONTAINER_ID]


def test_registry_start_refuses_existing_container_or_bad_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_container_exists", lambda _name: True)
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    with pytest.raises(producer.ProducerBuildError, match="already exists"):
        producer.start_producer_registry(
            REGISTRY,
            name="stateport-producer-registry-test",
            storage=tmp_path / "registry-storage",
            tls=tls_record(tmp_path),
            base_record=base_record_ok(),
            cgroup_parent=None,
        )
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_image_observation", fake_image_observation)

    def bad_id(arguments: list[str], **_kwargs: object) -> str:
        calls.append([str(item) for item in arguments])
        return "not-a-container-id"

    monkeypatch.setattr(bri, "_run", bad_id)
    with pytest.raises(producer.ProducerBuildError, match="container ID"):
        producer.start_producer_registry(
            REGISTRY,
            name="stateport-producer-registry-test",
            storage=tmp_path / "registry-storage-2",
            tls=tls_record(tmp_path),
            base_record=base_record_ok(),
            cgroup_parent=None,
        )


def test_registry_start_refuses_incomplete_base_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    incomplete = base_record_ok()
    incomplete["verification"] = "unverified"
    with pytest.raises(producer.ProducerBuildError, match="base verification"):
        producer.start_producer_registry(
            REGISTRY,
            name="stateport-producer-registry-test",
            storage=tmp_path / "registry-storage",
            tls=tls_record(tmp_path),
            base_record=incomplete,
            cgroup_parent=None,
        )


def test_registry_stop_removes_by_exact_recorded_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    record = producer.stop_producer_registry(
        {"containerId": CONTAINER_ID, "name": "unused-name"}
    )
    assert record["cleanup"] == "container-removed-by-exact-id"
    assert [argv[1:2] for argv in calls] == [["stop"], ["rm"]]
    assert calls[0][-3:] == ["--time", "10", CONTAINER_ID]
    assert calls[1][-1] == CONTAINER_ID
    assert all("unused-name" not in argv for argv in calls)


# ---------------------------------------------------------------------------
# D1: certs.d trust write/remove


def test_certs_d_trust_write_and_identity_checked_removal(tmp_path: Path) -> None:
    home = tmp_path / "home"
    record = producer.install_certs_d_trust(tls_record(tmp_path), REGISTRY, home=home)
    target = home / ".config/containers/certs.d/127.0.0.1:5001/ca.crt"
    assert record["path"] == str(target)
    assert record["written"] is True
    assert target.is_file()
    assert stat.S_IMODE(target.stat().st_mode) == 0o444
    assert target.read_text() == FAKE_CRT
    removed = producer.remove_certs_d_trust(record)
    assert removed["removed"] is True
    assert not target.exists()
    assert not target.parent.exists()
    assert not target.parent.parent.exists()
    assert removed["prunedEmptyDirs"][-1].endswith("certs.d")


def test_certs_d_refuses_existing_entry(tmp_path: Path) -> None:
    home = tmp_path / "home"
    producer.install_certs_d_trust(tls_record(tmp_path), REGISTRY, home=home)
    with pytest.raises(producer.ProducerBuildError, match="already exists"):
        producer.install_certs_d_trust(tls_record(tmp_path / "tls2"), REGISTRY, home=home)


def test_certs_d_refuses_tampered_entry_before_removal(tmp_path: Path) -> None:
    home = tmp_path / "home"
    record = producer.install_certs_d_trust(tls_record(tmp_path), REGISTRY, home=home)
    target = Path(record["path"])
    target.chmod(0o644)
    target.write_text("tampered-ca\n", encoding="ascii")
    with pytest.raises(producer.ProducerBuildError, match="changed after write"):
        producer.remove_certs_d_trust(record)
    assert target.exists()


def test_certs_d_refuses_missing_entry_or_foreign_location(tmp_path: Path) -> None:
    home = tmp_path / "home"
    record = producer.install_certs_d_trust(tls_record(tmp_path), REGISTRY, home=home)
    Path(record["path"]).unlink()
    with pytest.raises(producer.ProducerBuildError, match="disappeared"):
        producer.remove_certs_d_trust(record)
    foreign = home / "elsewhere/ca.crt"
    foreign.parent.mkdir(parents=True)
    foreign.write_text(FAKE_CRT, encoding="ascii")
    with pytest.raises(producer.ProducerBuildError, match="certs.d"):
        producer.remove_certs_d_trust(
            {"path": str(foreign), "caDigest": record["caDigest"]}
        )


def test_certs_d_write_survives_short_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    real_write = os.write
    progress: list[int] = []

    def short_write(descriptor: int, data: object) -> int:
        written = real_write(descriptor, bytes(data[:1]))
        progress.append(written)
        return written

    monkeypatch.setattr(producer.os, "write", short_write)
    record = producer.install_certs_d_trust(tls_record(tmp_path), REGISTRY, home=home)
    assert len(progress) == len(FAKE_CRT)
    assert Path(record["path"]).read_text(encoding="ascii") == FAKE_CRT


# ---------------------------------------------------------------------------
# Identity-checked teardown


def test_teardown_reports_storage_identity_mismatch(tmp_path: Path) -> None:
    storage = tmp_path / "registry-storage"
    storage.mkdir(mode=0o700)
    identity = bri.directory_identity(storage)
    shutil.rmtree(storage)
    storage.mkdir(mode=0o700)
    teardown, errors = producer._teardown(
        registry_record=None,
        output=tmp_path,
        storage_identity=identity,
        certs_record=None,
    )
    assert teardown["storage"] == "removal-failed"
    assert errors and "storage:" in errors[0]


def test_teardown_reports_container_removal_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bri, "_container_exists", lambda _name: True)

    def refusing_stop(_arguments: list[str], **_kwargs: object) -> str:
        raise bri.ReleaseBuildError("stop failed")

    monkeypatch.setattr(bri, "_run", refusing_stop)
    teardown, errors = producer._teardown(
        registry_record={"containerId": CONTAINER_ID, "name": "n"},
        output=None,
        storage_identity=None,
        certs_record=None,
    )
    assert teardown["container"] == "removal-failed"
    assert errors and "container:" in errors[0]


# ---------------------------------------------------------------------------
# D7: full receipt through the orchestrator


def test_producer_build_writes_complete_receipt_and_tears_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    context, receipt_path = make_context(tmp_path)
    home = tmp_path / "home"
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_image_observation", fake_image_observation)
    monkeypatch.setattr(bri, "governor_cgroup_parent", lambda: CGROUP_PARENT)
    monkeypatch.setattr(producer, "_wait_registry_health", lambda *_a, **_k: True)
    monkeypatch.setenv("STATEPORT_RELEASE_BUILDER_DESCRIPTOR", str(builder_descriptor(tmp_path)))
    output_root = tmp_path / "producer-run"

    receipt = producer.producer_build(
        context=context,
        context_receipt=receipt_path,
        output_root=output_root,
        registry=REGISTRY,
        head=HEAD,
        guard_receipt_digest="sha256:guard",
        home=home,
    )

    # D7: receipt completeness.
    assert receipt["formatVersion"] == producer.RECEIPT_FORMAT
    assert receipt["result"] == "succeeded"
    assert receipt["outputRoot"] == str(output_root)
    assert Path(receipt["outputRoot"]).is_absolute()
    assert receipt["identity"]["head"] == HEAD
    assert receipt["identity"]["epoch"] == EPOCH
    assert receipt["identity"]["epochDerivationCommand"] == [
        "git",
        "show",
        "-s",
        "--format=%ct",
        HEAD,
    ]
    assert receipt["guard"] == {
        "action": "image_build",
        "cgroupParent": CGROUP_PARENT,
        "receiptDigest": "sha256:guard",
    }
    assert receipt["builder"]["executablePath"].endswith("podman-under-test")
    assert receipt["builder"]["version"] == "6.1.0"
    assert receipt["builder"]["executableDigest"].startswith("sha256:")
    assert receipt["contextReceipt"]["receiptDigest"].startswith("sha256:")
    assert receipt["contextReceipt"]["fileCount"] == 9
    assert set(receipt["contextReceipt"]["files"]) == set(CONTEXT_FILES)
    assert receipt["buildArgvIdentical"] is True
    assert receipt["reproducible"] is True
    assert [entry["ordinal"] for entry in receipt["builds"]] == [1, 2]
    assert receipt["builds"][0]["command"] == receipt["builds"][1]["command"]
    assert all(
        entry["pushedDigest"] == PUSHED_DIGEST for entry in receipt["builds"]
    )
    assert all(
        "--tls-verify=false" in entry["pushCommand"]
        and "--digestfile" in entry["pushCommand"]
        and entry["pushCommand"][entry["pushCommand"].index("--format") + 1] == "docker"
        for entry in receipt["builds"]
    )
    assert receipt["manifestDigest"] == PUSHED_DIGEST
    assert receipt["platformManifestDigest"] == PUSHED_DIGEST
    assert receipt["image"]["imageId"] == PROVIDER_IMAGE_ID
    assert receipt["acceptedReference"] == (
        f"{REGISTRY}/{producer.PROVIDER_REPOSITORY}@{PUSHED_DIGEST}"
    )
    assert receipt["registry"]["containerId"] == CONTAINER_ID
    assert receipt["registry"]["storageIdentity"]["path"] == str(
        output_root / producer.STORAGE_DIR
    )
    assert receipt["registry"]["baseVerification"]["indexDigest"] == (
        base_config_entry()["indexDigest"]
    )
    assert receipt["registry"]["cleanup"] == "container-removed-by-exact-id"
    assert receipt["registry"]["storageResult"] == "removed-identity-checked"
    assert receipt["tls"]["caCertDigest"].startswith("sha256:")
    assert receipt["certsD"]["written"] is True
    assert receipt["certsD"]["removed"] is True
    assert receipt["certsD"]["path"] == str(
        home / ".config/containers/certs.d/127.0.0.1:5001/ca.crt"
    )

    # Teardown really happened on disk.
    assert receipt["registry"]["containerId"] in [
        argv[-1] for argv in calls if argv[1:2] == ["stop"]
    ]
    assert not (output_root / producer.STORAGE_DIR).exists()
    assert not (home / ".config/containers/certs.d").exists()

    # The receipt file itself is retained create-only under the output root.
    persisted = json.loads(
        (output_root / producer.RECEIPT_NAME).read_text(encoding="utf-8")
    )
    assert persisted == receipt
    digests = output_root / producer.DIGESTS_DIR
    assert sorted(p.name for p in digests.iterdir()) == [
        "producer-r1-build1.digest",
        "producer-r1-build2.digest",
    ]


def test_producer_build_writes_failure_record_and_tears_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    context, receipt_path = make_context(tmp_path)
    home = tmp_path / "home"
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_image_observation", fake_image_observation)
    monkeypatch.setattr(bri, "governor_cgroup_parent", lambda: CGROUP_PARENT)
    monkeypatch.setattr(producer, "_wait_registry_health", lambda *_a, **_k: True)
    monkeypatch.setenv("STATEPORT_RELEASE_BUILDER_DESCRIPTOR", str(builder_descriptor(tmp_path)))

    def unequal_digests(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        calls.append(argv)
        if argv[1:2] == ["push"]:
            ordinal = 1 if argv[argv.index("--digestfile") + 1].endswith("build1.digest") else 2
            Path(argv[argv.index("--digestfile") + 1]).write_text(
                "sha256:" + f"{ordinal}" * 64 + "\n", encoding="ascii"
            )
            return ""
        return happy_run(calls)(arguments)

    monkeypatch.setattr(bri, "_run", unequal_digests)
    output_root = tmp_path / "producer-run"
    with pytest.raises(producer.ProducerBuildError, match="not OCI-digest reproducible"):
        producer.producer_build(
            context=context,
            context_receipt=receipt_path,
            output_root=output_root,
            registry=REGISTRY,
            head=HEAD,
            home=home,
        )
    failure = json.loads(
        (output_root / producer.FAILURE_NAME).read_text(encoding="utf-8")
    )
    assert failure["formatVersion"] == producer.FAILURE_FORMAT
    assert failure["errorType"] == "ProducerBuildError"
    assert failure["teardown"]["container"] == "container-removed-by-exact-id"
    assert failure["teardown"]["storage"] == "removed-identity-checked"
    assert failure["teardown"]["certsD"] == "removed-identity-checked"
    assert not (output_root / producer.RECEIPT_NAME).exists()
    assert not (home / ".config/containers/certs.d").exists()


def test_producer_build_refuses_success_receipt_after_failed_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, receipt_path = make_context(tmp_path)
    home = tmp_path / "home"
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_run", happy_run([]))
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_image_observation", fake_image_observation)
    monkeypatch.setattr(bri, "governor_cgroup_parent", lambda: CGROUP_PARENT)
    monkeypatch.setattr(producer, "_wait_registry_health", lambda *_a, **_k: True)
    monkeypatch.setenv("STATEPORT_RELEASE_BUILDER_DESCRIPTOR", str(builder_descriptor(tmp_path)))

    def break_storage_removal(root: Path, relative: str, *, expected_identity) -> None:
        raise release_safe_io.ReleaseIOError("cleanup target identity changed")

    monkeypatch.setattr(producer, "remove_tree_exact", break_storage_removal)
    with pytest.raises(producer.ProducerBuildError, match="teardown failed"):
        producer.producer_build(
            context=context,
            context_receipt=receipt_path,
            output_root=tmp_path / "producer-run",
            registry=REGISTRY,
            head=HEAD,
            home=home,
        )


# ---------------------------------------------------------------------------
# Guard wiring


def test_main_binds_image_build_guard_and_default_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_guard(action: str, argv: list[str] | None = None) -> str:
        captured["action"] = action
        captured["argv"] = list(argv or [])
        return "sha256:guard"

    def fake_build(**kwargs):
        captured["kwargs"] = kwargs
        return {"result": "succeeded"}

    monkeypatch.setattr(producer, "require_guard", fake_guard)
    monkeypatch.setattr(producer, "producer_build", fake_build)
    exit_code = producer.main(
        [
            "--context",
            "/external/ctx",
            "--context-receipt",
            "/external/ctx-receipt.json",
            "--output-root",
            "/external/out",
        ]
    )
    assert exit_code == 0
    assert captured["action"] == "image_build"
    assert captured["argv"][0].endswith("producer_build_custom_provider.py")
    assert captured["kwargs"]["registry"] == "127.0.0.1:5001"
    assert captured["kwargs"]["guard_receipt_digest"] == "sha256:guard"
    assert captured["kwargs"]["head"] is None


def test_main_forwards_explicit_head_and_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}
    monkeypatch.setattr(producer, "require_guard", lambda _a, _v: "sha256:guard")
    monkeypatch.setattr(
        producer, "producer_build", lambda **kwargs: captured.update(kwargs) or {}
    )
    producer.main(
        [
            "--context",
            "/external/ctx",
            "--context-receipt",
            "/external/ctx-receipt.json",
            "--output-root",
            "/external/out",
            "--registry-host",
            "127.0.0.1",
            "--port",
            "5001",
            "--head",
            HEAD,
        ]
    )
    assert captured["registry"] == "127.0.0.1:5001"
    assert captured["head"] == HEAD


def test_main_refuses_non_loopback_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(producer, "require_guard", lambda _a, _v: "sha256:guard")
    with pytest.raises(bri.ReleaseBuildError, match="loopback"):
        producer.main(
            [
                "--context",
                "/external/ctx",
                "--context-receipt",
                "/external/ctx-receipt.json",
                "--output-root",
                "/external/out",
                "--registry-host",
                "registry.example",
            ]
        )


def test_main_refuses_reserved_consumer_port(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setattr(
        producer,
        "require_guard",
        lambda *_a, **_k: pytest.fail("guard must not run for a refused port"),
    )
    with pytest.raises(SystemExit) as refused:
        producer.main(
            [
                "--context",
                "/external/ctx",
                "--context-receipt",
                "/external/ctx-receipt.json",
                "--output-root",
                "/external/out",
                "--port",
                "5000",
            ]
        )
    assert refused.value.code == 2
    assert "reserved for the consumer rebuild" in capsys.readouterr().err


def test_main_accepts_non_reserved_port(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    monkeypatch.setattr(producer, "require_guard", lambda _a, _v: "sha256:guard")
    monkeypatch.setattr(
        producer,
        "producer_build",
        lambda **kwargs: captured.update(kwargs) or {"result": "succeeded"},
    )
    exit_code = producer.main(
        [
            "--context",
            "/external/ctx",
            "--context-receipt",
            "/external/ctx-receipt.json",
            "--output-root",
            "/external/out",
            "--port",
            "5001",
        ]
    )
    assert exit_code == 0
    assert captured["registry"] == "127.0.0.1:5001"


def test_producer_build_refuses_reserved_consumer_port_before_any_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("no work may run for the reserved consumer port")

    monkeypatch.setattr(bri, "_run", unexpected)
    monkeypatch.setattr(bri, "governor_cgroup_parent", unexpected)
    with pytest.raises(producer.ProducerBuildError, match="reserved for the consumer rebuild"):
        producer.producer_build(
            context=Path("/external/ctx"),
            context_receipt=Path("/external/ctx-receipt.json"),
            output_root=Path("/external/out"),
            registry="127.0.0.1:5000",
            head=HEAD,
        )


def test_entrypoint_maps_timeout_expired_to_clean_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    def timing_out(_argv: list[str] | None = None) -> int:
        raise subprocess.TimeoutExpired(cmd=["podman", "build"], timeout=7200)

    monkeypatch.setattr(producer, "main", timing_out)
    assert producer.entrypoint([]) == 2
    assert "producer build refused" in capsys.readouterr().err


def test_entrypoint_maps_release_io_error_to_clean_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    def failing_main(_argv: list[str] | None = None) -> int:
        raise release_safe_io.ReleaseIOError("success receipt could not be written")

    monkeypatch.setattr(producer, "main", failing_main)
    assert producer.entrypoint([]) == 2
    assert "producer build refused" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Reuse sanity: the imported builder verification is the real one


def test_verify_podman_builder_reuse_via_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setenv("STATEPORT_RELEASE_BUILDER_DESCRIPTOR", str(builder_descriptor(tmp_path)))
    monkeypatch.setattr(bri, "_run", happy_run(calls))
    builder = producer.bri.verify_podman_builder()
    assert builder["name"] == "podman"
    assert builder["version"] == "6.1.0"
    assert builder["rootless"] is True
    assert builder["platform"] == "linux/amd64"
    assert any(argv[1:2] == ["version"] for argv in calls)


# ---------------------------------------------------------------------------
# F2: --keep-registry retention


def run_producer_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    calls: list[list[str]],
    *,
    keep_registry: bool,
    run_override=None,
):
    """Drive a fully mocked producer build and return its receipt/exception."""

    context, receipt_path = make_context(tmp_path)
    home = tmp_path / "home"
    install_fake_socket(monkeypatch)
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    monkeypatch.setattr(bri, "_image_observation", fake_image_observation)
    monkeypatch.setattr(bri, "governor_cgroup_parent", lambda: CGROUP_PARENT)
    monkeypatch.setattr(producer, "_wait_registry_health", lambda *_a, **_k: True)
    monkeypatch.setenv("STATEPORT_RELEASE_BUILDER_DESCRIPTOR", str(builder_descriptor(tmp_path)))
    monkeypatch.setattr(bri, "_run", run_override or happy_run(calls))
    return producer.producer_build(
        context=context,
        context_receipt=receipt_path,
        output_root=tmp_path / "producer-run",
        registry=REGISTRY,
        head=HEAD,
        guard_receipt_digest="sha256:guard",
        home=home,
        keep_registry=keep_registry,
    )


def test_keep_registry_success_retains_and_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    output_root = tmp_path / "producer-run"
    receipt = run_producer_build(
        tmp_path, monkeypatch, calls, keep_registry=True
    )

    retention = receipt["registryRetention"]
    assert retention["mode"] == producer.RETENTION_MODE
    assert retention["containerId"] == CONTAINER_ID
    assert retention["storageIdentity"] == receipt["registry"]["storageIdentity"]
    assert retention["certsPath"] == receipt["certsD"]["path"]
    assert retention["retainedAt"].endswith("Z")

    assert receipt["registry"]["cleanup"] == producer.RETENTION_MODE
    assert receipt["registry"]["storageResult"] == producer.RETENTION_MODE
    assert "stoppedAt" not in receipt["registry"]
    assert receipt["certsD"].get("removed") is not True

    # Nothing teardown-shaped happened: no stop/rm, storage and trust intact.
    assert not any(argv[1:2] in (["stop"], ["rm"]) for argv in calls)
    assert (output_root / producer.STORAGE_DIR).is_dir()
    assert (Path(retention["certsPath"])).is_file()
    assert (output_root / producer.RECEIPT_NAME).is_file()


def test_keep_registry_failure_still_tears_down_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    digests = iter(["sha256:" + "1" * 64, "sha256:" + "2" * 64])

    def unequal_digests(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        calls.append(argv)
        if argv[1:2] == ["push"]:
            Path(argv[argv.index("--digestfile") + 1]).write_text(
                next(digests) + "\n", encoding="ascii"
            )
            return ""
        return happy_run(calls)(arguments)

    home = tmp_path / "home"
    output_root = tmp_path / "producer-run"
    with pytest.raises(producer.ProducerBuildError, match="not OCI-digest reproducible"):
        run_producer_build(
            tmp_path, monkeypatch, calls, keep_registry=True, run_override=unequal_digests
        )
    failure = json.loads((output_root / producer.FAILURE_NAME).read_text(encoding="utf-8"))
    assert failure["teardown"]["container"] == "container-removed-by-exact-id"
    assert failure["teardown"]["storage"] == "removed-identity-checked"
    assert failure["teardown"]["certsD"] == "removed-identity-checked"
    assert not (output_root / producer.STORAGE_DIR).exists()
    assert not (home / ".config/containers/certs.d").exists()
    assert any(argv[1:2] == ["stop"] and argv[-1] == CONTAINER_ID for argv in calls)
    assert not (output_root / producer.RECEIPT_NAME).exists()


def test_keep_registry_receipt_write_failure_revokes_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ReleaseIOError deriving from ValueError must still trigger teardown."""

    calls: list[list[str]] = []
    home = tmp_path / "home"
    output_root = tmp_path / "producer-run"
    real_write_json = producer.write_json_create_only

    def failing_receipt_only(root: Path, relative: str, value: object) -> Path:
        if relative == producer.RECEIPT_NAME:
            raise release_safe_io.ReleaseIOError(
                "success receipt path is not writable"
            )
        return real_write_json(root, relative, value)

    monkeypatch.setattr(producer, "write_json_create_only", failing_receipt_only)
    with pytest.raises(release_safe_io.ReleaseIOError, match="not writable") as refused:
        run_producer_build(tmp_path, monkeypatch, calls, keep_registry=True)

    # ReleaseIOError is a ValueError, so the CLI entrypoint exits non-zero (2).
    assert isinstance(refused.value, ValueError)

    failure = json.loads((output_root / producer.FAILURE_NAME).read_text(encoding="utf-8"))
    assert failure["formatVersion"] == producer.FAILURE_FORMAT
    assert failure["errorType"] == "ReleaseIOError"
    assert failure["teardown"]["container"] == "container-removed-by-exact-id"
    assert failure["teardown"]["storage"] == "removed-identity-checked"
    assert failure["teardown"]["certsD"] == "removed-identity-checked"

    # The retained registry really was stopped, removed and unhooked.
    assert any(argv[1:2] == ["stop"] and argv[-1] == CONTAINER_ID for argv in calls)
    assert any(argv[1:2] == ["rm"] and argv[-1] == CONTAINER_ID for argv in calls)
    assert not (output_root / producer.STORAGE_DIR).exists()
    assert not (home / ".config/containers/certs.d").exists()
    assert not (output_root / producer.RECEIPT_NAME).exists()


# ---------------------------------------------------------------------------
# F2: retained teardown mode


def retained_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict, Path]:
    """Produce a retained receipt and prepare the teardown mock surface."""

    calls: list[list[str]] = []
    receipt = run_producer_build(tmp_path, monkeypatch, calls, keep_registry=True)
    receipt_path = tmp_path / "producer-run" / producer.RECEIPT_NAME
    return receipt_path, receipt, tmp_path / "home"


def test_retained_teardown_happy_path_writes_sidecar_and_receipt_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_path, receipt, home = retained_run(tmp_path, monkeypatch)
    receipt_bytes = receipt_path.read_bytes()
    teardown_calls: list[list[str]] = []
    monkeypatch.setattr(bri, "_run", happy_run(teardown_calls))
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)

    report = producer.retained_registry_teardown(receipt_path)

    assert report["formatVersion"] == producer.TEARDOWN_FORMAT
    assert report["retentionMode"] == producer.RETENTION_MODE
    assert report["errors"] == []
    assert report["receiptSha256"] == "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()
    assert report["verified"]["container"]["observedContainerId"] == CONTAINER_ID
    assert report["verified"]["container"]["imageId"] == BASE_IMAGE_ID
    assert report["verified"]["container"]["labels"] == dict(
        producer.MANAGED_REGISTRY_LABELS
    )
    assert report["verified"]["storage"]["observedIdentity"]["path"] == str(
        tmp_path / "producer-run" / producer.STORAGE_DIR
    )
    assert report["verified"]["certsD"]["caDigest"] == receipt["certsD"]["caDigest"]
    assert report["removed"]["container"] == "container-removed-by-exact-id"
    assert report["removed"]["storage"] == "removed-identity-checked"
    assert report["removed"]["certsD"] == "removed-identity-checked"
    assert report["startedAt"].endswith("Z") and report["finishedAt"].endswith("Z")

    # Removals happened by exact identity, in the real filesystem.
    stops = [argv for argv in teardown_calls if argv[1:2] == ["stop"]]
    rms = [argv for argv in teardown_calls if argv[1:2] == ["rm"]]
    assert [argv[-1] for argv in stops] == [CONTAINER_ID]
    assert [argv[-1] for argv in rms] == [CONTAINER_ID]
    assert not (tmp_path / "producer-run" / producer.STORAGE_DIR).exists()
    assert not (home / ".config/containers/certs.d").exists()
    assert report["removed"]["prunedEmptyDirs"][-1].endswith("certs.d")

    # Create-only sidecar beside the receipt; receipt itself untouched.
    sidecar = receipt_path.parent / producer.TEARDOWN_NAME
    persisted = json.loads(sidecar.read_text(encoding="utf-8"))
    assert persisted == report
    assert receipt_path.read_bytes() == receipt_bytes


def test_retained_teardown_refuses_container_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_path, _receipt, home = retained_run(tmp_path, monkeypatch)
    expected_id = "b" * 64

    def wrong_container(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        if argv[1:3] == ["container", "inspect"]:
            return json.dumps(
                [
                    {
                        "Id": expected_id,
                        "Image": BASE_IMAGE_ID,
                        "Labels": dict(producer.MANAGED_REGISTRY_LABELS),
                    }
                ]
            )
        return happy_run([])(arguments)

    monkeypatch.setattr(bri, "_run", wrong_container)
    storage = tmp_path / "producer-run" / producer.STORAGE_DIR
    with pytest.raises(producer.ProducerBuildError, match="container identity mismatch"):
        producer.retained_registry_teardown(receipt_path)
    assert storage.is_dir()
    assert (home / ".config/containers/certs.d").exists()
    assert not (receipt_path.parent / producer.TEARDOWN_NAME).exists()


def test_retained_teardown_refuses_container_label_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_path, _receipt, home = retained_run(tmp_path, monkeypatch)
    drifted = dict(producer.MANAGED_REGISTRY_LABELS)
    drifted["io.stateport.purpose"] = "something-else"

    def drifted_labels(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        if argv[1:3] == ["container", "inspect"]:
            return json.dumps(
                [{"Id": CONTAINER_ID, "Image": BASE_IMAGE_ID, "Labels": drifted}]
            )
        return happy_run([])(arguments)

    monkeypatch.setattr(bri, "_run", drifted_labels)
    with pytest.raises(producer.ProducerBuildError, match="labels mismatch"):
        producer.retained_registry_teardown(receipt_path)
    assert (home / ".config/containers/certs.d").exists()
    assert not (receipt_path.parent / producer.TEARDOWN_NAME).exists()


def test_retained_teardown_refuses_container_image_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_path, _receipt, home = retained_run(tmp_path, monkeypatch)

    def wrong_image(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        if argv[1:3] == ["container", "inspect"]:
            return json.dumps(
                [
                    {
                        "Id": CONTAINER_ID,
                        "Image": "sha256:" + "0" * 64,
                        "Labels": dict(producer.MANAGED_REGISTRY_LABELS),
                    }
                ]
            )
        return happy_run([])(arguments)

    monkeypatch.setattr(bri, "_run", wrong_image)
    storage = tmp_path / "producer-run" / producer.STORAGE_DIR
    with pytest.raises(producer.ProducerBuildError, match="image mismatch"):
        producer.retained_registry_teardown(receipt_path)
    assert storage.is_dir()
    assert (home / ".config/containers/certs.d").exists()
    assert not (receipt_path.parent / producer.TEARDOWN_NAME).exists()


def test_retained_teardown_refuses_missing_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_path, _receipt, home = retained_run(tmp_path, monkeypatch)

    def missing_container(arguments: list[str], **_kwargs: object) -> str:
        argv = [str(item) for item in arguments]
        if argv[1:3] == ["container", "inspect"]:
            raise bri.ReleaseBuildError("no such container")
        return happy_run([])(arguments)

    monkeypatch.setattr(bri, "_run", missing_container)
    with pytest.raises(
        producer.ProducerBuildError, match="missing or uninspectable"
    ):
        producer.retained_registry_teardown(receipt_path)
    assert (home / ".config/containers/certs.d").exists()


def test_retained_teardown_refuses_storage_identity_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_path, _receipt, home = retained_run(tmp_path, monkeypatch)
    # Recreate the storage directory: new inode, same path.
    storage = tmp_path / "producer-run" / producer.STORAGE_DIR
    shutil.rmtree(storage)
    storage.mkdir(mode=0o700)
    teardown_calls: list[list[str]] = []
    monkeypatch.setattr(bri, "_run", happy_run(teardown_calls))
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    with pytest.raises(producer.ProducerBuildError, match="storage identity mismatch"):
        producer.retained_registry_teardown(receipt_path)
    assert storage.is_dir()
    assert (home / ".config/containers/certs.d").exists()
    assert not any(argv[1:2] == ["stop"] for argv in teardown_calls)
    assert not (receipt_path.parent / producer.TEARDOWN_NAME).exists()


def test_retained_teardown_refuses_certs_digest_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_path, receipt, home = retained_run(tmp_path, monkeypatch)
    target = Path(receipt["certsD"]["path"])
    target.chmod(0o644)
    target.write_text("tampered-ca\n", encoding="ascii")
    teardown_calls: list[list[str]] = []
    monkeypatch.setattr(bri, "_run", happy_run(teardown_calls))
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    with pytest.raises(producer.ProducerBuildError, match="digest mismatch"):
        producer.retained_registry_teardown(receipt_path)
    assert target.exists()
    assert (tmp_path / "producer-run" / producer.STORAGE_DIR).is_dir()
    assert not any(argv[1:2] == ["stop"] for argv in teardown_calls)
    assert not (receipt_path.parent / producer.TEARDOWN_NAME).exists()


def test_retained_teardown_refuses_non_retained_or_unsafe_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    run_producer_build(tmp_path, monkeypatch, calls, keep_registry=False)
    default_receipt = tmp_path / "producer-run" / producer.RECEIPT_NAME
    with pytest.raises(producer.ProducerBuildError, match="no retained registry"):
        producer.retained_registry_teardown(default_receipt)

    retained_base = tmp_path / "retained"
    retained_base.mkdir()
    retained_path, _receipt, _home = retained_run(retained_base, monkeypatch)
    receipt = json.loads(retained_path.read_text(encoding="utf-8"))
    receipt["formatVersion"] = "stateport.producer-build-receipt/v0"
    retained_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(producer.ProducerBuildError, match="formatVersion"):
        producer.retained_registry_teardown(retained_path)


def test_retained_teardown_refuses_when_sidecar_already_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_path, _receipt, home = retained_run(tmp_path, monkeypatch)
    sidecar = receipt_path.parent / producer.TEARDOWN_NAME
    sidecar.write_text('{"formatVersion": "earlier-run"}\n', encoding="utf-8")
    monkeypatch.setattr(bri, "_run", happy_run([]))
    monkeypatch.setattr(bri, "_container_exists", lambda _name: False)
    with pytest.raises(producer.ProducerBuildError, match="must not run twice"):
        producer.retained_registry_teardown(receipt_path)
    assert sidecar.read_text(encoding="utf-8") == '{"formatVersion": "earlier-run"}\n'
    assert (home / ".config/containers/certs.d").exists()


# ---------------------------------------------------------------------------
# F2: CLI mode wiring


def test_main_teardown_mode_skips_guard_and_uses_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_calls: list[str] = []
    teardown_calls: list[Path] = []

    def fake_guard(action: str, argv: list[str] | None = None) -> str:
        guard_calls.append(action)
        return "sha256:guard"

    def fake_teardown(receipt_path: Path) -> dict:
        teardown_calls.append(receipt_path)
        return {"formatVersion": producer.TEARDOWN_FORMAT}

    monkeypatch.setattr(producer, "require_guard", fake_guard)
    monkeypatch.setattr(producer, "retained_registry_teardown", fake_teardown)
    receipt_path = tmp_path / producer.RECEIPT_NAME
    exit_code = producer.main(["--teardown", "--receipt", str(receipt_path)])
    assert exit_code == 0
    assert guard_calls == []
    assert teardown_calls == [receipt_path]


def test_main_refuses_teardown_without_receipt_or_receipt_without_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setattr(
        producer,
        "require_guard",
        lambda *_a, **_k: pytest.fail("guard must not run for a refused CLI"),
    )
    with pytest.raises(SystemExit) as missing:
        producer.main(["--teardown"])
    assert missing.value.code == 2
    with pytest.raises(SystemExit) as orphan:
        producer.main(
            [
                "--context",
                "/external/ctx",
                "--context-receipt",
                "/external/ctx-receipt.json",
                "--output-root",
                "/external/out",
                "--receipt",
                str(tmp_path / producer.RECEIPT_NAME),
            ]
        )
    assert orphan.value.code == 2
    with pytest.raises(SystemExit) as bare:
        producer.main([])
    assert bare.value.code == 2
    assert "required in build mode" in capsys.readouterr().err


def test_main_build_mode_forwards_keep_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}
    monkeypatch.setattr(producer, "require_guard", lambda _a, _v: "sha256:guard")

    def fake_build(**kwargs):
        captured.update(kwargs)
        return {"result": "succeeded"}

    monkeypatch.setattr(producer, "producer_build", fake_build)
    producer.main(
        [
            "--context",
            "/external/ctx",
            "--context-receipt",
            "/external/ctx-receipt.json",
            "--output-root",
            "/external/out",
            "--keep-registry",
        ]
    )
    assert captured["keep_registry"] is True


def test_help_documents_both_modes_and_retention_lifecycle(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setattr("sys.argv", ["producer_build_custom_provider.py", "--help"])
    with pytest.raises(SystemExit) as requested:
        producer.main(["--help"])
    assert requested.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    for needle in (
        "--keep-registry",
        "--teardown",
        "--receipt",
        producer.RETENTION_MODE,
        "consumer rebuild",
        "FAILED run still tears down everything",
        "recorded image ID",
        "removed manually by its exact recorded identity",
        "image_build governor action",
    ):
        assert needle in text, needle


def test_module_docstring_documents_manual_teardown_recovery() -> None:
    text = " ".join((producer.__doc__ or "").split())
    assert "removed manually by its exact recorded identity after inspection" in text
