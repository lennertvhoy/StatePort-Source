#!/usr/bin/env python3
"""Static checks for the first self-hosted Compose shape."""

from pathlib import Path
import importlib.util
import json
import os
import stat
import sys
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_compose_has_api_and_instance_first_web_services() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "stateport-api:" in text and "stateport-web:" in text and "stateport-worker:" in text
    assert '"127.0.0.1:${STATEPORT_WEB_PORT:-8080}:8080"' in text
    assert "STATEPORT_API_PORT" not in text and "STATEPORT_WORKER_PORT" not in text
    assert "network_mode" not in text
    assert "read_only: true" in text
    assert "no-new-privileges:true" in text
    assert "executionEnabled" not in text
    assert text.count("stateport-operations:/workspace/.stateport") == 2
    assert "volumes:\n  stateport-operations:" in text
    compose = yaml.safe_load(text)
    assert all(service.get("init") is True for service in compose["services"].values())
    assert all(
        service["logging"]
        == {"driver": "json-file", "options": {"max-size": "1m", "max-file": "3"}}
        for service in compose["services"].values()
    )
    for service_name in ("stateport-api", "stateport-worker"):
        service = compose["services"][service_name]
        assert "ports" not in service
        assert service["environment"]["STATEPORT_LOG_LEVEL"] == "${STATEPORT_LOG_LEVEL:-info}"
        assert service["healthcheck"]["test"][-1] == "/readyz"
        assert service["healthcheck"]["test"][1] == "/usr/local/bin/stateport-healthcheck"
        dockerfile = (ROOT / service["build"]["dockerfile"]).read_text(encoding="utf-8")
        assert "COPY packages/observability/src" in dockerfile
        assert "/workspace/packages/observability/src" in dockerfile


def test_compose_web_uses_the_single_same_origin_appserver() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    web = compose["services"]["stateport-web"]
    dockerfile = (ROOT / web["build"]["dockerfile"]).read_text(encoding="utf-8")
    wrapper = (ROOT / "apps" / "web" / "container-service.py").read_text(encoding="utf-8")
    source_root = ROOT / "packages" / "persistent-app" / "src" / "stateport_persistent_app"
    base_entry = (source_root / "service_entry.py").read_text(encoding="utf-8")
    cancellation_entry = (source_root / "service_cancellation_entry.py").read_text(encoding="utf-8")
    resilient_entry = (source_root / "service_resilient_entry.py").read_text(encoding="utf-8")

    # The product container must never regress to a static-only server. The
    # final entry is a thin extension chain over the original AppServer: base
    # assistant events, per-work cancellation, then retryable redelivery. No
    # second HTTP server, static authority, or conversation authority is added.
    assert "http.server" not in dockerfile
    assert "stateport_persistent_app.service_resilient_entry import main" in wrapper
    assert "from stateport_persistent_app import service_process as base" in base_entry
    assert "class AssistantHandler(base.Handler)" in base_entry
    assert "super().do_GET()" in base_entry
    assert "class CancellableAssistantHandler(base_entry.AssistantHandler)" in cancellation_entry
    assert "super().do_POST()" in cancellation_entry
    assert "class ResilientAssistantHandler(CancellableAssistantHandler)" in resilient_entry
    assert "super()._assistant_event_payload(event, record)" in resilient_entry
    assert "service_process.Handler = ResilientAssistantHandler" in resilient_entry
    assert "return service_process.main(remaining)" in resilient_entry
    assert "ThreadingHTTPServer" not in base_entry
    assert "ThreadingHTTPServer" not in cancellation_entry
    assert "ThreadingHTTPServer" not in resilient_entry
    assert (
        json.dumps(
            [
                "python3",
                "/workspace/apps/web/container-service.py",
                "--port",
                "8080",
                "--repo-root",
                "/workspace",
                "--host",
                "0.0.0.0",
                "--allow-public-bind",
                "--actor-role",
                "platform_operator",
            ]
        )
        in dockerfile
    )
    # Cross-platform networking: host mode is Linux-only, so the container
    # binds 0.0.0.0 on the private bridge (gated by AppServer's explicit
    # --allow-public-bind flag) while host exposure stays loopback-only via
    # the port mapping on every platform, including Docker Desktop.
    assert "network_mode" not in web
    assert web["ports"] == ["127.0.0.1:${STATEPORT_WEB_PORT:-8080}:8080"]
    assert web["environment"] == {"STATEPORT_EXTERNAL_LOOPBACK_PORT": "${STATEPORT_WEB_PORT:-8080}"}
    assert web["networks"] == ["stateport"]
    assert compose["networks"]["stateport"]["driver"] == "bridge"
    assert "depends_on" not in web
    assert web["healthcheck"]["test"][-1] == "/health"
    assert web["healthcheck"]["test"][1] == "/usr/local/bin/stateport-healthcheck"

    build_args = web["build"]["args"]
    assert build_args == {
        "STATEPORT_BUILD_SOURCE_COMMIT": "${STATEPORT_BUILD_SOURCE_COMMIT:-unknown}",
        "STATEPORT_BUILD_SOURCE_TREE": "${STATEPORT_BUILD_SOURCE_TREE:-unknown}",
        "STATEPORT_BUILD_SOURCE_REF": "${STATEPORT_BUILD_SOURCE_REF:-unknown}",
        "STATEPORT_BUILD_SOURCE_DIRTY": "${STATEPORT_BUILD_SOURCE_DIRTY:-true}",
        "STATEPORT_BUILD_SOURCE_DATE_EPOCH": "${STATEPORT_BUILD_SOURCE_DATE_EPOCH:-unknown}",
        "STATEPORT_BUILD_VERSION": "${STATEPORT_BUILD_VERSION:-0.0.0-source}",
        "STATEPORT_BUILD_CREATED": "${STATEPORT_BUILD_CREATED:-1970-01-01T00:00:00Z}",
        "STATEPORT_BUILD_ADAPTER": "${STATEPORT_BUILD_ADAPTER:-source-compose-unknown}",
    }
    assert all(service["build"]["args"] == build_args for service in compose["services"].values())
    for required in (
        "ARG STATEPORT_BUILD_SOURCE_COMMIT=unknown",
        "ARG STATEPORT_BUILD_SOURCE_TREE=unknown",
        "ARG STATEPORT_BUILD_SOURCE_REF=unknown",
        "ARG STATEPORT_BUILD_SOURCE_DIRTY=true",
        "ARG STATEPORT_BUILD_SOURCE_DATE_EPOCH=unknown",
        "ARG STATEPORT_BUILD_VERSION=0.0.0-unknown",
        "ARG STATEPORT_BUILD_CREATED=1970-01-01T00:00:00Z",
        "ARG STATEPORT_BUILD_ADAPTER=unknown",
        'org.opencontainers.image.revision="${STATEPORT_BUILD_SOURCE_COMMIT}"',
        'io.stateport.source.tree="${STATEPORT_BUILD_SOURCE_TREE}"',
        'org.opencontainers.image.ref.name="${STATEPORT_BUILD_SOURCE_REF}"',
        'io.stateport.source.dirty="${STATEPORT_BUILD_SOURCE_DIRTY}"',
        'io.stateport.source-date-epoch="${STATEPORT_BUILD_SOURCE_DATE_EPOCH}"',
        'org.opencontainers.image.version="${STATEPORT_BUILD_VERSION}"',
        'org.opencontainers.image.created="${STATEPORT_BUILD_CREATED}"',
        'io.stateport.build.adapter="${STATEPORT_BUILD_ADAPTER}"',
    ):
        assert required in dockerfile
    volumes = web["volumes"]
    # Source-build compose runs from a Git checkout, and the AppServer
    # validates the exact runtime Git identity of the product root at startup
    # (_validate_product_root). The read-only .git mount is therefore required
    # here; the no-.git pull model belongs to digest-pinned release Quadlets,
    # not to the source-build path.
    assert "./.git:/workspace/.git:ro,z" in volumes
    assert "stateport-product-data:/var/lib/stateport" in volumes
    assert "stateport-product-data" in compose["volumes"]


def _load_container_service_module():
    path = ROOT / "apps" / "web" / "container-service.py"
    spec = importlib.util.spec_from_file_location("container_service_under_test", path)
    module = importlib.util.module_from_spec(spec)
    # The module imports the service entry at import time; provide the real
    # source-tree path so the import chain resolves, then stub the entry main.
    for parent in (ROOT / "packages", ROOT / "apps"):
        for source in sorted(parent.glob("*/src")):
            if source.is_dir():
                sys.path.insert(0, str(source))
    sys.modules["stateport_persistent_app.service_resilient_entry"] = type(
        sys)("stateport_persistent_app.service_resilient_entry")
    sys.modules["stateport_persistent_app.service_resilient_entry"].main = lambda: 0
    spec.loader.exec_module(module)
    return module


def test_platform_operator_authority_bootstrap_creates_private_file_once() -> None:
    module = _load_container_service_module()
    with tempfile.TemporaryDirectory() as tmp:
        config_root = Path(tmp) / "config" / "stateport"
        config_root.mkdir(parents=True)
        old = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = str(config_root.parent)
        try:
            module._bootstrap_platform_operator_authority()
            boundary = config_root / "platform-operator-authority"
            assert boundary.is_file()
            mode = stat.S_IMODE(boundary.stat().st_mode)
            assert mode == 0o600, oct(mode)
            assert boundary.stat().st_uid == os.geteuid()
            # Second call (existing file) must not fail or replace it.
            module._bootstrap_platform_operator_authority()
            assert boundary.read_bytes() == b""
        finally:
            if old is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = old


def test_platform_operator_authority_bootstrap_keeps_existing_file() -> None:
    module = _load_container_service_module()
    with tempfile.TemporaryDirectory() as tmp:
        config_root = Path(tmp) / "config" / "stateport"
        config_root.mkdir(parents=True)
        boundary = config_root / "platform-operator-authority"
        boundary.write_bytes(b"operator-owned")
        os.chmod(boundary, 0o600)
        old = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = str(config_root.parent)
        try:
            module._bootstrap_platform_operator_authority()
            assert boundary.read_bytes() == b"operator-owned"
        finally:
            if old is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = old


def test_compose_has_no_live_provider_or_secret_defaults() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8").lower()
    assert "telegram" not in text
    assert "api_key" not in text and "token:" not in text


def test_docker_build_context_excludes_secrets_and_generated_files() -> None:
    patterns = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    for required in (
        ".git",
        ".env",
        ".env.*",
        "secrets",
        "private",
        "*.tfstate",
        "*.tfstate.*",
        "**/__pycache__",
        "**/*.pyc",
    ):
        assert required in patterns


def test_runner_image_is_explicit_and_contains_no_provider_configuration() -> None:
    text = (ROOT / "apps" / "runner" / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 65532:65532" in text
    assert 'CMD ["python3", "-m", "runner", "/stateport/instance"]' in text
    lowered = text.lower()
    assert "api_key" not in lowered and "token=" not in lowered


if __name__ == "__main__":
    test_compose_has_api_and_instance_first_web_services()
    test_compose_web_uses_the_single_same_origin_appserver()
    test_compose_has_no_live_provider_or_secret_defaults()
    test_docker_build_context_excludes_secrets_and_generated_files()
    test_runner_image_is_explicit_and_contains_no_provider_configuration()
    print("PASS")
