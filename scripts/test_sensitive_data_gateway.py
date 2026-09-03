#!/usr/bin/env python3
"""Public-safe regression tests for the headless sensitive-data slice."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "sensitive-data-gateway" / "src"))

from stateport_sensitive_data import (  # noqa: E402
    BrokerRefusal,
    CapabilityBroker,
    DeterministicScanner,
    GatewayBlocked,
    GatewayFailure,
    InMemorySecretStore,
    SecretRequirement,
    SensitiveDataGateway,
    SensitiveDataPolicy,
    verify_values_absent,
)


NOW = "2026-07-28T18:00:00Z"
LATER = "2026-07-28T18:05:00Z"


def private_key_fixture() -> str:
    header = "-----" + "BEGIN " + "PRIVATE" + " KEY-----"
    footer = "-----" + "END " + "PRIVATE" + " KEY-----"
    return header + "\n" + ("RmljdGlvbmFsS2V5Qnl0ZXM=" * 3) + "\n" + footer


def secret_fixture() -> str:
    # Runtime assembly keeps the complete synthetic value out of repository
    # source and compiled test artifacts.
    return "".join(("fictional", "-", "capability", "-", "material", "-", "alpha", "-", "7391"))


def requirement() -> SecretRequirement:
    return SecretRequirement(
        requirement_id="requirement.fixture-api",
        display_name="Fictional fixture API",
        purpose="Exercise a local mock operation",
        expected_interface="mock.fixture/v1",
        capability="fixture.lookup",
        scope="project.demo",
    )


def test_prompt_attachment_and_selected_context_are_scanned_without_value_evidence() -> None:
    gateway = SensitiveDataGateway(DeterministicScanner())
    key = private_key_fixture()
    for kind in ("prompt", "attachment", "selected_context"):
        with pytest.raises(GatewayBlocked) as refused:
            gateway.sanitize_ingress({kind: "please inspect\n" + key})
        serialized = json.dumps([asdict(item) for item in refused.value.findings], sort_keys=True)
        assert key not in serialized
        assert all(not hasattr(item, "matched_value") for item in refused.value.findings)


def test_email_is_stably_redacted_and_possible_name_is_not_confirmed() -> None:
    gateway = SensitiveDataGateway(DeterministicScanner())
    text = "Contact: Ada Example\nEmail: ada@example.invalid\nAgain: ada@example.invalid"
    decision = gateway.redact(text, source_kind="prompt")
    assert "ada@example.invalid" not in decision.sanitized_text
    assert decision.placeholders == ("[PERSON_1]", "[EMAIL_1]")
    assert decision.sanitized_text.count("[EMAIL_1]") == 2
    person = next(item for item in decision.findings if item.category == "person")
    assert person.confidence == "possible_sensitive"
    assert person.action == "review"


def test_final_payload_scan_is_separate_and_fails_closed_on_detection_or_scanner_error() -> None:
    gateway = SensitiveDataGateway(DeterministicScanner())
    safe, _ = gateway.sanitize_ingress({"prompt": "Summarize the fixture."})
    safe["late_template"] = private_key_fixture()
    with pytest.raises(GatewayBlocked, match="provider_serialization"):
        gateway.serialize_provider_payload(safe)

    serialized, receipt = gateway.serialize_provider_payload({"late_retrieval": "ada@example.invalid"})
    assert b"ada@example.invalid" not in serialized
    assert b"[EMAIL_" in serialized
    assert receipt.outcome == "sanitized"

    class BrokenScanner(DeterministicScanner):
        def scan(self, *args: object, **kwargs: object):
            raise RuntimeError("fixture scanner crash")

    with pytest.raises(GatewayFailure, match="failed closed"):
        SensitiveDataGateway(BrokenScanner()).serialize_provider_payload({"prompt": "safe"})


def test_store_api_separates_metadata_and_mock_broker_exposes_only_opaque_reference() -> None:
    store = InMemorySecretStore(clock=lambda: NOW, token=lambda size: "a" * (size * 2))
    value = secret_fixture()
    reference = store.create(requirement(), value)
    metadata = store.metadata(reference.reference_id)
    assert value not in json.dumps(reference.to_dict())
    assert value not in json.dumps(metadata.to_dict())
    assert not hasattr(store, "get") and not hasattr(store, "reveal")

    scanner = DeterministicScanner(exact_matcher=store.exact_matches)
    gateway = SensitiveDataGateway(scanner, SensitiveDataPolicy())
    broker = CapabilityBroker(store, gateway, clock=lambda: NOW, token=lambda size: "b" * (size * 2))
    request = broker.request(
        reference, run_id="run.fixture", operation="lookup", capability="fixture.lookup", scope="project.demo",
    )
    assert value not in json.dumps(request.to_dict())
    grant = broker.approve(request.request_id, expires_at=LATER)
    seen: list[str] = []

    def handler(material: str) -> str:
        seen.append(material)
        return "fictional lookup completed"

    output, receipt = broker.execute(
        grant.grant_id, run_id="run.fixture", operation="lookup",
        capability="fixture.lookup", scope="project.demo", handler=handler,
    )
    assert output == "fictional lookup completed"
    assert seen == [value]
    assert value not in json.dumps(receipt.to_dict())
    with pytest.raises(BrokerRefusal) as reused:
        broker.execute(
            grant.grant_id, run_id="run.fixture", operation="lookup",
            capability="fixture.lookup", scope="project.demo", handler=handler,
        )
    assert reused.value.code == "grant_already_consumed"
    assert seen == [value]


def test_blocked_private_key_can_be_replaced_by_an_opaque_reference_before_provider_serialization() -> None:
    store = InMemorySecretStore(clock=lambda: NOW, token=lambda size: "c" * (size * 2))
    key = private_key_fixture()
    reference = store.create(requirement(), key)
    gateway = SensitiveDataGateway(DeterministicScanner(exact_matcher=store.exact_matches))
    with pytest.raises(GatewayBlocked):
        gateway.sanitize_ingress({"prompt": "Use " + key})
    sanitized, _ = gateway.sanitize_ingress({"prompt": "Use " + reference.reference_id})
    serialized, _ = gateway.serialize_provider_payload(sanitized)
    assert key.encode("utf-8") not in serialized
    assert reference.reference_id.encode("utf-8") in serialized


def test_failed_operation_consumes_grant_and_never_retries() -> None:
    store = InMemorySecretStore(clock=lambda: NOW)
    reference = store.create(requirement(), secret_fixture())
    broker = CapabilityBroker(store, SensitiveDataGateway(DeterministicScanner(exact_matcher=store.exact_matches)), clock=lambda: NOW)
    request = broker.request(reference, run_id="run.fail", operation="lookup", capability="fixture.lookup", scope="project.demo")
    grant = broker.approve(request.request_id, expires_at=LATER)
    calls = 0

    def fail(_: str) -> str:
        nonlocal calls
        calls += 1
        raise RuntimeError("synthetic failure")

    with pytest.raises(BrokerRefusal) as failed:
        broker.execute(grant.grant_id, run_id="run.fail", operation="lookup", capability="fixture.lookup", scope="project.demo", handler=fail)
    assert failed.value.code == "capability_failed_no_retry"
    with pytest.raises(BrokerRefusal) as retry:
        broker.execute(grant.grant_id, run_id="run.fail", operation="lookup", capability="fixture.lookup", scope="project.demo", handler=fail)
    assert retry.value.code == "grant_already_consumed"
    assert calls == 1


def test_grant_is_exactly_bound_and_expired_grants_fail_without_execution() -> None:
    store = InMemorySecretStore(clock=lambda: NOW)
    reference = store.create(requirement(), secret_fixture())
    broker = CapabilityBroker(store, SensitiveDataGateway(DeterministicScanner(exact_matcher=store.exact_matches)), clock=lambda: NOW)
    request = broker.request(reference, run_id="run.bound", operation="lookup", capability="fixture.lookup", scope="project.demo")
    grant = broker.approve(request.request_id, expires_at=LATER)
    calls = 0

    def handler(_: str) -> str:
        nonlocal calls
        calls += 1
        return "should not run"

    with pytest.raises(BrokerRefusal) as mismatch:
        broker.execute(grant.grant_id, run_id="run.other", operation="lookup", capability="fixture.lookup", scope="project.demo", handler=handler)
    assert mismatch.value.code == "grant_binding_mismatch"
    assert calls == 0

    expired_broker = CapabilityBroker(store, SensitiveDataGateway(DeterministicScanner(exact_matcher=store.exact_matches)), clock=lambda: LATER)
    expired_request = expired_broker.request(reference, run_id="run.expired", operation="lookup", capability="fixture.lookup", scope="project.demo")
    with pytest.raises(BrokerRefusal) as invalid_expiry:
        expired_broker.approve(expired_request.request_id, expires_at=NOW)
    assert invalid_expiry.value.code == "grant_expiry_not_future"
    assert calls == 0


def test_revocation_refuses_new_grants_and_known_value_is_withheld_before_model_return() -> None:
    store = InMemorySecretStore(clock=lambda: NOW)
    value = secret_fixture()
    reference = store.create(requirement(), value)
    gateway = SensitiveDataGateway(DeterministicScanner(exact_matcher=store.exact_matches))
    broker = CapabilityBroker(store, gateway, clock=lambda: NOW)
    request = broker.request(reference, run_id="run.echo", operation="lookup", capability="fixture.lookup", scope="project.demo")
    grant = broker.approve(request.request_id, expires_at=LATER)
    with pytest.raises(BrokerRefusal) as withheld:
        broker.execute(
            grant.grant_id, run_id="run.echo", operation="lookup", capability="fixture.lookup",
            scope="project.demo", handler=lambda material: "echo=" + material,
        )
    assert withheld.value.code == "sensitive_output_withheld"
    store.revoke(reference.reference_id)
    with pytest.raises(BrokerRefusal) as revoked:
        broker.request(reference, run_id="run.after", operation="lookup", capability="fixture.lookup", scope="project.demo")
    assert revoked.value.code == "secret_revoked"


def test_revocation_between_request_and_approval_prevents_new_grant() -> None:
    store = InMemorySecretStore(clock=lambda: NOW)
    reference = store.create(requirement(), secret_fixture())
    broker = CapabilityBroker(store, SensitiveDataGateway(DeterministicScanner(exact_matcher=store.exact_matches)), clock=lambda: NOW)
    request = broker.request(reference, run_id="run.pending", operation="lookup", capability="fixture.lookup", scope="project.demo")
    store.revoke(reference.reference_id)
    with pytest.raises(BrokerRefusal) as revoked:
        broker.approve(request.request_id, expires_at=LATER)
    assert revoked.value.code == "secret_revoked"


def test_no_synthetic_material_is_persisted_in_receipts_or_test_artifacts(tmp_path: Path) -> None:
    store = InMemorySecretStore(clock=lambda: NOW)
    value = secret_fixture()
    reference = store.create(requirement(), value)
    gateway = SensitiveDataGateway(DeterministicScanner(exact_matcher=store.exact_matches))
    decision = gateway.redact("output=" + value, source_kind="tool_output")
    artifact = tmp_path / "evidence.json"
    artifact.write_text(json.dumps(decision.to_dict(), sort_keys=True), encoding="utf-8")
    assert value.encode("utf-8") not in artifact.read_bytes()
    assert value.encode("utf-8") not in json.dumps(store.metadata(reference.reference_id).to_dict()).encode("utf-8")
    for surface in ("state", "logs", "evidence", "screenshots", "frontend-storage", "test-artifacts"):
        directory = tmp_path / surface
        directory.mkdir()
        (directory / "metadata.json").write_text(json.dumps({"reference": reference.reference_id}), encoding="utf-8")
    receipt = verify_values_absent((tmp_path.resolve(), ROOT.resolve()), (value.encode("utf-8"),))
    assert receipt.outcome == "absent"
    assert receipt.excluded_directories >= 1
    assert value not in json.dumps(receipt.to_dict())


def test_negative_persistence_scan_never_follows_symlinks(tmp_path: Path) -> None:
    external = tmp_path.parent / (tmp_path.name + "-external")
    external.mkdir()
    (external / "secret.txt").write_bytes(secret_fixture().encode("utf-8"))
    (tmp_path / "external-link").symlink_to(external, target_is_directory=True)
    (tmp_path / "file-link").symlink_to(external / "secret.txt")

    receipt = verify_values_absent((tmp_path.resolve(),), (secret_fixture().encode("utf-8"),))

    assert receipt.outcome == "absent"
    assert receipt.symlinks_skipped == 2
