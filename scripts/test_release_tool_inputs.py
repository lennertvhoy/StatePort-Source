from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "release-contracts" / "src"))
from stateport_release.cosign import private_key_der_spki_fingerprint
spec = spec_from_file_location(
    "collect_release_evidence", ROOT / "scripts/collect_release_evidence.py"
)
assert spec and spec.loader
module = module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_installed_supply_chain_tools_match_pinned_versions_hashes_and_bottles() -> None:
    observed = module.verify_toolchain()
    assert set(observed) == {"syft", "grype", "cosign"}
    assert observed["syft"]["version"] == "1.51.0"
    assert observed["grype"]["version"] == "0.117.0"
    assert observed["cosign"]["version"] == "3.1.3"


def _ephemeral_cosign_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Generate an ephemeral, test-only Cosign key pair; never release evidence."""

    monkeypatch.setenv("COSIGN_PASSWORD", "test-ephemeral-non-release")
    cosign = "/home/linuxbrew/.linuxbrew/bin/cosign"
    subprocess.run(
        [cosign, "generate-key-pair", "--output-key-prefix", "test"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    return tmp_path / "test.pub"


def test_private_cosign_command_requires_exact_der_spki_key_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"artifact")
    bundle = tmp_path / "artifact.sigstore.json"
    bundle.write_text("{}")
    public_key = _ephemeral_cosign_key(tmp_path, monkeypatch)
    fingerprint = module.public_key_der_spki_fingerprint(public_key)
    assert fingerprint != module.sha256_file(public_key)
    command = module.signature_verification_command(
        artifact=artifact,
        bundle=bundle,
        public_key=public_key,
        expected_key_fingerprint=fingerprint,
        expected_key_id="stateport-alpha-private-2026-08",
        configured_key_id="stateport-alpha-private-2026-08",
    )
    assert command[0] == "/home/linuxbrew/.linuxbrew/bin/cosign"
    assert command[1] == "verify-blob"
    assert "--insecure-ignore-tlog" in command
    assert "--bundle" in command and "--key" in command
    with pytest.raises(module.EvidenceError, match="fingerprint"):
        module.signature_verification_command(
            artifact=artifact,
            bundle=bundle,
            public_key=public_key,
            expected_key_fingerprint=module.sha256_file(public_key),
            expected_key_id="stateport-alpha-private-2026-08",
            configured_key_id="stateport-alpha-private-2026-08",
        )
    with pytest.raises(module.EvidenceError, match="key ID"):
        module.signature_verification_command(
            artifact=artifact,
            bundle=bundle,
            public_key=public_key,
            expected_key_fingerprint=fingerprint,
            expected_key_id="stateport-alpha-private-2026-08",
            configured_key_id="wrong-key-id",
        )


def test_signature_policy_never_claims_a_private_release_trust_root() -> None:
    value = yaml.safe_load((ROOT / "config/release-tool-inputs.yaml").read_text())
    signature = value["policy"]["signature"]
    assert signature["status"] == "configured_owner_trust_root"
    assert signature["keyId"] == "stateport-alpha-private-2026-08"
    assert signature["publicKeyFingerprint"] == (
        "sha256:df24c1ccdcf1ecf72da6d8d81ae8b0ffaca8d399826091b107cc4d6905915ea5"
    )
    assert signature["externalPrivateKeyReference"] == (
        "operator-managed-secret-store:stateport-alpha-private-2026-08-v6"
    )
    assert signature["publicTransparencyLogUpload"] is False
    assert signature["testKeys"] == "ephemeral_non_release_only"


def test_alpha4_trust_material_matches_established_owner_key_and_rejects_unrelated_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = yaml.safe_load((ROOT / "config/release-tool-inputs.yaml").read_text())
    signature = value["policy"]["signature"]
    public_key = ROOT / str(signature["publicKeyPath"])
    established = Path(
        os.environ.get("STATEPORT_OWNER_COSIGN_KEY", "~/.config/stateport/secrets/cosign.key")
    ).expanduser()
    if not established.is_file():
        pytest.skip("owner-managed signing key is unavailable in this environment")

    if not os.environ.get("COSIGN_PASSWORD"):
        pytest.skip("owner-managed signing password is unavailable in this environment")
    owner_fingerprint = private_key_der_spki_fingerprint(
        established, cosign="/home/linuxbrew/.linuxbrew/bin/cosign"
    )
    assert owner_fingerprint == signature["publicKeyFingerprint"]
    assert module.public_key_der_spki_fingerprint(public_key) == owner_fingerprint

    unrelated_public = _ephemeral_cosign_key(tmp_path, monkeypatch)
    assert module.public_key_der_spki_fingerprint(unrelated_public) != owner_fingerprint


def _build_receipt(tmp_path: Path) -> Path:
    digest = "sha256:" + "a" * 64
    builds = []
    for ordinal in (1, 2):
        relative = f"digests/web-{ordinal}.digest"
        path = tmp_path / relative
        path.parent.mkdir(exist_ok=True, mode=0o700)
        path.write_text(digest + "\n", encoding="ascii")
        builds.append(
            {
                "ordinal": ordinal,
                "localTag": f"127.0.0.1:5000/stateport-alpha/stateport-web:test-{ordinal}",
                "localImageId": "local-image-id",
                "digestFile": relative,
                "digestFileDigest": module.sha256_file(path),
                "pushedDigest": digest,
                "digestReference": f"127.0.0.1:5000/stateport-alpha/stateport-web@{digest}",
                "pulledImageId": "local-image-id",
                "observedRemoteDigests": [digest],
                "startedAt": "2026-08-01T10:00:00Z",
                "finishedAt": "2026-08-01T10:01:00Z",
            }
        )
    receipt = {
        "formatVersion": "stateport.release-image-build-receipt/v1",
        "identity": {
            "commit": "b" * 40,
            "tree": "c" * 40,
            "version": "0.2.0-alpha.1",
            "created": "2026-08-01T10:00:00Z",
            "source_date_epoch": 1785578400,
        },
        "builder": {
            "version": "5.8.4",
            "executableDigest": "sha256:" + "e" * 64,
            "descriptorDigest": "sha256:" + "f" * 64,
            "artifact": {
                "uri": "https://example.invalid/podman-5.8.4",
                "digest": "sha256:" + "e" * 64,
            },
        },
        "context": {"archiveDigest": "sha256:" + "d" * 64},
        "images": {
            "stateport-web": {
                "containerfile": "apps/web/Dockerfile",
                "containerfileDigest": "sha256:" + "e" * 64,
                "builds": builds,
                "reproducible": True,
                "acceptedReference": f"127.0.0.1:5000/stateport-alpha/stateport-web@{digest}",
            }
        },
    }
    path = tmp_path / "build-receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path


def test_double_build_digests_are_derived_from_receipt_and_live_image_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    receipt_path = _build_receipt(tmp_path)
    monkeypatch.setattr(
        module,
        "_podman_observation",
        lambda _reference: {"imageId": "local-image-id", "observedDigests": ["sha256:" + "a" * 64]},
    )
    receipt, image, second, receipt_digest = module.derive_build_observations(
        image_id="stateport-web", build_receipt_path=receipt_path
    )
    assert receipt["identity"]["commit"] == "b" * 40
    assert image["builds"][0]["pushedDigest"] == image["builds"][1]["pushedDigest"]
    assert second["ordinal"] == 2
    assert receipt_digest == module.sha256_file(receipt_path)

    digest_path = tmp_path / "digests/web-2.digest"
    digest_path.chmod(0o600)
    digest_path.write_text("sha256:" + "f" * 64 + "\n", encoding="ascii")
    with pytest.raises(module.EvidenceError, match="no longer matches"):
        module.derive_build_observations(image_id="stateport-web", build_receipt_path=receipt_path)


def test_provenance_matches_canonical_schema_and_binds_dependencies_and_byproducts(
    tmp_path: Path,
) -> None:
    byproduct = tmp_path / "web.cdx.json"
    byproduct.write_text("{}\n", encoding="utf-8")
    receipt = {
        "identity": {
            "commit": "b" * 40,
            "tree": "c" * 40,
            "source_date_epoch": 1785578400,
        },
        "builder": {
            "version": "5.8.4",
            "executableDigest": "sha256:" + "e" * 64,
            "descriptorDigest": "sha256:" + "f" * 64,
            "artifact": {
                "uri": "https://example.invalid/podman-5.8.4",
                "digest": "sha256:" + "e" * 64,
            },
        },
    }
    image = {
        "containerfile": "apps/web/Dockerfile",
        "builds": [
            {"startedAt": "2026-08-01T10:00:00Z"},
            {"finishedAt": "2026-08-01T10:01:00Z"},
        ],
    }
    dependency = {"uri": "oci:example", "digest": {"sha256": "d" * 64}}
    provenance = module.build_provenance(
        image_id="stateport-web",
        image_reference="registry.example/stateport-web@sha256:" + "a" * 64,
        image=image,
        receipt=receipt,
        receipt_digest="sha256:" + "f" * 64,
        source_repository="https://github.com/lennertvhoy/StatePort.git",
        public_snapshot_commit="1" * 40,
        public_snapshot_tree="2" * 40,
        dependencies=[dependency],
        byproduct_paths=[byproduct],
    )
    definition = provenance["predicate"]["buildDefinition"]
    assert definition["buildType"] == "https://stateport.invalid/buildtypes/oci/v1"
    assert definition["resolvedDependencies"] == [dependency]
    assert provenance["predicate"]["runDetails"]["byproducts"][0]["digest"] == module.sha256_file(
        byproduct
    )


def test_dev_workspace_provenance_binds_source_built_tool_inputs() -> None:
    dependencies = module._resolved_dependencies(
        image={
            "containerfile": "images/stateport-dev-workspace/Containerfile",
            "containerfileDigest": "sha256:" + "a" * 64,
        },
            receipt={
                "identity": {"commit": "b" * 40},
                "context": {"archiveDigest": "sha256:" + "c" * 64},
                "builder": {
                    "artifact": {
                        "uri": "https://example.invalid/podman-5.8.4",
                        "digest": "sha256:" + "e" * 64,
                    }
                },
            },
        receipt_digest="sha256:" + "d" * 64,
    )
    dependencies_by_uri = {dependency["uri"]: dependency for dependency in dependencies}
    inputs = yaml.safe_load((ROOT / "config/container-build-inputs.yaml").read_text())
    for dependency in (
        *inputs["buildToolchains"].values(),
        *inputs["upstreamTools"].values(),
    ):
        assert dependencies_by_uri[dependency["uri"]]["digest"]["sha256"] == dependency[
            "digest"
        ].removeprefix("sha256:")


def test_execution_host_provenance_binds_source_built_podman() -> None:
    dependencies = module._resolved_dependencies(
        image={
            "containerfile": "images/stateport-execution-host/Containerfile",
            "containerfileDigest": "sha256:" + "a" * 64,
        },
            receipt={
                "identity": {"commit": "b" * 40},
                "context": {"archiveDigest": "sha256:" + "c" * 64},
                "builder": {
                    "artifact": {
                        "uri": "https://example.invalid/podman-5.8.4",
                        "digest": "sha256:" + "e" * 64,
                    }
                },
            },
        receipt_digest="sha256:" + "d" * 64,
    )
    inputs = yaml.safe_load((ROOT / "config/container-build-inputs.yaml").read_text())
    podman = inputs["sourceBuiltTools"]["podman-remote"]
    assert {
        "uri": podman["uri"],
        "digest": {"sha256": podman["digest"].removeprefix("sha256:")},
    } in dependencies


def test_playwright_provenance_binds_browser_asset() -> None:
    dependencies = module._resolved_dependencies(
        image={
            "containerfile": "images/stateport-playwright/Containerfile",
            "containerfileDigest": "sha256:" + "a" * 64,
        },
        receipt={
            "identity": {"commit": "b" * 40},
            "context": {"archiveDigest": "sha256:" + "c" * 64},
            "builder": {
                "artifact": {
                    "uri": "https://example.invalid/podman-5.8.4",
                    "digest": "sha256:" + "e" * 64,
                }
            },
        },
        receipt_digest="sha256:" + "d" * 64,
    )
    inputs = yaml.safe_load((ROOT / "config/container-build-inputs.yaml").read_text())
    browser = inputs["browserAssets"]["chrome-for-testing"]
    assert {
        "uri": browser["uri"],
        "digest": {"sha256": browser["digest"].removeprefix("sha256:")},
    } in dependencies


def test_grype_freshness_enforces_max_age_and_reports_headroom(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 1, 12, tzinfo=timezone.utc)
    monkeypatch.setattr(
        module,
        "_run",
        lambda _arguments: json.dumps(
            {"schemaVersion": "v6", "built": "2026-08-01T00:00:00Z", "valid": True}
        ),
    )
    status = module.grype_database_status(now=now)
    assert status["valid"] is True
    assert status["remainingHours"] == 12
    assert status["minimumRemainingHours"] == 8
    monkeypatch.setattr(
        module,
        "_run",
        lambda _arguments: json.dumps(
            {"schemaVersion": "v6", "built": "2026-07-31T19:59:59Z", "valid": True}
        ),
    )
    status = module.grype_database_status(now=now)
    assert status["valid"] is True
    assert status["headroomWarning"] == "release-headroom-shortfall"
    monkeypatch.setattr(
        module,
        "_run",
        lambda _arguments: json.dumps(
            {"schemaVersion": "v6", "built": "2026-07-30T11:30:00Z", "valid": True}
        ),
    )
    with pytest.raises(module.EvidenceError, match="absolute latest-available"):
        module.grype_database_status(now=now)
    source = (ROOT / "scripts/collect_release_evidence.py").read_text(encoding="utf-8")
    assert "--only-fixed" not in source
    assert '"--first-digest"' not in source and '"--second-digest"' not in source
    assert '"--public-snapshot-commit"' not in source
    assert '"--public-snapshot-tree"' not in source


def test_evidence_collection_uses_one_syft_catalogue_and_scans_its_json() -> None:
    source = (ROOT / "scripts/collect_release_evidence.py").read_text(encoding="utf-8")
    assert 'f"syft-json={syft_json}"' in source
    assert 'f"cyclonedx-json={cdx}"' in source
    assert 'f"spdx-json={spdx}"' in source
    assert 'f"sbom:{syft_json}"' in source
    assert source.count('"-o",\n                f"') >= 3
    assert '[grype, local_source, "-o", "json"]' not in source
    assert 'f"oci-archive:{archive_path}"' in source


def test_grype_freshness_accepts_exact_headroom_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 1, 12, tzinfo=timezone.utc)
    monkeypatch.setattr(
        module,
        "_run",
        lambda _arguments: json.dumps(
            {"schemaVersion": "v6", "built": "2026-07-31T20:00:00Z", "valid": True}
        ),
    )
    assert module.grype_database_status(now=now)["remainingHours"] == 8


def test_grype_freshness_rejects_invalid_reserve(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = yaml.safe_load((ROOT / "config/release-tool-inputs.yaml").read_text())
    manifest["policy"]["minimumDatabaseFreshnessRemainingHours"] = 24
    monkeypatch.setattr(module, "_load_yaml", lambda _path: manifest)
    monkeypatch.setattr(
        module,
        "_run",
        lambda _arguments: json.dumps(
            {"schemaVersion": "v6", "built": "2026-08-01T11:30:00Z", "valid": True}
        ),
    )
    with pytest.raises(module.EvidenceError, match="reserve is invalid"):
        module.grype_database_status(now=datetime(2026, 8, 1, 12, tzinfo=timezone.utc))


def test_grype_latest_available_grace_is_bounded_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 1, 12, tzinfo=timezone.utc)

    def status_for(built: str) -> None:
        monkeypatch.setattr(
            module,
            "_run",
            lambda _arguments: json.dumps(
                {"schemaVersion": "v6", "built": built, "valid": True}
            ),
        )

    status_for("2026-07-31T12:06:00Z")
    assert module.grype_database_status(now=now)["freshnessClass"] == "fresh"

    status_for("2026-07-31T11:27:00Z")
    proof = {
        "exitCode": 0,
        "meaning": "up-to-date-no-newer-database",
        "observedAt": "2026-08-01T12:00:00Z",
    }
    grace = module.grype_database_status(now=now, latest_database_check=proof)
    assert grace["freshnessClass"] == "latest-available-grace"
    assert grace["latestDatabaseCheck"] == proof
    with pytest.raises(module.EvidenceError, match="did not prove"):
        module.grype_database_status(
            now=now,
            latest_database_check={**proof, "exitCode": 1, "meaning": "newer-database-available"},
        )
    with pytest.raises(module.EvidenceError, match="did not prove"):
        module.grype_database_status(
            now=now,
            latest_database_check={**proof, "exitCode": 2, "meaning": "database-check-failed"},
        )
    with pytest.raises(module.EvidenceError, match="missing"):
        module.grype_database_status(now=now)

    status_for("2026-07-30T11:59:00Z")
    with pytest.raises(module.EvidenceError, match="absolute latest-available"):
        module.grype_database_status(now=now, latest_database_check=proof)

    status_for("2026-07-31T11:27:00Z")
    with pytest.raises(module.EvidenceError, match="older than"):
        module.grype_database_status(
            now=now,
            latest_database_check={**proof, "observedAt": "2026-08-01T11:44:00Z"},
        )

    status_for("2026-07-31T11:27:00Z")
    with pytest.raises(module.EvidenceError, match="not valid"):
        monkeypatch.setattr(
            module,
            "_run",
            lambda _arguments: json.dumps(
                {"schemaVersion": "v6", "built": "2026-07-31T11:27:00Z", "valid": False}
            ),
        )
        module.grype_database_status(now=now, latest_database_check=proof)


def test_refresh_grype_database_attempts_update_check_then_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    built = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setattr(
        module,
        "_run",
        lambda arguments, **_kwargs: calls.append(list(arguments))
        or json.dumps({"schemaVersion": "v6", "built": built, "valid": True}),
    )
    monkeypatch.setattr(
        module,
        "_run_result",
        lambda arguments, **_kwargs: subprocess.CompletedProcess(arguments, 0, "", ""),
    )
    database = module.refresh_grype_database()
    assert calls[0][-2:] == ["db", "update"]
    assert calls[1][-4:] == ["db", "status", "-o", "json"]
    assert database["updateAttempted"] is True
    assert database["latestDatabaseCheck"]["meaning"] == "up-to-date-no-newer-database"


def test_scanner_process_helpers_use_real_disk_temp_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "evidence"
    scanner_tmp = evidence / "scanner-tmp"
    monkeypatch.setenv("STATEPORT_EVIDENCE_ROOT", str(evidence))
    environments: list[dict[str, str]] = []

    def run(arguments, **kwargs):
        environments.append(kwargs["env"])
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(module.subprocess, "run", run)
    module._run(["tool", "status"])
    module._run_result(["tool", "check"])
    module._run_to_new_file(["tool", "scan"], evidence / "scan.json")

    assert scanner_tmp.is_dir()
    assert [environment["TMPDIR"] for environment in environments] == [
        str(scanner_tmp),
        str(scanner_tmp),
        str(scanner_tmp),
    ]


def test_batch_collection_prepares_release_wide_inputs_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    context = module.CollectionContext(
        receipt={"images": {"web": {}, "api": {}}},
        candidate={},
        tools={},
        database={},
        exceptions_config={},
        exceptions_digest="sha256:" + "a" * 64,
        receipt_digest="sha256:" + "b" * 64,
    )
    output = tmp_path / "evidence"
    monkeypatch.setenv("STATEPORT_EVIDENCE_ROOT", "before-collection")

    def prepare_context(**_kwargs):
        calls.append("context")
        assert os.environ["STATEPORT_EVIDENCE_ROOT"] == str(output)
        assert module._tool_environment()["TMPDIR"] == str(output / "scanner-tmp")
        return context

    monkeypatch.setattr(module, "prepare_collection_context", prepare_context)
    monkeypatch.setattr(
        module,
        "_collect_image",
        lambda **kwargs: {"imageId": kwargs["image_id"]},
    )
    repository = tmp_path / "repo"
    repository.mkdir()
    manifests = module.collect_many(
        image_ids=["web", "api"],
        build_receipt=tmp_path / "receipt.json",
        candidate_provenance=tmp_path / "candidate.yaml",
        candidate_bundle=tmp_path / "candidate.bundle",
        output_root=output,
    )
    assert manifests == [{"imageId": "web"}, {"imageId": "api"}]
    assert calls == ["context"]


def test_resume_discards_partial_image_outputs_before_recollecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = module.CollectionContext(
        receipt={"images": {"web": {}}},
        candidate={},
        tools={},
        database={},
        exceptions_config={},
        exceptions_digest="sha256:" + "a" * 64,
        receipt_digest="sha256:" + "b" * 64,
    )
    monkeypatch.setattr(module, "prepare_collection_context", lambda **_kwargs: context)
    collected: list[str] = []
    monkeypatch.setattr(
        module,
        "_collect_image",
        lambda **kwargs: collected.append(kwargs["image_id"]) or {"imageId": "web"},
    )
    repository = tmp_path / "repo"
    repository.mkdir()
    output = module.prepare_output_root(tmp_path / "evidence", repository=repository)
    (output / "web.syft.json").write_text("partial", encoding="utf-8")
    manifests = module.collect_many(
        image_ids=["web"],
        build_receipt=tmp_path / "receipt.json",
        candidate_provenance=tmp_path / "candidate.yaml",
        candidate_bundle=tmp_path / "candidate.bundle",
        output_root=output,
        resume=True,
    )
    assert manifests == [{"imageId": "web"}]
    assert collected == ["web"]
    assert not (output / "web.syft.json").exists()


def test_resume_checkpoint_rejects_a_different_grype_database(tmp_path: Path) -> None:
    artifact = tmp_path / "web.syft.json"
    artifact.write_text("{}\n", encoding="utf-8")
    manifest_path = tmp_path / "web.evidence.json"
    manifest_path.write_text(
        json.dumps(
            {
                "imageId": "web",
                "buildReceiptDigest": "sha256:" + "b" * 64,
                "grypeDatabase": {"builtAt": "2026-08-01T00:00:00Z"},
                "artifacts": {artifact.name: module.sha256_file(artifact)},
            }
        ),
        encoding="utf-8",
    )
    context = module.CollectionContext(
        receipt={},
        candidate={},
        tools={},
        database={"builtAt": "2026-08-02T00:00:00Z"},
        exceptions_config={},
        exceptions_digest="sha256:" + "a" * 64,
        receipt_digest="sha256:" + "b" * 64,
    )
    with pytest.raises(module.EvidenceError, match="current Grype database"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=context,
        )


def test_candidate_identity_is_rederived_and_bound_to_build_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = {
        "candidateId": "stateport-public-candidate-test",
        "materialization": {
            "sourceRepository": "https://github.com/lennertvhoy/StatePort.git",
            "sourceCommit": "b" * 40,
            "sourceTree": "c" * 40,
        },
        "repository": {"commit": "d" * 40, "tree": "e" * 40},
        "artifacts": {"publicManifest": {"sha256": "f" * 64}},
    }
    contract = tmp_path / "candidate.yaml"
    contract.write_text(yaml.safe_dump(candidate), encoding="utf-8")
    bundle = tmp_path / "candidate.bundle"
    bundle.write_bytes(b"verified-test-bundle")
    monkeypatch.setattr(module, "validate_candidate_contract", lambda value, _schema: value)
    monkeypatch.setattr(module, "validate_repository_relationship", lambda _value, _root: None)
    monkeypatch.setattr(module, "verify_candidate_bundle", lambda _value, _bundle: None)
    receipt = {"identity": {"commit": "b" * 40, "tree": "c" * 40}}
    identity = module.validated_candidate_identity(
        candidate_provenance=contract,
        candidate_bundle=bundle,
        receipt=receipt,
    )
    assert identity["publicSnapshotCommit"] == "d" * 40
    assert identity["publicSnapshotTree"] == "e" * 40
    assert identity["candidateContractDigest"] == module.sha256_file(contract)
    assert identity["candidateBundleDigest"] == module.sha256_file(bundle)

    receipt["identity"]["commit"] = "0" * 40
    with pytest.raises(module.EvidenceError, match="does not match"):
        module.validated_candidate_identity(
            candidate_provenance=contract,
            candidate_bundle=bundle,
            receipt=receipt,
        )
