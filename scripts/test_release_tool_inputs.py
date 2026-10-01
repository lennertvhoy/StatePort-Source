from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "release-contracts" / "src"))
from stateport_release.contract import canonical_digest, canonical_json_bytes  # noqa: E402
from stateport_release.cosign import (  # noqa: E402
    private_key_der_spki_fingerprint,
    public_key_der_spki_fingerprint,
)
spec = spec_from_file_location(
    "collect_release_evidence", ROOT / "scripts/collect_release_evidence.py"
)
assert spec and spec.loader
if spec.name in sys.modules:
    # Reuse the one registered copy. Executing the file again here and
    # rebinding sys.modules would leave every test that already imported this
    # module holding a DIFFERENT module object from the one their functions read,
    # so a test that rebinds module state can patch a copy nobody under test
    # consults. That was measured: a suppression test passed alone and failed in
    # a multi-file run for exactly this reason.
    module = sys.modules[spec.name]
else:
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)


def test_installed_supply_chain_tools_match_pinned_versions_hashes_and_bottles() -> None:
    observed = module.verify_toolchain()
    assert set(observed) == {"syft", "grype", "cosign"}
    assert observed["syft"]["version"] == "1.51.0"
    assert observed["grype"]["version"] == "0.117.0"
    assert observed["cosign"]["version"] == "3.1.3"


# =============================================================================
# THE shared, NON-RELEASE ephemeral Cosign key helper.
#
# There is exactly ONE copy of this code in the repository.  It was previously
# written twice (here as ``_ephemeral_cosign_key`` and in
# ``scripts/test_assemble_release_index.py`` as the ``trust_root`` fixture);
# both now delegate here, and the synthetic native-admission fixtures use it too.
#
# The four bindings that make a private key in a test path acceptable, all
# enforced by construction rather than by convention:
#
#   1. SCOPE -- the caller supplies a ``tmp_path_factory``/``tmp_path`` root.
#      Nothing here can write anywhere else, so the private key lives only in a
#      directory pytest owns and removes with the run;
#   2. PASSWORD -- one fixed literal, never read from the environment and never
#      a real secret, so no operator credential can leak into a test run;
#   3. KEY ID -- ``EPHEMERAL_TEST_KEY_ID``, distinct from the release trust
#      root's ``stateport-alpha-private-2026-08`` and refused by the driver's
#      front door whenever the release pin is the one in force;
#   4. NOT THE TRUST ROOT -- the key is generated fresh per run from the pinned
#      Cosign binary, so it cannot be, and is never checked in as, the release
#      trust root.  ``tests`` assert both directions cryptographically.
#
# It never generates a release key and never signs a release artifact: the only
# thing it can sign is a synthetic payload staged inside a pytest temp dir.
# =============================================================================

RELEASE_TRUST_KEY_ID = "stateport-alpha-private-2026-08"
EPHEMERAL_TEST_KEY_ID = "stateport-ephemeral-test-2026-09-26"
EPHEMERAL_COSIGN_PASSWORD = "test-ephemeral-non-release"
PINNED_COSIGN = Path("/home/linuxbrew/.linuxbrew/bin/cosign")
RELEASE_SIGNED_PAYLOAD_NAME = "release-index.signed-payload.json"
RELEASE_BUNDLE_NAME = "release-index.sigstore.json"
#: PEM armor that only ever delimits PRIVATE key material.  A public key the
#: release pipeline commits under ``config/trust`` never matches one of these,
#: so the repository scan built on this tuple cannot pass because it is blind.
PRIVATE_KEY_HEADERS = (
    "ENCRYPTED SIGSTORE PRIVATE KEY",
    "ENCRYPTED COSIGN PRIVATE KEY",
    "PRIVATE KEY",
    "EC PRIVATE KEY",
    "RSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
)


def _is_pem_private_key(content: bytes) -> bool:
    """True for a COMPLETE PEM private-key document, not for a mention of one.

    Both the BEGIN and the matching END line are required, because a header on
    its own is a string a source file or a compiled ``.pyc`` can legitimately
    contain -- this file's own detector table does.  Key material is a whole PEM
    document, so that is what is looked for, and a false positive on a doc that
    quotes a header line is not a leak.
    """

    for kind in PRIVATE_KEY_HEADERS:
        if (
            f"-----BEGIN {kind}-----".encode() in content
            and f"-----END {kind}-----".encode() in content
        ):
            return True
    return False


def private_key_findings(roots: list[Path] | tuple[Path, ...]) -> list[Path]:
    """Every file under ``roots`` that carries PRIVATE key material.

    Two independent rules, so neither can be the only thing making this return
    an empty list: the Cosign naming convention (a ``*.key`` file) and a complete
    PEM private-key document inside the file.  ``.git`` is skipped -- the claim
    is about the working tree a test run can write, not about packed repository
    objects.

    Compiled-bytecode DIRECTORIES are skipped as well, and the reason is measured
    rather than tidiness: ``__pycache__/`` is untracked, derived and regenerable,
    and a source file whose literals merely LOOK like key-detection patterns --
    this repository's own sensitive-data tests do -- compiles into a ``.pyc`` that
    the content rule then reports as a finding.  That is a false positive about
    compiled bytes, not private key material in the repository, and it is
    unfixable except by excluding derived artefacts, because the literal is
    legitimately in the source.  THE EXCLUSION IS BY DIRECTORY NAME ONLY, never by
    file suffix, so a ``.pyc``-named file anywhere else in the tree is still
    scanned: a name-based exclusion would itself be an evasion path.  It cannot
    hide a real key either way, because bytecode only ever exists because a
    scanned source file exists, and both the ``*.key`` naming rule and the PEM
    content rule still apply to every other file, source included.
    """

    findings: list[Path] = []
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        for parent, directories, names in os.walk(root):
            directories[:] = [
                name
                for name in directories
                if name not in {".git", "__pycache__"}
            ]
            for name in names:
                path = Path(parent) / name
                if path.is_symlink() or not path.is_file():
                    continue
                if path.suffix == ".key":
                    findings.append(path)
                    continue
                try:
                    if path.stat().st_size > 4 * 1024 * 1024:
                        continue
                    content = path.read_bytes()
                except OSError:
                    continue
                if _is_pem_private_key(content):
                    findings.append(path)
    return sorted(set(findings))


class EphemeralTestTrust:
    """One throwaway, NON-RELEASE Cosign key pair plus the signing it supports."""

    def __init__(
        self,
        *,
        root: Path,
        private: Path,
        public: Path,
        cosign: Path,
        key_id: str = EPHEMERAL_TEST_KEY_ID,
        password: str = EPHEMERAL_COSIGN_PASSWORD,
    ) -> None:
        self.root = root
        self.private = private
        self.public = public
        self.cosign = cosign
        self.key_id = key_id
        self.password = password

    @property
    def fingerprint(self) -> str:
        """The canonical DER SPKI fingerprint -- the same value a verifier pins."""

        return public_key_der_spki_fingerprint(self.public)

    def trust_fields(self, bundle_root: Path) -> dict[str, Any]:
        """The five fields of the driver's trust input, for this NON-RELEASE key.

        The caller builds its own ``CosignTrustInput`` from these, so this helper
        stays independent of any one driver's types.
        """

        return {
            "cosign": self.cosign,
            "public_key": self.public,
            "public_key_fingerprint": self.fingerprint,
            "key_id": self.key_id,
            "bundle_root": Path(bundle_root),
        }

    def sign_index(
        self,
        target: Path,
        signed: Mapping[str, Any],
        *,
        payload_name: str = RELEASE_SIGNED_PAYLOAD_NAME,
        bundle_name: str = RELEASE_BUNDLE_NAME,
    ) -> dict[str, Any]:
        """Sign ``signed`` with THIS ephemeral key and return the descriptor.

        The payload file is written as the canonical JSON the digest is taken
        over, so the signature covers exactly the bytes the envelope claims, and
        the descriptor is the product's own ``cosign-v3-bundle`` shape -- the
        same one the release assembler emits.
        """

        target = Path(target)
        target.mkdir(parents=True, exist_ok=True)
        payload = target / payload_name
        payload.write_bytes(canonical_json_bytes(signed))
        bundle = target / bundle_name
        if bundle.exists():
            raise AssertionError(f"refusing to overwrite an existing bundle: {bundle}")
        completed = subprocess.run(
            [
                str(self.cosign),
                "sign-blob",
                "--use-signing-config=false",
                "--tlog-upload=false",
                "--bundle",
                str(bundle),
                "--key",
                str(self.private),
                str(payload),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
            shell=False,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "COSIGN_PASSWORD": self.password},
        )
        if completed.returncode != 0 or not bundle.is_file():
            raise AssertionError(
                f"ephemeral test signing failed: {completed.stderr.strip()[:300]}"
            )
        content = bundle.read_bytes()
        return {
            "scheme": "cosign-v3-bundle",
            "subjectDigest": canonical_digest(signed),
            "bundle": {
                "uri": f"operator://test/{bundle_name}",
                "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                "size": len(content),
                "mediaType": "application/vnd.sigstore.bundle.v0.3+json",
            },
            "trustMode": "pinned-public-key",
            "publicKeyFingerprint": self.fingerprint,
            "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
            "publicKeyId": self.key_id,
            "transparencyLog": "not-uploaded-private-candidate",
        }


def generate_ephemeral_test_trust(
    root: Path,
    *,
    cosign: Path = PINNED_COSIGN,
    key_id: str = EPHEMERAL_TEST_KEY_ID,
    prefix: str = "ephemeral-test",
) -> EphemeralTestTrust:
    """Create a throwaway key pair under ``root``; nothing outside ``root``."""

    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    subprocess.run(
        [str(cosign), "generate-key-pair", "--output-key-prefix", prefix],
        cwd=root,
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        env={**os.environ, "COSIGN_PASSWORD": EPHEMERAL_COSIGN_PASSWORD},
    )
    public = root / f"{prefix}.pub"
    private = root / f"{prefix}.key"
    if not public.is_file() or not private.is_file():
        raise AssertionError(f"ephemeral cosign key pair was not created under {root}")
    os.chmod(private, 0o600)
    if os.path.commonpath([str(private.resolve()), str(root.resolve())]) != str(
        root.resolve()
    ):
        raise AssertionError("the ephemeral private key escaped its temporary root")
    return EphemeralTestTrust(
        root=root, private=private, public=public, cosign=cosign, key_id=key_id
    )


def _ephemeral_cosign_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Generate an ephemeral, test-only Cosign key pair; never release evidence.

    Now a thin wrapper over the ONE shared helper above; it exists so this
    file's existing call sites keep their ``monkeypatch``-driven environment.
    """

    monkeypatch.setenv("COSIGN_PASSWORD", EPHEMERAL_COSIGN_PASSWORD)
    return generate_ephemeral_test_trust(tmp_path, prefix="test").public


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
    # Opt-in, deliberately NOT keyed on COSIGN_PASSWORD. COSIGN_PASSWORD is a
    # *working* variable: other tests set it (test_assemble_release_index.py), and
    # in a whole-suite run this test was observed to run rather than skip and then
    # fail with "private key is not a decryptable Cosign key" -- i.e. it reached the
    # owner's real Cosign private key and asked cosign to decrypt it. Which test
    # leaks the variable is NOT established, and that is recorded as unknown rather
    # than guessed; but the hazard does not depend on the answer. Any leak of a
    # routine working variable must not be able to arm an unattended run against
    # live signing material, so arming requires a dedicated opt-in that no other
    # test sets.
    if os.environ.get("STATEPORT_VERIFY_OWNER_SIGNING_KEY") != "1":
        pytest.skip(
            "owner signing-key verification is opt-in; set "
            "STATEPORT_VERIFY_OWNER_SIGNING_KEY=1 to run it against live signing material"
        )
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
        suppression_config={},
        suppression_digest="sha256:" + "c" * 64,
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
        suppression_config={},
        suppression_digest="sha256:" + "c" * 64,
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
        suppression_config={},
        suppression_digest="sha256:" + "c" * 64,
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


# ---------------------------------------------------------------------------
# The resume verdict check.
#
# `_collect_image` publishes the image manifest and only then refuses, so a scan
# that failed leaves behind a manifest that is COMPLETE and DIGEST-CORRECT --
# every artifact present, every digest matching. Checking integrity is not the
# same as checking the verdict, and these two tests pin the difference: one
# refuses a checkpoint that records a failed scan, the other proves a genuinely
# passed checkpoint still resumes, so the refusal cannot be satisfied by
# refusing everything.


def _write_evaluation(path: Path, module, **overrides) -> Path:
    """The stored scan evaluation, writable independently of the scan itself."""
    document = {
        "formatVersion": "stateport.release-scan-evaluation/v2",
        "imageId": "web",
        "unexplainedFindings": [],
        "unexplainedSuppressedFindings": [],
        "suppressedFindings": {"refusals": []},
    }
    document.update(overrides)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _write_scan(
    path: Path, module, *, unexplained: list | None = None, ignored: list | None = None
) -> Path:
    """The digested grype scan the evaluation is a conclusion about.

    A real High finding, so the evaluator reproduces it from this document
    without any help from the stored evaluation.
    """
    matches = [
        {
            "vulnerability": {
                "id": item.get("advisory", "CVE-2026-11940"),
                "severity": item.get("severity", "High"),
                "fix": {"state": "wont-fix", "versions": []},
            },
            "artifact": {"name": item.get("package", "python"), "version": "3.13.14"},
        }
        for item in (unexplained or [])
    ]
    path.write_text(
        json.dumps(
            {
                "descriptor": {
                    "name": "grype",
                    "version": module._pinned_grype_version(),
                    "configuration": {"output": ["json"], "ignore": []},
                },
                "matches": matches,
                "ignoredMatches": ignored or [],
            }
        ),
        encoding="utf-8",
    )
    return path


def _checkpoint_manifest(
    tmp_path: Path,
    module,
    *,
    claim: str,
    unexplained: list | None = None,
    refusals: list | None = None,
    inventory: bool = True,
    scan_inventory: bool = True,
    evaluation_overrides: dict | None = None,
    evaluated_on: str | None = "2026-08-02",
    ignored: list | None = None,
    stored_unexplained: list | None = None,
) -> Path:
    """A resume checkpoint whose CLAIM, EVIDENCE and SCAN are settable apart.

    The three are independent on purpose: a negative is a checkpoint that
    disagrees with itself, and the guard must be decided by the scan.
    """
    findings = [] if unexplained is None else unexplained
    artifact = tmp_path / "web.syft.json"
    artifact.write_text("{}\n", encoding="utf-8")
    scan = _write_scan(
        tmp_path / "web.grype.json", module, unexplained=findings, ignored=ignored
    )
    stored: dict = {}
    if stored_unexplained is None:
        if unexplained is not None:
            stored["unexplainedFindings"] = findings
    else:
        stored["unexplainedFindings"] = stored_unexplained
    if refusals is not None:
        stored["suppressedFindings"] = {"refusals": refusals}
    stored.update(evaluation_overrides or {})
    evaluation = _write_evaluation(
        tmp_path / "web.scan-evaluation.json", module, **stored
    )
    artifacts = {"web.syft.json": module.sha256_file(artifact)}
    if scan_inventory:
        artifacts["web.grype.json"] = module.sha256_file(scan)
    if inventory:
        artifacts["web.scan-evaluation.json"] = module.sha256_file(evaluation)
    scan_policy: dict = {
        "result": claim,
        "evaluationArtifact": "web.scan-evaluation.json",
        "unexplainedFindings": [],
        "unexplainedSuppressedFindings": [],
        "suppressionRefusals": [],
    }
    if evaluated_on is not None:
        scan_policy["evaluatedOn"] = evaluated_on
    manifest_path = tmp_path / "web.evidence.json"
    manifest_path.write_text(
        json.dumps(
            {
                "imageId": "web",
                "buildReceiptDigest": "sha256:" + "b" * 64,
                "grypeDatabase": {"builtAt": "2026-08-01T00:00:00Z"},
                "artifacts": artifacts,
                "scanPolicy": scan_policy,
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


def _checkpoint_context(module, *, exceptions: list | None = None) -> object:
    return module.CollectionContext(
        receipt={},
        candidate={},
        tools={},
        database={"builtAt": "2026-08-01T00:00:00Z"},
        exceptions_config={
            "formatVersion": "stateport.release-scan-exceptions/v1",
            "resolvedOn": "2026-08-02",
            "exceptions": exceptions or [],
        },
        exceptions_digest="sha256:" + "a" * 64,
        suppression_config={
            "formatVersion": "stateport.release-scan-suppression/v1",
            "resolvedOn": "2026-08-02",
            "tool": {"name": "grype", "version": module._pinned_grype_version()},
            "rules": [],
        },
        suppression_digest="sha256:" + "c" * 64,
        receipt_digest="sha256:" + "b" * 64,
    )


def test_resume_refuses_a_checkpoint_whose_claim_contradicts_its_scan_evaluation(
    tmp_path: Path,
) -> None:
    """The manifest says passed; the digested evaluation it points at says failed.

    The manifest is unsigned, so its `scanPolicy.result` is a claim. Before the
    verdict was re-derived from the evaluation artifact, editing that one field
    was enough to make `--resume` skip an image whose scan had failed.
    """
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="passed",
        unexplained=[{"advisory": "CVE-2026-11940", "package": "python", "severity": "High"}],
    )
    with pytest.raises(module.EvidenceError, match="while its scan evaluation derives"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_refuses_a_checkpoint_whose_scan_evaluation_records_a_suppression_refusal(
    tmp_path: Path,
) -> None:
    """The other half of the derivation: a suppression refusal is a failure too."""
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="passed",
        refusals=["1 suppressed finding(s) at or above the threshold are uncovered"],
    )
    with pytest.raises(module.EvidenceError, match="while its scan evaluation derives"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_refuses_a_checkpoint_that_does_not_carry_its_scan_evaluation(
    tmp_path: Path,
) -> None:
    """Drop the evidence and there is nothing left to derive a verdict from."""
    manifest_path = _checkpoint_manifest(
        tmp_path, module, claim="passed", inventory=False
    )
    with pytest.raises(module.EvidenceError, match="does not carry its scan evaluation"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_refuses_a_checkpoint_that_records_a_failed_scan(tmp_path: Path) -> None:
    """Honest failure: the claim and the evidence agree, and it is still not complete."""
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="failed",
        unexplained=[{"advisory": "CVE-2026-11940", "package": "python", "severity": "High"}],
    )
    with pytest.raises(module.EvidenceError, match="is not a completed image"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_accepts_a_checkpoint_whose_claim_and_evaluation_agree(
    tmp_path: Path,
) -> None:
    """The positive twin: a genuinely passed image is still resumable."""
    manifest_path = _checkpoint_manifest(tmp_path, module, claim="passed")
    completed = module._verified_checkpoint(
        manifest_path=manifest_path,
        image_id="web",
        context=_checkpoint_context(module),
    )
    assert completed is not None
    assert completed["imageId"] == "web"


def test_resume_refuses_a_checkpoint_with_no_scan_policy_at_all(tmp_path: Path) -> None:
    """Fail closed on the absence of a verdict, not only on a failing one."""
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
    with pytest.raises(module.EvidenceError, match="carries no scan policy"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


# ---------------------------------------------------------------------------
# One test per clause of the derivation.
#
# The independent verification of the derivation above found four clauses that
# were correct but unpinned: dropping the `unexplainedSuppressedFindings` test,
# the `imageId` binding, the "refuse unless BOTH" conjunct, or any of the
# isinstance type guards left the whole suite green. Each of those is a
# fail-closed behaviour, so each gets a test that fails when the clause goes.


def test_resume_refuses_an_evaluation_with_an_unexplained_suppressed_finding(
    tmp_path: Path,
) -> None:
    """A suppressed High the policy does not cover is a failure, not an absence."""
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="passed",
        evaluation_overrides={
            "unexplainedSuppressedFindings": [
                {"advisory": "CVE-2024-57857", "package": "linux-libc-dev", "severity": "High"}
            ]
        },
    )
    with pytest.raises(module.EvidenceError, match="while its scan evaluation derives"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_refuses_an_evaluation_bound_to_another_image(tmp_path: Path) -> None:
    """The artifact must be about this image, or its verdict is about nothing."""
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="passed",
        evaluation_overrides={"imageId": "stateport-web"},
    )
    with pytest.raises(module.EvidenceError, match="not bound to this image"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_refuses_a_manifest_claiming_failure_over_a_clean_evaluation(
    tmp_path: Path,
) -> None:
    """The claim and the derivation must BOTH be 'passed', not either.

    With a clean evaluation and a claim of 'failed', reading only one of the two
    would resume an image the manifest itself says is not complete.
    """
    manifest_path = _checkpoint_manifest(tmp_path, module, claim="failed")
    with pytest.raises(module.EvidenceError, match="is not a completed image"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_refuses_an_evaluation_whose_verdict_fields_are_the_wrong_type(
    tmp_path: Path,
) -> None:
    """A field the derivation cannot read is a failure, never a pass.

    An empty string, a zero and a null are all falsy, so a derivation written
    with bare truthiness would read every one of them as 'no findings' and wave
    an unreadable evaluation through.
    """
    for unusable in ("", 0, None):
        manifest_path = _checkpoint_manifest(
            tmp_path,
            module,
            claim="passed",
            evaluation_overrides={"unexplainedFindings": unusable},
        )
        with pytest.raises(module.EvidenceError, match="while its scan evaluation derives"):
            module._verified_checkpoint(
                manifest_path=manifest_path,
                image_id="web",
                context=_checkpoint_context(module),
            )
        (tmp_path / "web.evidence.json").unlink()


# ---------------------------------------------------------------------------
# The fresh re-derivation: the scan is the evidence, the evaluation a conclusion.
#
# The stored-evaluation consistency check above proves the checkpoint agrees with
# itself. Someone who can rewrite the evaluation document AND its digest defeats
# that, which was measured and left open. These tests pin the step that closes it
# for the common case: the evaluator is re-run over the scan the manifest already
# digests, and the stored conclusion must match what the evaluator produces from
# that scan. One test per clause -- reverting a guard proves nothing about its
# parts, which is the lesson the previous increment ended on.


def test_resume_refuses_a_clean_evaluation_over_a_scan_that_does_not_pass(
    tmp_path: Path,
) -> None:
    """The conclusion forgery: a scrubbed evaluation with a matching digest.

    Everything in the checkpoint is self-consistent -- the claim says passed, the
    stored evaluation says passed, and every listed digest matches, including the
    evaluation's own. The scan it describes still contains the finding.
    """
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="passed",
        unexplained=[{"advisory": "CVE-2026-11940", "package": "python"}],
        stored_unexplained=[],
    )
    with pytest.raises(module.EvidenceError, match="does not pass a fresh evaluation"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_refuses_a_clean_evaluation_over_a_scan_with_an_uncovered_suppression(
    tmp_path: Path,
) -> None:
    """The same forgery on the suppressed path: a High the policy does not cover."""
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="passed",
        ignored=[
            {
                "vulnerability": {
                    "id": "CVE-2024-57857",
                    "severity": "High",
                    "fix": {"state": "not-fixed", "versions": []},
                },
                "artifact": {
                    "name": "linux-libc-dev",
                    "version": "6.8.0-136.136",
                    "type": "deb",
                },
            }
        ],
    )
    with pytest.raises(module.EvidenceError, match="does not pass a fresh evaluation"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_refuses_an_evaluation_that_invents_a_finding_its_scan_does_not_have(
    tmp_path: Path,
) -> None:
    """A stored evaluation that names an advisory the scan does not contain.

    Caught by the stored-derivation check above, which is the check that owns it:
    a stored document claiming a finding derives "failed" on its own. This test
    names that check rather than implying the fresh comparison is what refuses.
    """
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="failed",
        unexplained=[],
        evaluation_overrides={
            "unexplainedFindings": [{"advisory": "CVE-2026-99999", "package": "python"}]
        },
    )
    with pytest.raises(module.EvidenceError, match="is not a completed image"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_refuses_a_checkpoint_that_does_not_carry_its_scan(tmp_path: Path) -> None:
    """Without the scan there is nothing to reproduce the evaluation from."""
    manifest_path = _checkpoint_manifest(
        tmp_path, module, claim="passed", scan_inventory=False
    )
    with pytest.raises(module.EvidenceError, match="does not carry its scan document"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module),
        )


def test_resume_does_not_accept_an_image_whose_exception_has_since_lapsed(
    tmp_path: Path,
) -> None:
    """The regression this increment exists for: a backdated evaluation date.

    The exception was live on the date the checkpoint records and has since
    expired, so the stored evaluation is a true record of a past judgement and
    the image really was clean when it was collected. Signing it now would be
    wrong, and a guard that re-ran with the recorded date would pass it.

    107 of the 227 records in the committed ledger have already lapsed, so this
    is the common case rather than a corner.
    """
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="passed",
        evaluated_on="2026-08-02",
        unexplained=[{"advisory": "CVE-2026-11940", "package": "python"}],
        stored_unexplained=[],
    )
    lapsed = {
        "id": "RX-2026-999",
        "advisory": "CVE-2026-11940",
        "package": "python",
        "images": ["web"],
        "severity": "High",
        "surface": "Control-plane runtime.",
        "reachability": "Unreachable through the service surface.",
        "evidence": "Retained scan document.",
        "remediation": "Rebase onto a fixed release.",
        "expiresOn": "2026-09-01",
    }
    with pytest.raises(module.EvidenceError, match="does not pass a fresh evaluation"):
        module._verified_checkpoint(
            manifest_path=manifest_path,
            image_id="web",
            context=_checkpoint_context(module, exceptions=[lapsed]),
        )


def test_resume_accepts_an_image_whose_exception_is_still_live(tmp_path: Path) -> None:
    """The positive twin: the ledger rule must not refuse a genuinely clean image."""
    manifest_path = _checkpoint_manifest(
        tmp_path,
        module,
        claim="passed",
        unexplained=[{"advisory": "CVE-2026-11940", "package": "python"}],
        stored_unexplained=[],
    )
    live = {
        "id": "RX-2026-998",
        "advisory": "CVE-2026-11940",
        "package": "python",
        "images": ["web"],
        "severity": "High",
        "surface": "Control-plane runtime.",
        "reachability": "Unreachable through the service surface.",
        "evidence": "Retained scan document.",
        "remediation": "Rebase onto a fixed release.",
        "expiresOn": "2099-12-31",
    }
    completed = module._verified_checkpoint(
        manifest_path=manifest_path,
        image_id="web",
        context=_checkpoint_context(module, exceptions=[live]),
    )
    assert completed is not None
    assert completed["imageId"] == "web"


def test_the_resume_verdict_is_always_decided_under_the_committed_ledger() -> None:
    """The resume verdict depends on WHICH ledger the resume runs under.

    `_verified_checkpoint` reproduces the scan with the exception and suppression
    configuration carried on the context, and it never reads the ledger digest the
    checkpoint recorded. A context carrying a MORE PERMISSIVE ledger therefore
    passes a scan the committed ledger fails -- measured on a real retained scan
    with seven unexplained High findings and no ledger record for any of them.

    In production that is unreachable, because the only place a `CollectionContext`
    is built is inside `prepare_collection_context`, which loads the committed
    ledger. That is a property of the code with no test behind it, and a refactor
    that hand-built a context would change the verdict of a release gate silently.
    So the property is pinned here rather than assumed.
    """
    source = Path(module.__file__).read_text(encoding="utf-8")
    constructions = source.count("CollectionContext(")
    assert constructions == 1, (
        "a second CollectionContext construction would let a caller choose the "
        "ledger the resume verdict is decided under"
    )
    prepare = source[source.index("def prepare_collection_context"):]
    prepare = prepare[: prepare.index("\ndef ")]
    assert "load_scan_exceptions()" in prepare
    assert "load_scan_suppression()" in prepare
