"""The release vulnerability scan must run under the committed configuration.

These tests are behavioural, not structural: the explicit `-c` assertion is made
by executing `_collect_grype_scan` against a fake grype that records its own
argv, and the fail-closed assertions are made by feeding the loader an absent,
unparseable and drifting configuration.
"""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import stat
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "release-contracts" / "src"))
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

CONFIG = ROOT / "config" / "grype-scan.v1.yaml"
RECORDED_RULE = {
    "match-type": "exact-indirect-match",
    "namespace": "",
    "package": {
        "name": "linux-libc-dev",
        "type": "deb",
        "upstream-name": "linux",
        "language": "",
    },
}


def _fake_grype(tmp_path: Path, *, document: dict) -> tuple[str, Path]:
    """A fake grype that records its argv and prints a chosen scan document."""

    argv_path = tmp_path / "argv.json"
    document_path = tmp_path / "document.json"
    document_path.write_text(json.dumps(document), encoding="utf-8")
    executable = tmp_path / "grype"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        f"open({str(argv_path)!r}, 'w', encoding='utf-8').write(json.dumps(sys.argv[1:]))\n"
        f"sys.stdout.write(open({str(document_path)!r}, encoding='utf-8').read())\n",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return str(executable), argv_path


def _minimal_evidence_root(tmp_path: Path) -> Path:
    output = tmp_path / "evidence"
    output.mkdir(mode=0o700)
    (output / "web.syft.json").write_text(
        json.dumps({"artifacts": [], "source": {"type": "image"}}), encoding="utf-8"
    )
    return output


def test_committed_configuration_declares_exactly_the_recorded_rule() -> None:
    document = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    assert list(document) == ["ignore"], "the file must declare nothing but its ignore list"
    rules = document["ignore"]
    assert isinstance(rules, list)
    assert len(rules) == 1, "the signed documents record exactly one effective rule"
    assert rules[0] == RECORDED_RULE

    loaded = module.load_scan_configuration()
    assert loaded.path == CONFIG
    assert loaded.repository_path == "config/grype-scan.v1.yaml"
    assert loaded.digest == "sha256:" + module.sha256_file(CONFIG)
    assert loaded.ignore_rules == (RECORDED_RULE,)


def test_configuration_carries_no_location_or_version_scope_the_evidence_cannot_support() -> None:
    rule = module.load_scan_configuration().ignore_rules[0]
    assert "location" not in rule["package"]
    assert "version" not in rule["package"]
    assert "location" not in rule


def test_scan_passes_the_committed_configuration_explicitly(tmp_path: Path) -> None:
    """A fake grype records argv; `-c` must name the committed file."""

    grype, argv_path = _fake_grype(tmp_path, document={"matches": [], "ignoredMatches": []})
    output = _minimal_evidence_root(tmp_path)
    configuration = module.load_scan_configuration()

    published, started, completed, population = module._collect_grype_scan(
        image_id="web",
        syft_json=output / "web.syft.json",
        grype=grype,
        scan_config=configuration,
        output=output,
    )
    argv = json.loads(argv_path.read_text(encoding="utf-8"))

    assert "-c" in argv, f"the scan must name its configuration explicitly: {argv}"
    assert argv[argv.index("-c") + 1] == str(CONFIG)
    assert "-o" in argv and argv[argv.index("-o") + 1] == "json"
    assert argv[0] == f"sbom:{output / 'web.syft.json'}"
    assert len(argv) == 5, f"unexpected extra grype arguments: {argv}"
    assert published.is_file() and published.name == "web.grype.json"
    assert started <= completed
    assert population == {
        "suppressedMatches": 0,
        "suppressedMatchesBySeverity": {},
        "appliedIgnoreRules": [],
    }


def test_scan_declares_the_population_the_committed_configuration_suppressed(
    tmp_path: Path,
) -> None:
    """The published manifest records the suppression instead of hiding it."""

    document = {
        "matches": [],
        "ignoredMatches": [
            {
                "vulnerability": {"id": "CVE-2012-4542", "severity": "Critical"},
                "artifact": {"name": "linux-libc-dev", "version": "6.8.0-136.136", "type": "deb"},
                "appliedIgnoreRules": [RECORDED_RULE],
            },
            {
                "vulnerability": {"id": "CVE-2013-0194", "severity": "Medium"},
                "artifact": {"name": "linux-libc-dev", "version": "6.8.0-136.136", "type": "deb"},
                "appliedIgnoreRules": [RECORDED_RULE],
            },
        ],
    }
    grype, _ = _fake_grype(tmp_path, document=document)
    output = _minimal_evidence_root(tmp_path)
    configuration = module.load_scan_configuration()

    _, _, _, population = module._collect_grype_scan(
        image_id="web",
        syft_json=output / "web.syft.json",
        grype=grype,
        scan_config=configuration,
        output=output,
    )

    assert population["suppressedMatches"] == 2
    assert population["suppressedMatchesBySeverity"] == {"Critical": 1, "Medium": 1}
    assert population["appliedIgnoreRules"] == [RECORDED_RULE]


def test_a_rule_the_configuration_does_not_declare_refuses_the_scan(tmp_path: Path) -> None:
    """An ambient rule leaking into a scan is a collection defect, not a pass."""

    document = {
        "matches": [],
        "ignoredMatches": [
            {
                "vulnerability": {"id": "CVE-2019-11477", "severity": "High"},
                "artifact": {"name": "linux-libc-dev", "version": "6.8.0-136.136", "type": "deb"},
                "appliedIgnoreRules": [
                    {
                        "match-type": "exact-indirect-match",
                        "namespace": "",
                        "package": {
                            "name": "linux-kbuild-6.8.0",
                            "type": "deb",
                            "upstream-name": "linux",
                            "language": "",
                        },
                    }
                ],
            }
        ],
    }
    grype, _ = _fake_grype(tmp_path, document=document)
    output = _minimal_evidence_root(tmp_path)

    with pytest.raises(module.EvidenceError, match="does not\\s+declare|does not declare"):
        module._collect_grype_scan(
            image_id="web",
            syft_json=output / "web.syft.json",
            grype=grype,
            scan_config=module.load_scan_configuration(),
            output=output,
        )


def test_missing_configuration_refuses_to_scan(tmp_path: Path) -> None:
    with pytest.raises(module.EvidenceError, match="missing or unsafe"):
        module.load_scan_configuration(tmp_path / "grype-scan.v1.yaml")


def test_a_symlinked_configuration_refuses_to_scan(tmp_path: Path) -> None:
    link = tmp_path / "grype-scan.v1.yaml"
    link.symlink_to(CONFIG)
    with pytest.raises(module.EvidenceError, match="missing or unsafe"):
        module.load_scan_configuration(link)


def test_unparseable_configuration_refuses_to_scan(tmp_path: Path) -> None:
    broken = tmp_path / "grype-scan.v1.yaml"
    broken.write_text("ignore: [\n  - this: is: not: yaml\n", encoding="utf-8")
    with pytest.raises(module.EvidenceError, match="unreadable"):
        module.load_scan_configuration(broken)


def test_configuration_without_an_ignore_list_refuses_to_scan(tmp_path: Path) -> None:
    empty = tmp_path / "grype-scan.v1.yaml"
    empty.write_text("fail-on-severity: High\n", encoding="utf-8")
    with pytest.raises(module.EvidenceError, match="no single top-level ignore list"):
        module.load_scan_configuration(empty)


@pytest.mark.parametrize(
    "drift",
    [
        pytest.param(
            "ignore:\n  - match-type: exact-indirect-match\n    package:\n"
            "      name: kernel-headers\n      type: rpm\n      upstream-name: kernel\n",
            id="different-package",
        ),
        pytest.param(
            "ignore:\n"
            "  - match-type: exact-indirect-match\n    package:\n"
            "      name: linux-libc-dev\n      type: deb\n      upstream-name: linux\n"
            "  - match-type: exact-direct-match\n    package:\n"
            "      name: linux-libc-dev\n      type: deb\n      upstream-name: linux\n",
            id="second-rule-added",
        ),
        pytest.param("ignore: []\n", id="no-rule"),
    ],
)
def test_a_drifted_rule_set_refuses_to_scan(tmp_path: Path, drift: str) -> None:
    drifted = tmp_path / "grype-scan.v1.yaml"
    drifted.write_text(drift, encoding="utf-8")
    with pytest.raises(module.EvidenceError, match="exactly one ignore rule|recorded rule"):
        module.load_scan_configuration(drifted)


@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param("version", "6.8.0-136.136", id="version"),
        pytest.param("location", "/usr/src/linux-headers-6.8.0", id="location"),
    ],
)
def test_a_narrowing_field_the_evidence_cannot_support_is_refused(
    tmp_path: Path, field: str, value: str
) -> None:
    """`location` is absent from the signed artifact record, so it is refused."""

    rule = json.loads(json.dumps(RECORDED_RULE))
    rule["package"][field] = value
    narrowed = tmp_path / "grype-scan.v1.yaml"
    narrowed.write_text(
        yaml.safe_dump({"ignore": [rule]}, sort_keys=True, default_flow_style=False),
        encoding="utf-8",
    )
    with pytest.raises(module.EvidenceError, match="unrecorded fields"):
        module.load_scan_configuration(narrowed)


def test_release_preflight_refuses_before_any_scanner_runs(tmp_path: Path, monkeypatch) -> None:
    """An absent configuration aborts the release, not one image of it."""

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a scanner must not run when the configuration is absent")

    monkeypatch.setattr(module, "verify_toolchain", forbidden)
    monkeypatch.setattr(module, "refresh_grype_database", forbidden)
    monkeypatch.setattr(module, "load_scan_exceptions", lambda: ({}, "sha256:" + "a" * 64))
    monkeypatch.setattr(
        module,
        "load_scan_configuration",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            module.EvidenceError("committed scan configuration is missing or unsafe: none")
        ),
    )
    receipt = tmp_path / "build-receipt.json"
    receipt.write_text(
        json.dumps({"formatVersion": "stateport.release-image-build-receipt/v1", "images": {}}),
        encoding="utf-8",
    )
    with pytest.raises(module.EvidenceError, match="missing or unsafe"):
        module.prepare_collection_context(
            build_receipt=receipt,
            candidate_provenance=tmp_path / "provenance.yaml",
            candidate_bundle=tmp_path / "bundle",
        )
    assert os.environ.get("STATEPORT_RELEASE_GUARD_RECEIPT") is None
