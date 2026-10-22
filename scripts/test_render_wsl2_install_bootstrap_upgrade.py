#!/usr/bin/env python3
"""The one-line command must know about an installed release BEFORE it changes
anything on this machine.

The bootstrap installs host packages before it downloads the installer, so a
release that may not take over an existing installation has to be refused
before that first privileged step -- otherwise the person is left with a
changed machine and a refusal.  These tests cover the rendered detection
block itself: that it runs first, that it asks for the typed word
"upgrade" when this release declares the installed one as its predecessor,
and that it refuses in plain words when it may not.

The shell logic is executed, not merely read: a rendered block that says the
right things but computes the wrong answer is the defect this guards.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import render_wsl2_install_bootstrap as wsl2_bootstrap  # noqa: E402

BEGIN = "# stateport:upgrade-detection:begin"
END = "# stateport:upgrade-detection:end"


def _candidate(tmp_path: Path, *, version: str, predecessor=None):
    """Render a candidate's bootstrap from the install suite's own fixtures."""

    import install_no_checkout as installer
    import test_install_no_checkout as install_suite

    tmp_path.mkdir(parents=True, exist_ok=True)
    public = tmp_path / "trust.pub"
    public.write_text(install_suite.TEST_PUBLIC_KEY_PEM, encoding="utf-8")
    trust = {
        "public": public,
        "fingerprint": installer.der_spki_fingerprint(
            install_suite.TEST_PUBLIC_KEY_PEM.encode("ascii")
        ),
        "key_id": install_suite.KEY_ID,
    }
    if predecessor is None:
        fixture = install_suite._signed_index(  # noqa: SLF001 - shared fixture helper
            tmp_path / "fixture",
            trust,
            target_id=installer.WSL2_TARGET_ID,
            version=version,
        )
    else:
        fixture = install_suite._successor_index(  # noqa: SLF001 - shared fixture helper
            tmp_path, trust, predecessor, version=version, target_id=installer.WSL2_TARGET_ID
        )
    candidate = fixture.index_path.parent / "release"
    shutil.copyfile(fixture.index_path, candidate / "release-index.json")
    shutil.copyfile(
        fixture.bundle_root / "release-index.sigstore.json",
        candidate / "release-index.sigstore.json",
    )
    predecessor_bundle = fixture.bundle_root / "predecessor-bundle" / "release-index.sigstore.json"
    if predecessor_bundle.is_file():
        (candidate / "predecessor-bundle").mkdir(exist_ok=True)
        shutil.copyfile(
            predecessor_bundle,
            candidate / "predecessor-bundle" / "release-index.sigstore.json",
        )
    for image_id in install_suite.IMAGES:
        shutil.copyfile(
            fixture.bundle_root / f"{image_id}.sigstore.json",
            candidate / f"{image_id}.sigstore.json",
        )
    text = wsl2_bootstrap.render(
        candidate=candidate,
        trust_public_key=public,
        release_root_url=f"https://example.invalid/download/{version}",
    ).decode("utf-8")
    return text, fixture


def _detection_block(text: str) -> str:
    lines = text.splitlines()
    begin = lines.index(BEGIN)
    end = lines.index(END)
    return "\n".join(lines[begin + 1 : end])


def _run_detection(
    block: str, *, state_root: Path, answer: str = ""
) -> subprocess.CompletedProcess[str]:
    """Run the rendered detection block the way the bootstrap runs it.

    The bootstrap asks on the terminal (``/dev/tty``), so the block runs under
    a pseudo-terminal: ``script`` gives the child a real controlling terminal,
    which is what the person typing the word has.
    """

    script = (
        "fail() { printf 'StatePort install: %s\\n' \"$*\" >&2; exit 1; }\n"
        f'STATE_ROOT="{state_root}"\n'
        f"{block}\n"
        'printf "upgrade_confirmed=%s\\n" "${upgrade_confirmed:-0}"\n'
        'printf "STATEPORT_UPGRADE=%s\\n" "${STATEPORT_UPGRADE:-}"\n'
    )
    return subprocess.run(
        ["/usr/bin/script", "-qec", "/bin/sh -c " + shlex.quote(script), "/dev/null"],
        input=answer,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _installed_release(state_root: Path, release_id: str, version: str, digest: str) -> None:
    state_root.mkdir(parents=True, exist_ok=True)
    (state_root / "installed-release").write_text(
        "schema=stateport.internal-installed-release/v1\n"
        "state=installed\n"
        f"release_id={release_id}\n"
        f"version={version}\n"
        f"signed_payload_digest={digest}\n",
        encoding="utf-8",
    )


def test_the_detection_runs_before_the_first_privileged_step(tmp_path: Path) -> None:
    """Nothing on this machine may be changed before the decision."""

    text, _fixture = _candidate(tmp_path, version="0.1.0-alpha.5")
    lines = text.splitlines()
    detection = lines.index(BEGIN)
    privileged = [
        index
        for index, line in enumerate(lines)
        if line.startswith("sudo ") or line.startswith("sudo -n ")
    ]
    assert privileged, "the bootstrap must have privileged steps"
    assert detection < min(privileged), (
        "the installed-release detection must run before the first privileged step"
    )
    # The install itself is even later.
    assert detection < min(
        index for index, line in enumerate(lines) if 'python3 "$tmp/installer"' in line
    )


def test_the_typed_upgrade_word_is_asked_and_exported(tmp_path: Path) -> None:
    """The declared predecessor is asked about, in plain words."""

    base, base_fixture = _candidate(tmp_path / "base", version="0.1.0-alpha.5")
    text, successor = _candidate(tmp_path / "successor", version="0.1.0-alpha.6", predecessor=base_fixture)
    block = _detection_block(text)
    state_root = tmp_path / "state"

    # Nothing installed here: the command proceeds without asking anything.
    empty = _run_detection(block, state_root=state_root)
    assert empty.returncode == 0, empty.stdout + empty.stderr
    assert "upgrade_confirmed=0" in empty.stdout

    # The declared predecessor is installed: the word "upgrade" is asked for.
    predecessor = json.loads(base_fixture.index_path.read_text(encoding="utf-8"))
    predecessor_digest = (
        "sha256:"
        + __import__("hashlib").sha256(
            json.dumps(
                predecessor["signed"],
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )
    _installed_release(
        state_root, "stateport-alpha-0.1.0-alpha.5", "0.1.0-alpha.5", predecessor_digest
    )
    refused = _run_detection(block, state_root=state_root, answer="no\n")
    assert refused.returncode != 0
    assert "not confirmed" in refused.stdout + refused.stderr
    confirmed = _run_detection(block, state_root=state_root, answer="upgrade\n")
    assert confirmed.returncode == 0, confirmed.stdout + confirmed.stderr
    assert "upgrade_confirmed=1" in confirmed.stdout
    assert "STATEPORT_UPGRADE=1" in confirmed.stdout
    # The plan was explained in plain words before the word was asked for.
    assert "will replace the installed StatePort 0.1.0-alpha.5 in place" in confirmed.stdout


def test_a_release_that_may_not_take_over_is_refused_before_anything_changes(
    tmp_path: Path,
) -> None:
    """Only the declared predecessor may be replaced, and the refusal is plain."""

    base, base_fixture = _candidate(tmp_path / "base", version="0.1.0-alpha.5")
    text, _successor = _candidate(tmp_path / "successor", version="0.1.0-alpha.6", predecessor=base_fixture)
    block = _detection_block(text)
    state_root = tmp_path / "state"
    # A release that is NOT the declared predecessor is installed.
    _installed_release(
        state_root,
        "stateport-alpha-0.1.0-alpha.4",
        "0.1.0-alpha.4",
        "sha256:" + "3" * 64,
    )

    refused = _run_detection(block, state_root=state_root, answer="upgrade\n")

    assert refused.returncode != 0
    assert "cannot replace the installed StatePort 0.1.0-alpha.4 in place" in refused.stdout + refused.stderr
    assert "declares exactly one predecessor release" in refused.stdout + refused.stderr
    assert "stateport-alpha-0.1.0-alpha.5" in refused.stdout + refused.stderr
    assert "Nothing on this machine was changed." in refused.stdout + refused.stderr
    # It says what to do instead.
    assert "stateport-update" in refused.stdout + refused.stderr
    assert "stateport purge" in refused.stdout + refused.stderr
    assert "DELETES your StatePort data" in refused.stdout + refused.stderr


def test_a_release_that_declares_no_predecessor_refuses_too(tmp_path: Path) -> None:
    """A release with no declared predecessor may not replace anything."""

    text, _fixture = _candidate(tmp_path, version="0.1.0-alpha.5")
    block = _detection_block(text)
    state_root = tmp_path / "state"
    _installed_release(
        state_root, "stateport-alpha-0.1.0-alpha.4", "0.1.0-alpha.4", "sha256:" + "4" * 64
    )

    refused = _run_detection(block, state_root=state_root, answer="upgrade\n")

    assert refused.returncode != 0
    assert "declares no predecessor release" in refused.stdout + refused.stderr
    assert "Nothing on this machine was changed." in refused.stdout + refused.stderr


def test_the_same_release_installed_is_not_an_upgrade(tmp_path: Path) -> None:
    """Reinstalling the same release is not an upgrade and asks for nothing."""

    text, fixture = _candidate(tmp_path, version="0.1.0-alpha.5")
    block = _detection_block(text)
    state_root = tmp_path / "state"
    document = json.loads(fixture.index_path.read_text(encoding="utf-8"))
    digest = "sha256:" + __import__("hashlib").sha256(
        json.dumps(
            document["signed"],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    _installed_release(
        state_root, document["signed"]["release"]["releaseId"], "0.1.0-alpha.5", digest
    )

    result = _run_detection(block, state_root=state_root, answer="upgrade\n")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "upgrade_confirmed=0" in result.stdout
    assert "STATEPORT_UPGRADE=" in result.stdout
    assert "STATEPORT_UPGRADE=1" not in result.stdout


@pytest.mark.parametrize("answer", ["", "yes\n", "UPGRADE\n", " upgrade \n"])
def test_only_the_exact_word_upgrades(tmp_path: Path, answer: str) -> None:
    """The word is typed, not guessed: only "upgrade" upgrades."""

    base, base_fixture = _candidate(tmp_path / "base", version="0.1.0-alpha.5")
    text, _successor = _candidate(tmp_path / "successor", version="0.1.0-alpha.6", predecessor=base_fixture)
    block = _detection_block(text)
    state_root = tmp_path / "state"
    predecessor = json.loads(base_fixture.index_path.read_text(encoding="utf-8"))
    digest = "sha256:" + __import__("hashlib").sha256(
        json.dumps(
            predecessor["signed"],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    _installed_release(
        state_root, "stateport-alpha-0.1.0-alpha.5", "0.1.0-alpha.5", digest
    )

    result = _run_detection(block, state_root=state_root, answer=answer)

    assert result.returncode != 0, result.stdout
    assert "not confirmed" in result.stdout + result.stderr


def _payload_digest(fixture) -> str:
    signed = json.loads(fixture.index_path.read_text(encoding="utf-8"))["signed"]
    return "sha256:" + __import__("hashlib").sha256(
        json.dumps(signed, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _receipt(state_root: Path, name: str, document: dict) -> None:
    receipts = state_root / "receipts"
    receipts.mkdir(parents=True, exist_ok=True)
    (receipts / name).write_text(json.dumps(document), encoding="utf-8")


def test_a_release_without_the_flat_record_is_detected_from_its_install_receipt(tmp_path: Path) -> None:
    """Alpha.24 and earlier never wrote installed-release; their install receipt names the release.

    Without this, the one-line command of a successor would not notice the installed predecessor
    before its privileged steps, and the installer would then refuse under --yes because the
    bootstrap never asked for the typed word.
    """

    _base, base_fixture = _candidate(tmp_path / "base", version="0.1.0-alpha.5")
    text, _successor = _candidate(tmp_path / "successor", version="0.1.0-alpha.6", predecessor=base_fixture)
    block = _detection_block(text)
    state_root = tmp_path / "state"
    _receipt(state_root, "install_receipt_aaaa.json", {
        "schema": "stateport.install-receipt/v1", "operation": "install", "result": "succeeded", "finishedAt": "2026-10-08T10:00:00Z",
        "release": {"version": "0.1.0-alpha.5", "signedPayloadDigest": _payload_digest(base_fixture)},
    })
    confirmed = _run_detection(block, state_root=state_root, answer="upgrade\n")
    assert confirmed.returncode == 0, confirmed.stdout + confirmed.stderr
    assert "will replace the installed StatePort 0.1.0-alpha.5 in place" in confirmed.stdout
    assert "STATEPORT_UPGRADE=1" in confirmed.stdout

    # A failed install receipt does not count as an installation.
    failed_root = tmp_path / "failed"
    _receipt(failed_root, "install_receipt_bbbb.json", {
        "result": "failed", "recordedAt": "2026-10-08T10:00:00Z",
        "release": {"version": "0.1.0-alpha.5", "signedPayloadDigest": _payload_digest(base_fixture)},
    })
    nothing = _run_detection(block, state_root=failed_root)
    assert nothing.returncode == 0 and "upgrade_confirmed=0" in nothing.stdout, nothing.stdout + nothing.stderr


def test_an_uninstall_newer_than_the_install_receipt_means_nothing_is_installed(tmp_path: Path) -> None:
    _base, base_fixture = _candidate(tmp_path / "base", version="0.1.0-alpha.5")
    text, _successor = _candidate(tmp_path / "successor", version="0.1.0-alpha.6", predecessor=base_fixture)
    block = _detection_block(text)
    state_root = tmp_path / "state"
    _receipt(state_root, "install_receipt_aaaa.json", {
        "result": "succeeded", "recordedAt": "2026-10-08T10:00:00Z",
        "release": {"version": "0.1.0-alpha.5", "signedPayloadDigest": _payload_digest(base_fixture)},
    })
    install_time = (state_root / "receipts" / "install_receipt_aaaa.json").stat().st_mtime
    _receipt(state_root, "uninstall_receipt_cccc.json", {"result": "succeeded", "finishedAt": "2026-10-09T10:00:00Z"})
    os.utime(state_root / "receipts" / "uninstall_receipt_cccc.json", (install_time + 60, install_time + 60))
    nothing = _run_detection(block, state_root=state_root)
    assert nothing.returncode == 0, nothing.stdout + nothing.stderr
    assert "upgrade_confirmed=0" in nothing.stdout


def test_two_install_receipts_in_the_same_second_are_ordered_by_file_write_not_by_name(tmp_path: Path) -> None:
    # finishedAt has one-second resolution and receipt names are random tokens, so the name must never decide
    # which install came last. Here the later write is the declared predecessor and the earlier one is not.
    _base, base_fixture = _candidate(tmp_path / "base", version="0.1.0-alpha.5")
    text, _successor = _candidate(tmp_path / "successor", version="0.1.0-alpha.6", predecessor=base_fixture)
    block = _detection_block(text)
    state_root = tmp_path / "state"
    same_second = "2026-10-08T10:00:00Z"
    _receipt(state_root, "install_receipt_zzzz.json", {
        "operation": "install", "result": "succeeded", "finishedAt": same_second,
        "release": {"version": "0.1.0-alpha.4", "signedPayloadDigest": "sha256:" + "0" * 64},
    })
    _receipt(state_root, "install_receipt_aaaa.json", {
        "operation": "install", "result": "succeeded", "finishedAt": same_second,
        "release": {"version": "0.1.0-alpha.5", "signedPayloadDigest": _payload_digest(base_fixture)},
    })
    older = (state_root / "receipts" / "install_receipt_zzzz.json").stat().st_mtime
    os.utime(state_root / "receipts" / "install_receipt_aaaa.json", (older + 1, older + 1))
    confirmed = _run_detection(block, state_root=state_root, answer="upgrade\n")
    assert confirmed.returncode == 0, confirmed.stdout + confirmed.stderr
    assert "will replace the installed StatePort 0.1.0-alpha.5 in place" in confirmed.stdout
