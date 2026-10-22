#!/usr/bin/env python3
"""The root provisioner must be re-verified after the root install (audit S1-05).

The bootstrap downloads the execution-host provisioner into a user-writable
temporary directory and hash-checks it there, then runs apt/dpkg and several
interactive prompts before it installs the file as root.  Without a second
check, a same-user process could swap ``$tmp/provisioner`` inside that window
and get its bytes installed and executed as root.  The earlier root step (the
podman package stage) already seals and re-hashes as root; the provisioner
install must follow the same rule: hash the root-owned installed copy, as root,
before anything executes it.
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import render_wsl2_install_bootstrap as wsl2_bootstrap  # noqa: E402

INSTALLED = "/usr/local/libexec/stateport-execution-host-provision"


def _render_synthetic(tmp_path: Path) -> str:
    import install_no_checkout as installer
    import test_install_no_checkout as install_suite

    public = tmp_path / "trust.pub"
    public.write_text(install_suite.TEST_PUBLIC_KEY_PEM, encoding="utf-8")
    trust = {
        "public": public,
        "fingerprint": installer.der_spki_fingerprint(
            install_suite.TEST_PUBLIC_KEY_PEM.encode("ascii")
        ),
        "key_id": install_suite.KEY_ID,
    }
    fixture = install_suite._signed_index(  # noqa: SLF001 - shared fixture helper
        tmp_path / "fixture",
        trust,
        target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    candidate = fixture.index_path.parent / "release"
    shutil.copyfile(fixture.index_path, candidate / "release-index.json")
    shutil.copyfile(
        fixture.bundle_root / "release-index.sigstore.json",
        candidate / "release-index.sigstore.json",
    )
    for image_id in install_suite.IMAGES:
        shutil.copyfile(
            fixture.bundle_root / f"{image_id}.sigstore.json",
            candidate / f"{image_id}.sigstore.json",
        )
    return wsl2_bootstrap.render(
        candidate=candidate,
        trust_public_key=public,
        release_root_url="https://example.invalid/download/0.1.0-alpha.5",
    ).decode("utf-8")


def test_root_installed_provisioner_is_rehashed_as_root_before_it_runs(tmp_path: Path) -> None:
    text = _render_synthetic(tmp_path)
    lines = text.splitlines()

    install_at = [
        i for i, line in enumerate(lines)
        if line.startswith("sudo -n install -o root -g root -m 0555 ")
        and '"$tmp/provisioner"' in line and INSTALLED in line
    ]
    assert len(install_at) == 1, "expected exactly one root install of the provisioner"
    install_index = install_at[0]

    # The provisioner's own pinned digest, as the renderer emitted it for the
    # pre-install download check.
    digest = re.search(r'^check "([0-9a-f]{64})" "\$tmp/provisioner"$', text, re.M)
    assert digest, "the pre-install provisioner hash check is missing"

    # A root-run `sha256sum -c` of the INSTALLED root-owned copy must follow the
    # install and precede the first execution of that copy.
    verify_at = [
        i for i, line in enumerate(lines)
        if i > install_index
        and line.startswith("sudo -n sh -c ")
        and "sha256sum -c --status" in line
        and digest.group(1) in line
        and INSTALLED in line
    ]
    assert verify_at, (
        "the installed root provisioner is never re-hashed as root; a swap of "
        "$tmp/provisioner between the download check and the root install would "
        "be installed and executed as root unnoticed"
    )
    first_exec = next(
        i for i, line in enumerate(lines)
        if i > install_index and line.startswith(f"sudo -n {INSTALLED} ")
    )
    assert verify_at[0] < first_exec, "the re-hash must precede the first root execution"
    assert "|| fail" in lines[verify_at[0]], "a failed re-hash must abort the install"
