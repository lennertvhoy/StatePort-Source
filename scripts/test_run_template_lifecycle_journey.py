#!/usr/bin/env python3
"""The generic third template's Git identity must be a real pin.

The journey creates its third template locally rather than cloning a real
repository, so the recorded ``sourceCommit`` is only a pin if the commit that
produces it is reproducible. It was not: the commit inherited the wall clock, so
two runs of identical content produced different identities, which left an
unverifiable value in a column of pins beside two real ones.

These tests pin reproducibility, the recorded value, and the content, and they
prove the pin is falsifiable rather than decorative: a content change must move
the identity, and a wrong recorded pin must be refused.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_template_lifecycle_journey as journey  # noqa: E402


def _create(tmp_path: Path) -> Path:
    return journey._create_generic_template(tmp_path / "statespec-template")


def _rev_parse(root: Path) -> str:
    return journey._git(root, "rev-parse", "HEAD")


def test_two_independent_creations_produce_the_same_identity(tmp_path: Path) -> None:
    """The defect itself: the same content must yield the same commit id."""
    first = _create(tmp_path / "one")
    second = _create(tmp_path / "two")
    assert _rev_parse(first) == _rev_parse(second)


def test_identity_equals_the_recorded_pin(tmp_path: Path) -> None:
    """The value recorded as the third template's pin is the one produced."""
    produced = _rev_parse(_create(tmp_path))
    assert produced == journey.GENERIC_TEMPLATE_COMMIT


def test_created_tree_is_clean_and_holds_exactly_the_declared_content(
    tmp_path: Path,
) -> None:
    """A clean tree means the recorded identity covers the whole content."""
    root = _create(tmp_path)
    assert journey._git(root, "status", "--porcelain") == ""
    tracked = [
        line for line in journey._git(root, "ls-files").splitlines() if line.strip()
    ]
    assert tracked == ["README.md", "template.yaml"]


def test_a_wrong_recorded_pin_is_refused(tmp_path: Path, monkeypatch) -> None:
    """The guard must fail loudly rather than emit an unreviewed identity."""
    monkeypatch.setattr(journey, "GENERIC_TEMPLATE_COMMIT", "0" * 40)
    with pytest.raises(RuntimeError, match="does not match the recorded pin"):
        _create(tmp_path)


def test_the_pin_detects_a_content_change(tmp_path: Path) -> None:
    """Proof the pin is falsifiable: different content, different identity.

    Built with the same fixed dates, author and message as the generator, so the
    identity can only move because the content moved. Without this, a pinned
    value that no longer describes the template would be indistinguishable from
    a correct one.
    """
    original = _create(tmp_path / "original")
    variant_root = tmp_path / "variant"
    variant_root.mkdir()
    (variant_root / "template.yaml").write_text(
        (original / "template.yaml").read_text(encoding="utf-8").replace(
            "Journey Generic Template", "Journey Generic Template Revised"
        ),
        encoding="utf-8",
    )
    (variant_root / "README.md").write_text(
        (original / "README.md").read_text(encoding="utf-8"), encoding="utf-8"
    )
    env = {
        "GIT_AUTHOR_DATE": journey.GENERIC_TEMPLATE_COMMIT_DATE,
        "GIT_COMMITTER_DATE": journey.GENERIC_TEMPLATE_COMMIT_DATE,
    }
    for arguments in (
        ("init", "-q", "--initial-branch=main"),
        ("config", "user.name", "StatePort journey"),
        ("config", "user.email", "journey@stateport.invalid"),
        ("add", "--all"),
        ("commit", "-q", "-m", "generic template"),
    ):
        journey._git(variant_root, *arguments, env=env)
    assert _rev_parse(variant_root) != _rev_parse(original)
    assert _rev_parse(variant_root) != journey.GENERIC_TEMPLATE_COMMIT


def test_a_second_creation_reuses_the_pinned_checkout(tmp_path: Path) -> None:
    """Idempotence, which the actual-template restart leg depends on.

    The restart leg re-enters the generator in a new process against the same
    disposable root, where the template already exists.  A bare ``mkdir`` there
    raised FileExistsError, which is what failed the restart run; reuse must
    return the same pinned identity instead of recreating it.
    """
    root = _create(tmp_path)
    again = journey._create_generic_template(root)
    assert again == root
    assert _rev_parse(again) == journey.GENERIC_TEMPLATE_COMMIT
    assert journey._git(again, "status", "--porcelain") == ""


def test_a_tampered_preexisting_checkout_is_refused_not_reused(tmp_path: Path) -> None:
    """Reuse must not make the pin decorative.

    Reusing whatever is already on disk would adopt a re-pointed or dirty
    checkout silently, which is the exact hole the recorded pin exists to
    close.  This is the control for that: a second pass over a tampered
    checkout has to fail rather than pass.
    """
    root = _create(tmp_path)
    (root / "README.md").write_text(
        (root / "README.md").read_text(encoding="utf-8") + "tampered\n", encoding="utf-8"
    )
    journey._git(root, "add", "--all")
    journey._git(root, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                 "commit", "-q", "-m", "tamper")
    assert _rev_parse(root) != journey.GENERIC_TEMPLATE_COMMIT
    with pytest.raises(RuntimeError, match="refusing to reuse it"):
        journey._create_generic_template(root)


def test_git_is_available_for_this_suite(tmp_path: Path) -> None:
    """The suite creates real repositories, so record a real dependency."""
    completed = subprocess.run(
        ["git", "--version"], stdout=subprocess.PIPE, text=True, check=True
    )
    assert completed.stdout.startswith("git version")
