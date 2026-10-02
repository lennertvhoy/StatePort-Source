"""Tests for the extend-only immutable release set generator.

The generator exists because the campaign cited a 167-entry hand-authored manifest as proof that
"every earlier published byte" is untouched, while the declared immutable artifact classes held 419
files of which it covered 11, and zero signed payloads. The tests here pin the three properties that
make extending it safe:

  * the scope is exactly three artifact classes, and it does not silently absorb receipts;
  * the output is a UNION, so extending can never quietly release a byte that was already pinned
    (this is the regression that matters most, and it is asserted explicitly, not implied);
  * a pinned byte that is GONE or MISMATCHED makes the build REFUSE and write nothing. A generator
    that can re-baseline a changed byte is not an immutability check, so the anti-blessing test is
    the sharpest one in this file and it exercises the real CLI, not a helper.

The tests are MACHINE-INDEPENDENT: every tree is built in a temporary directory and no test reads
or writes the canonical release root or the live manifest. The canonical numbers are host state, so
they are proved by a separate re-runnable command, not asserted here.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from immutable_release_set import (  # noqa: E402
    SCOPE,
    ImmutableSetError,
    build_manifest,
    digest_file,
    main,
    read_manifest,
    render_manifest,
    scoped_paths,
    verify_existing,
)

# A scope member, a receipt, an evidence document, and two near-miss names that must NOT be
# selected: a name that merely CONTAINS a scoped name is not in scope, and neither is a file that
# merely ends in a scoped suffix.
SCOPE_MEMBERS = (
    "alpha15/bundle-r1/release-index.signed-payload.json",
    "alpha15/bundle-r1/release-index.json",
    "alpha16/bundle-r1/release-index.json",
    "alpha16/candidate-r1/alpha16.sigstore.json",
    "alpha18/bundle-r1/payload.sigstore.json",
)
OUT_OF_SCOPE = (
    "alpha15/bundle-r1/bundle-receipt.json",
    "alpha15/bundle-r1/candidate-input-manifest.json",
    "alpha15/guards/site-public-state-r1.json",
    "alpha15/bundle-r1/evidence/anonymous-normal-clone-receipt.json",
    "alpha15/bundle-r1/notes.txt",
    "alpha15/bundle-r1/release-index.predecessor.json",
    "alpha15/bundle-r1/prefix-release-index.json",
    "alpha16/candidate-r1/alpha16.sigstore.json.bak",
    "alpha16/candidate-r1/README.md",
)


def _build(root: Path) -> Path:
    """Populate a fixture release tree: the five scope members plus the out-of-scope files."""
    for relative in SCOPE_MEMBERS + OUT_OF_SCOPE:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"content of {relative}\n", encoding="utf-8")
    return root


def _existing_manifest(root: Path, *relatives: str) -> dict[str, str]:
    return {relative: digest_file(root / relative) for relative in relatives}


def test_scope_selects_exactly_the_three_declared_classes(tmp_path: Path) -> None:
    """The scope is the three declared classes and nothing adjacent to them."""
    _build(tmp_path)
    assert scoped_paths(tmp_path) == sorted(SCOPE_MEMBERS)
    for excluded in OUT_OF_SCOPE:
        assert excluded not in scoped_paths(tmp_path)
    assert [pattern for _kind, pattern in SCOPE] == [
        "release-index.signed-payload.json",
        "release-index.json",
        "*.sigstore.json",
    ]


def test_scope_covers_every_scope_class_present(tmp_path: Path) -> None:
    """Each of the three classes contributes, and a deeper nesting level is found."""
    deep = "a/b/c/d/e/release-index.signed-payload.json"
    path = tmp_path / deep
    path.parent.mkdir(parents=True)
    path.write_text("{}\n", encoding="utf-8")
    _build(tmp_path)
    assert deep in scoped_paths(tmp_path)


def test_union_adds_the_scope_and_drops_nothing(tmp_path: Path) -> None:
    """THE REGRESSION THAT MATTERS: extending must never release an already-pinned byte.

    The existing manifest pins two receipts that are outside the declared scope and one file that
    is inside it. The union must contain all three unchanged, plus every scoped file. If a future
    change made this a plain overwrite, the two receipts would vanish from the manifest and the
    gate would stop covering bytes it covers today, with a perfectly green exit code.
    """
    _build(tmp_path)
    existing = _existing_manifest(
        tmp_path,
        "alpha15/bundle-r1/bundle-receipt.json",
        "alpha15/guards/site-public-state-r1.json",
        "alpha15/bundle-r1/release-index.json",
    )
    text = build_manifest(tmp_path, existing)
    produced = read_manifest_text(text)

    for relative, digest in existing.items():
        assert relative in produced, f"existing entry {relative} was dropped by the union"
        assert produced[relative] == digest, f"existing entry {relative} was re-digested"
    for relative in SCOPE_MEMBERS:
        assert relative in produced, f"scoped file {relative} was not added"
        assert produced[relative] == digest_file(tmp_path / relative)

    # The dropped set is empty, and the union is strictly larger than the existing manifest.
    assert set(existing) - set(produced) == set()
    assert len(produced) == len(existing) + len(SCOPE_MEMBERS) - 1  # one path is in both


def test_union_over_a_live_looking_manifest_keeps_receipts_and_adds_payloads(tmp_path: Path) -> None:
    """The shape of the real defect: a manifest of receipts extended to cover signed payloads."""
    _build(tmp_path)
    existing = _existing_manifest(
        tmp_path,
        "alpha15/bundle-r1/bundle-receipt.json",
        "alpha15/guards/site-public-state-r1.json",
        "alpha16/candidate-r1/alpha16.sigstore.json",
    )
    produced = read_manifest_text(build_manifest(tmp_path, existing))
    signed = [path for path in produced if path.endswith("release-index.signed-payload.json")]
    assert signed == ["alpha15/bundle-r1/release-index.signed-payload.json"]
    assert len(produced) == 7


def test_gone_entry_makes_the_build_raise_and_write_nothing(tmp_path: Path) -> None:
    """A pinned file that disappeared is a refusal, not a line to delete."""
    _build(tmp_path)
    manifest = tmp_path / "immutable-set.sha256"
    manifest.write_text(
        render_manifest(
            _existing_manifest(
                tmp_path,
                "alpha15/bundle-r1/bundle-receipt.json",
                "alpha15/bundle-r1/release-index.json",
            )
        ),
        encoding="utf-8",
    )
    before = manifest.read_bytes()
    (tmp_path / "alpha15/bundle-r1/bundle-receipt.json").unlink()

    gone, mismatched = verify_existing(tmp_path, read_manifest(manifest))
    assert gone == ["alpha15/bundle-r1/bundle-receipt.json"]
    assert mismatched == []

    with pytest.raises(ImmutableSetError) as refusal:
        build_manifest(tmp_path, read_manifest(manifest))
    assert "alpha15/bundle-r1/bundle-receipt.json" in str(refusal.value)
    assert "gone" in str(refusal.value)
    assert manifest.read_bytes() == before, "the manifest was written despite the interlock firing"


def test_mismatched_entry_makes_the_build_raise_and_write_nothing(tmp_path: Path) -> None:
    """THE ANTI-BLESSING TEST.

    One published byte changes among many that do not. The generator must refuse, name the file, and
    leave the live manifest byte-identical -- through the real CLI with ``--replace``, because that
    is the only path on which anything could be written. A generator that re-baselines here would
    make the immutability gate permanently incapable of detecting this exact change.
    """
    _build(tmp_path)
    manifest = tmp_path / "immutable-set.sha256"
    manifest.write_text(
        render_manifest(
            _existing_manifest(
                tmp_path,
                "alpha15/bundle-r1/release-index.json",
                "alpha15/bundle-r1/bundle-receipt.json",
                "alpha15/guards/site-public-state-r1.json",
                "alpha15/bundle-r1/candidate-input-manifest.json",
            )
        ),
        encoding="utf-8",
    )
    before = manifest.read_bytes()
    tampered = tmp_path / "alpha15/bundle-r1/release-index.json"
    tampered.write_text('{"altered": true}\n', encoding="utf-8")

    gone, mismatched = verify_existing(tmp_path, read_manifest(manifest))
    assert gone == []
    assert mismatched == ["alpha15/bundle-r1/release-index.json"]

    with pytest.raises(ImmutableSetError) as refusal:
        build_manifest(tmp_path, read_manifest(manifest))
    assert "alpha15/bundle-r1/release-index.json" in str(refusal.value)
    assert "mismatched" in str(refusal.value)

    # The real CLI, with the one flag that permits writing at all.
    exit_code = main([str(tmp_path), "--output", str(manifest), "--replace"])
    assert exit_code == 1
    assert manifest.read_bytes() == before, "a changed byte was re-baselined by the CLI"

    # ...and in the mode a CI job or pre-commit hook would use.
    assert main([str(tmp_path), "--output", str(manifest), "--check"]) == 1
    assert manifest.read_bytes() == before


def test_refusal_is_deterministic_and_order_independent(tmp_path: Path) -> None:
    """Two attempts at the same bad tree produce the same refusal, whichever order entries arrive in."""
    _build(tmp_path)
    entries = _existing_manifest(
        tmp_path,
        "alpha15/bundle-r1/bundle-receipt.json",
        "alpha15/bundle-r1/release-index.json",
    )
    (tmp_path / "alpha15/bundle-r1/bundle-receipt.json").unlink()
    (tmp_path / "alpha15/bundle-r1/release-index.json").write_text("changed\n", encoding="utf-8")

    forwards = reversed(dict(entries))
    messages = set()
    for ordering in (dict(entries), {key: entries[key] for key in forwards}):
        with pytest.raises(ImmutableSetError) as refusal:
            build_manifest(tmp_path, ordering)
        messages.add(str(refusal.value))
    assert len(messages) == 1
    assert "1 gone, 1 mismatched" in messages.pop()


def test_no_flag_bypasses_the_interlock(tmp_path: Path) -> None:
    """Neither --check nor --replace can be combined into a re-baseline."""
    _build(tmp_path)
    manifest = tmp_path / "immutable-set.sha256"
    manifest.write_text(
        render_manifest(_existing_manifest(tmp_path, "alpha15/bundle-r1/release-index.json")),
        encoding="utf-8",
    )
    before = manifest.read_bytes()
    (tmp_path / "alpha15/bundle-r1/release-index.json").write_text("changed\n", encoding="utf-8")
    assert main([str(tmp_path), "--output", str(manifest), "--check"]) == 1
    assert main([str(tmp_path), "--output", str(manifest), "--replace"]) == 1
    assert main([str(tmp_path), "--output", str(manifest), "--check", "--replace"]) == 1
    assert manifest.read_bytes() == before


def test_overwrite_without_replace_is_refused(tmp_path: Path) -> None:
    """A healthy tree still may not have the live manifest silently rewritten."""
    _build(tmp_path)
    manifest = tmp_path / "immutable-set.sha256"
    manifest.write_text(
        render_manifest(_existing_manifest(tmp_path, "alpha15/bundle-r1/bundle-receipt.json")),
        encoding="utf-8",
    )
    before = manifest.read_bytes()
    assert main([str(tmp_path), "--output", str(manifest), "--check"]) == 0
    assert main([str(tmp_path), "--output", str(manifest)]) == 2
    assert manifest.read_bytes() == before
    assert main([str(tmp_path), "--output", str(manifest), "--replace"]) == 0
    assert manifest.read_bytes() != before
    assert set(read_manifest(manifest)) == set(SCOPE_MEMBERS) | {
        "alpha15/bundle-r1/bundle-receipt.json"
    }


def test_output_is_deterministic(tmp_path: Path) -> None:
    """The same inputs give byte-identical output, and insertion order of existing entries is irrelevant."""
    _build(tmp_path)
    entries = _existing_manifest(
        tmp_path, "alpha15/bundle-r1/bundle-receipt.json", "alpha15/guards/site-public-state-r1.json"
    )
    first = build_manifest(tmp_path, entries)
    second = build_manifest(tmp_path, entries)
    shuffled = build_manifest(tmp_path, {key: entries[key] for key in reversed(list(entries))})
    assert first == second == shuffled
    # Sorted by path in code-point order, one line per entry, two-space separator, trailing newline.
    lines = first.splitlines()
    assert lines == sorted(lines, key=lambda line: line.split("  ", 1)[1])
    assert all(line.split("  ", 1)[0].isalnum() and len(line.split("  ", 1)[0]) == 64 for line in lines)
    assert first.endswith("\n")
    assert len(lines) == len(set(lines))


def test_output_verifies_with_sha256sum_c_and_detects_a_later_change(tmp_path: Path) -> None:
    """The manifest is in real sha256sum format, and `sha256sum -c` on it has teeth."""
    _build(tmp_path)
    existing = _existing_manifest(tmp_path, "alpha15/bundle-r1/bundle-receipt.json")
    manifest = tmp_path / "immutable-set.sha256"
    manifest.write_text(build_manifest(tmp_path, existing), encoding="utf-8")

    clean = subprocess.run(
        ["sha256sum", "-c", "--quiet", str(manifest)], cwd=tmp_path, capture_output=True, text=True
    )
    assert clean.returncode == 0, clean.stdout + clean.stderr

    (tmp_path / "alpha16/bundle-r1/release-index.json").write_text("tampered\n", encoding="utf-8")
    dirty = subprocess.run(
        ["sha256sum", "-c", "--quiet", str(manifest)], cwd=tmp_path, capture_output=True, text=True
    )
    assert dirty.returncode != 0
    assert "release-index.json" in dirty.stdout + dirty.stderr


def test_scope_does_not_follow_a_symlinked_directory(tmp_path: Path) -> None:
    """A symlink cannot pull an out-of-tree tree into the pinned scope."""
    _build(tmp_path)
    outside = tmp_path.parent / f"outside-{tmp_path.name}"
    outside.mkdir()
    (outside / "release-index.json").write_text("{}\n", encoding="utf-8")
    try:
        (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
        assert "linked/release-index.json" not in scoped_paths(tmp_path)
    finally:
        for child in outside.iterdir():
            child.unlink()
        outside.rmdir()


def test_a_symlink_in_scope_is_refused_rather_than_pinned(tmp_path: Path) -> None:
    """Hashing a symlink's target would pin a byte that lives outside the release tree."""
    _build(tmp_path)
    real = tmp_path / "alpha15/bundle-r1/target.json"
    real.write_text("{}\n", encoding="utf-8")
    link = tmp_path / "alpha15/bundle-r1/release-index.signed-payload.json"
    link.unlink()
    link.symlink_to(real)
    assert "alpha15/bundle-r1/release-index.signed-payload.json" in scoped_paths(tmp_path)
    with pytest.raises(ImmutableSetError) as refusal:
        build_manifest(tmp_path, {})
    assert "symlink" in str(refusal.value)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
@pytest.mark.skipif(
    hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0,
    reason="root ignores the read bit",
)
def test_unreadable_scoped_file_is_a_refusal(tmp_path: Path) -> None:
    """A scoped file that cannot be read is a refusal, not a silently omitted line."""
    import os

    _build(tmp_path)
    locked = tmp_path / "alpha16/bundle-r1/release-index.json"
    locked.chmod(0o000)
    try:
        with pytest.raises(ImmutableSetError) as refusal:
            build_manifest(tmp_path, {})
        assert "cannot read" in str(refusal.value) or "non-regular" in str(refusal.value)
        assert main([str(tmp_path), "--output", str(tmp_path / "new.sha256"), "--replace"]) == 1
        assert not (tmp_path / "new.sha256").exists()
    finally:
        locked.chmod(0o644)


def test_manifest_entry_escaping_the_root_is_refused(tmp_path: Path) -> None:
    """An entry that names a path outside the tree cannot be verified, so it is not a pass."""
    _build(tmp_path)
    with pytest.raises(ImmutableSetError):
        verify_existing(tmp_path, {"../escape.json": "0" * 64})
    with pytest.raises(ImmutableSetError):
        verify_existing(tmp_path, {"/etc/hostname": "0" * 64})


def test_read_manifest_tolerates_the_sha256sum_text_format(tmp_path: Path) -> None:
    """The live manifest's exact two-space format parses, and a contradiction does not."""
    source = tmp_path / "m.sha256"
    source.write_text(
        f"{'a' * 64}  alpha15/bundle-r1/bundle-receipt.json\n"
        f"\n"
        f"{'b' * 64}  alpha15/bundle-r1/release-index.json\n",
        encoding="utf-8",
    )
    assert read_manifest(source) == {
        "alpha15/bundle-r1/bundle-receipt.json": "a" * 64,
        "alpha15/bundle-r1/release-index.json": "b" * 64,
    }
    contradictory = tmp_path / "c.sha256"
    contradictory.write_text(
        f"{'a' * 64}  x.json\n{'b' * 64}  x.json\n", encoding="utf-8"
    )
    with pytest.raises(ImmutableSetError):
        read_manifest(contradictory)
    single_space = tmp_path / "d.sha256"
    single_space.write_text(f"{'a' * 64} x.json\n", encoding="utf-8")
    with pytest.raises(ImmutableSetError):
        read_manifest(single_space)


def read_manifest_text(text: str) -> dict[str, str]:
    """Parse manifest TEXT the same way the real reader parses a file."""
    entries: dict[str, str] = {}
    for line in text.splitlines():
        digest, separator, name = line.partition("  ")
        assert separator
        entries[name] = digest
    return entries
