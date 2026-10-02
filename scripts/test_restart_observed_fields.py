"""The three surviving restart-artifact literals must become observations.

`measured` and `resumedDurableFixtureState` are NOT tested here: a concurrent
lane made them COMPUTED on this branch's base (`measured` from the exit
result, the new origin and the after-restart read; `resumedDurableFixtureState`
from the fixture's own `resume-preserved.json` receipt), and re-testing that
would land a second competing implementation of work that is already done.

What remains is the same defect class in the same artifact, at
`apps/web/tests/live-core.spec.ts` in the `restartInstances` construction. Each
is corroborated by a REAL assertion, so the leg can pass while the recorded
value is a constant and a reader of the artifact is told nothing was measured:

  * `approvedSourceDigestReverifiedInContainer: true`
        real teeth: `proveSource` recomputes the source digest in-container and
        polls for `APPROVED_SOURCE_<expectedDigest>`
  * `ownVolumeMarkerRetained: markerText[index]!`
        the EXPECTED marker name, read out of the DECLARED array rather than
        read back out of the retained volume
  * `foreignVolumeMarkersAbsent: true`
        real teeth: the terminal `test ! -e ... && cat ...` chain

These tests do NOT paraphrase the repair. They extract the exact
`STATEPORT-RESTART-OBSERVATIONS-BEGIN`/`-END` block from the spec and execute it
under node, which strips the TypeScript types natively, so a mutation in the
shipped block is caught here. No browser, no Playwright, no Podman, no governor
slot: the governed journey that CONSUMES these values is a separate, unrun leg.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import re

SPEC = Path(__file__).resolve().parents[1] / "apps" / "web" / "tests" / "live-core.spec.ts"
BEGIN = "// STATEPORT-RESTART-OBSERVATIONS-BEGIN"
END = "// STATEPORT-RESTART-OBSERVATIONS-END"

NODE = shutil.which("node")


def _block() -> str:
    text = SPEC.read_text(encoding="utf-8")
    assert BEGIN in text, f"{SPEC} no longer carries the {BEGIN} marker"
    assert END in text, f"{SPEC} no longer carries the {END} marker"
    assert text.index(BEGIN) < text.index(END)
    return text[text.index(BEGIN):text.index(END)]


def _run(body: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Execute the shipped derivation block under node with `body` as the driver."""
    module = tmp_path / "restart-observations.mts"
    module.write_text(_block(), encoding="utf-8")
    driver = tmp_path / "driver.mts"
    driver.write_text(
        "import * as O from './restart-observations.mts'\n"
        "import assert from 'node:assert/strict'\n"
        + body
        + "\nconsole.log('driver-ok')\n",
        encoding="utf-8",
    )
    return subprocess.run(
        [NODE, str(driver)], cwd=tmp_path, capture_output=True, text=True, timeout=120
    )


def test_the_derivation_block_is_importable_type_stripped_typescript(tmp_path):
    """If this fails every other test here is vacuous: nothing would execute."""
    result = _run("assert.equal(typeof O.deriveOwnVolumeMarkerReadBack, 'function')", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "driver-ok" in result.stdout


# ── deriveOwnVolumeMarkerReadBack: a read-back, not the expectation ─────────

MARKERS = """
const own = 'ui-study-marker'
const expectedContent = 'study-durable'
const declared = ['ui-marker', 'ui-study-marker', 'ui-generic-marker']
const probe = (rows, end = true) => rows.join('\\n') + (end ? '\\nMARK:END\\n' : '\\n')
const all = [
  'MARK:ABSENT:ui-marker',
  'MARK:PRESENT:ui-study-marker:study-durable',
  'MARK:ABSENT:ui-generic-marker',
]
"""


def test_a_complete_read_back_reports_what_the_volume_holds(tmp_path):
    result = _run(
        MARKERS
        + "const r = O.deriveOwnVolumeMarkerReadBack(probe(all), own, expectedContent, declared)\n"
        "assert.equal(r.complete, true)\n"
        "assert.equal(r.ownMarkerRetained, 'ui-study-marker')\n"
        "assert.equal(r.ownMarkerContent, 'study-durable')\n"
        "assert.equal(r.ownMarkerMatchedExpectation, true)\n"
        "assert.equal(r.foreignMarkersAbsent, true)\nassert.equal(r.reason, '')\n"
        "assert.equal(r.observed.length, 3)\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_read_back_name_comes_from_the_volume_not_the_declared_array(tmp_path):
    """The exact defect: a probe naming only ONE marker must not report another.

    `ownVolumeMarkerRetained: markerText[index]!` returned the EXPECTED content
    for every instance no matter what the volume held, so a probe that never
    mentions the third marker must not be able to satisfy the third instance.
    """
    result = _run(
        MARKERS
        + "const r = O.deriveOwnVolumeMarkerReadBack(probe(['MARK:PRESENT:ui-study-marker:study-durable']), 'ui-generic-marker', 'generic-durable', declared)\n"
        "assert.equal(r.ownMarkerRetained, null)\nassert.equal(r.complete, false)\n"
        "assert.equal(r.foreignMarkersAbsent, false)\n"
        "assert.ok(r.reason.includes('did not account for every declared marker'))\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "rows, end, expected",
    [
        # the own marker is simply gone
        (
            "['MARK:ABSENT:ui-marker', 'MARK:ABSENT:ui-study-marker', 'MARK:ABSENT:ui-generic-marker']",
            True,
            "ownMarkerRetained, null",
        ),
        # a foreign marker survived
        (
            "['MARK:PRESENT:ui-marker:capsule-durable', 'MARK:PRESENT:ui-study-marker:study-durable', 'MARK:ABSENT:ui-generic-marker']",
            True,
            "foreignMarkersAbsent, false",
        ),
        # the right marker holds the wrong content
        (
            "['MARK:ABSENT:ui-marker', 'MARK:PRESENT:ui-study-marker:tampered', 'MARK:ABSENT:ui-generic-marker']",
            True,
            "ownMarkerMatchedExpectation, false",
        ),
    ],
)
def test_a_wrong_volume_is_reported_as_wrong(tmp_path, rows, end, expected):
    field, _, value = expected.partition(", ")
    result = _run(
        MARKERS
        + f"const r = O.deriveOwnVolumeMarkerReadBack(probe({rows}, {str(end).lower()}), own, expectedContent, declared)\n"
        f"assert.equal(r.{field}, {value})\n"
        "assert.notEqual(r.reason, '')\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_truncated_probe_cannot_masquerade_as_an_absent_marker(tmp_path):
    """No end sentinel: the read did not finish, so absence is not knowable.

    This is the failure a bare `toContain(ownMarkerText)` invites — the own
    marker can arrive before the run dies, leaving the foreign markers unsaid.
    """
    result = _run(
        MARKERS
        + "const r = O.deriveOwnVolumeMarkerReadBack(probe(all, false), own, expectedContent, declared)\n"
        "assert.equal(r.complete, false)\nassert.equal(r.foreignMarkersAbsent, false)\n"
        "assert.ok(r.reason.includes('never reached its MARK:END'))\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_partial_read_where_only_the_own_marker_arrived_is_refused(tmp_path):
    """The realistic truncation: the `cat` output landed, the rest did not."""
    result = _run(
        MARKERS
        + "const r = O.deriveOwnVolumeMarkerReadBack(probe(['MARK:PRESENT:ui-study-marker:study-durable'], false), own, expectedContent, declared)\n"
        "assert.equal(r.ownMarkerRetained, 'ui-study-marker')\n"
        "assert.equal(r.ownMarkerMatchedExpectation, true)\n"
        "assert.equal(r.complete, false)\n"
        "assert.equal(r.foreignMarkersAbsent, false, 'absence cannot be claimed from a read that never finished')\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_garbled_present_line_is_refused_rather_than_read_as_a_name(tmp_path):
    result = _run(
        MARKERS
        + "const r = O.deriveOwnVolumeMarkerReadBack(probe([...all, 'MARK:PRESENT:no-colon-here']), own, expectedContent, declared)\n"
        "assert.equal(r.complete, false)\nassert.ok(r.reason.includes('no marker name'))\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_marker_name_holding_a_colon_in_its_content_still_splits_correctly(tmp_path):
    """Content is split at the FIRST colon only, so content may contain colons."""
    result = _run(
        MARKERS
        + "const r = O.deriveOwnVolumeMarkerReadBack(probe(['MARK:ABSENT:ui-marker', 'MARK:PRESENT:ui-study-marker:a:b:c', 'MARK:ABSENT:ui-generic-marker']), own, 'a:b:c', declared)\n"
        "assert.equal(r.ownMarkerRetained, 'ui-study-marker')\n"
        "assert.equal(r.ownMarkerContent, 'a:b:c')\n"
        "assert.equal(r.ownMarkerMatchedExpectation, true)\nassert.equal(r.complete, true)\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ── buildVolumeMarkerProbe: the probe and its parser cannot drift ───────────


def test_the_probe_names_every_declared_marker_and_ends_with_a_sentinel(tmp_path):
    result = _run(
        "const names = ['ui-marker', 'ui-study-marker', 'ui-generic-marker']\n"
        "const line = O.buildVolumeMarkerProbe(names)\n"
        "for (const name of names) assert.ok(line.includes(name), name + ' missing from the probe')\n"
        "assert.ok(line.includes('MARK:END'))\nassert.ok(line.includes('MARK:PRESENT'))\n"
        "assert.ok(line.includes('MARK:ABSENT'))\n"
        "// The probe must interrogate every declared name, not a hard-coded three.\n"
        "const one = O.buildVolumeMarkerProbe(['only'])\nassert.equal(one.includes('ui-marker'), false)\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_probe_the_parser_cannot_fully_account_for_yields_no_claim(tmp_path):
    """A probe/parser drift shows up as no claim, never as a silent `true`."""
    result = _run(
        MARKERS
        + "const drifted = O.buildVolumeMarkerProbe(declared).replace('MARK:END', 'MARK:FINISHED')\n"
        "const r = O.deriveOwnVolumeMarkerReadBack(drifted, own, expectedContent, declared)\n"
        "assert.equal(r.complete, false)\nassert.equal(r.foreignMarkersAbsent, false)\n"
        "assert.ok(r.reason.includes('never reached its MARK:END'))\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ── deriveApprovedSourceReverified ─────────────────────────────────────────


def test_approved_source_reverification_is_an_observation(tmp_path):
    # The comparison is a substring test, exactly as `proveSource`'s own poll is.
    # A stricter boundary check would reject the real output if a frame boundary
    # ever put a hex character next to the digest, and that cannot be exercised
    # without the governed journey, so the shipped behaviour is left alone. A
    # 64-hex sha256 cannot be a prefix of a different 64-hex digest, so the
    # looseness cannot produce a false positive for the value actually used.
    result = _run(
        "assert.equal(O.deriveApprovedSourceReverified('noise APPROVED_SOURCE_abc tail', 'abc'), true)\n"
        "assert.equal(O.deriveApprovedSourceReverified('noise APPROVED_SOURCE_abc tail', 'def'), false)\n"
        "assert.equal(O.deriveApprovedSourceReverified('', 'abc'), false)\n"
        "assert.equal(O.deriveApprovedSourceReverified('APPROVED_SOURCE_', 'abc'), false)\n"
        "assert.equal(O.deriveApprovedSourceReverified('APPROVED_SOURCE_ABCD', 'abc'), false)\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ── structural guards: the three literals must not come back ───────────────


def test_the_three_literals_are_no_longer_written_as_constants():
    text = SPEC.read_text(encoding="utf-8")
    assert "approvedSourceDigestReverifiedInContainer: true," not in text, (
        "approvedSourceDigestReverifiedInContainer is a bare constant again"
    )
    assert "ownVolumeMarkerRetained: markerText[index]!," not in text, (
        "ownVolumeMarkerRetained is the expected marker name again, not a read-back"
    )
    assert "foreignVolumeMarkersAbsent: true," not in text, (
        "foreignVolumeMarkersAbsent is a bare constant again"
    )


def test_the_existing_assertions_are_still_present():
    """The derivations are ADDED, never substituted for the real checks."""
    text = SPEC.read_text(encoding="utf-8")
    # proveSource still polls for the exact digest.
    assert "toContain(`APPROVED_SOURCE_${expectedDigest}`)" in text
    # The `&&` chain that short-circuits on a foreign marker is intact.
    assert "test ! -e /workspace/${name}" in text
    assert "&& cat /workspace/${markerNames[index]}" in text
    assert ".toContain(markerText[index]!)" in text
    # And the spec now also consumes its own derivations.
    assert "deriveOwnVolumeMarkerReadBack(" in text
    assert "deriveApprovedSourceReverified(" in text
    assert "buildVolumeMarkerProbe(markerNames)" in text


def test_the_derived_values_are_asserted_so_a_false_derivation_fails_the_leg():
    text = SPEC.read_text(encoding="utf-8")
    assert "expect(approvedSourceReverified," in text
    assert "volumeMarkerReadBack.ownMarkerRetained," in text
    assert "volumeMarkerReadBack.ownMarkerMatchedExpectation," in text
    assert "volumeMarkerReadBack.foreignMarkersAbsent," in text


# ── the pre-restart manifest bytes must be captured, not just digested ──────
#
# r5's `application-workspace-journey.json` predates the run that supposedly
# wrote it: the run died at an assertion long before its writer, so the artifact
# a reader would consult came from an earlier run and the manifest digests were
# never recorded at all. A digest proves equality but cannot be re-checked once
# the run is over, so the pre-restart BYTES are captured into the artifact root
# and stamped with this run's start.


def test_the_pre_restart_manifest_bytes_are_captured_into_the_artifact():
    text = SPEC.read_text(encoding="utf-8")
    assert "bindings-manifest-pre-restart.json" in text, (
        "the pre-restart manifest bytes are not captured, so the survival "
        "comparison cannot be re-checked after a failure"
    )
    # The capture must carry the actual bytes, not only a digest of them.
    assert "bytes: readFileSync(fixture.manifest)" in text
    assert "digest: manifestDigestBeforeRestart" in text
    # And it must be stamped, or a pre-existing capture is indistinguishable
    # from this run's.
    assert "writtenByRunStartingAt: restartRunStartedAt" in text


def test_the_artifact_records_which_run_wrote_it():
    """A reader must be able to tell this artifact from an earlier run's."""
    text = SPEC.read_text(encoding="utf-8")
    assert "writtenByRunStartingAt: restartRunStartedAt" in text
    assert "preRestartManifestBytesArtifact: 'bindings-manifest-pre-restart.json'" in text
    # The timestamp is a real clock read, never a constant.
    assert "const restartRunStartedAt = new Date().toISOString()" in text


def test_the_capture_happens_before_the_restart_not_after():
    """A capture taken after the restart would capture the wrong manifest."""
    text = SPEC.read_text(encoding="utf-8")
    capture = text.index("bindings-manifest-pre-restart.json")
    digest_before = text.index("const manifestDigestBeforeRestart = bindingsManifestDigest()")
    stop = text.index("await stopChild(previousChild)")
    assert digest_before < capture < stop, (
        "the pre-restart manifest must be captured after the before-restart "
        "digest and before the child is stopped"
    )


def test_the_lane_computed_fields_are_not_reimplemented_here():
    """Guard against a second competing implementation of work already done.

    `measured` and `resumedDurableFixtureState` are computed on the base by the
    concurrent lane. If a future edit re-liters them, or introduces a second
    derivation for them in this file, the duplication is the problem this guard
    is here to surface.
    """
    text = SPEC.read_text(encoding="utf-8")
    assert "measured: previousExitResult !== null" in text
    assert "resumedDurableFixtureState: resumePreserved !== null" in text
    for name in ("deriveRestartMeasured", "deriveResumedDurableFixtureState"):
        assert name not in text, f"{name} duplicates the concurrent lane's implementation"


# ── Repairs 2-5: the remaining instances of the same defect class ────────────
#
# Repair 1 above turned three recorded constants into observations. Repairs 2-5
# are the four the independent verifier named, and each is a different shape:
#
#   2  the manifest before/after digest equality was presented as SURVIVAL
#      evidence, when the fixture re-publishes that file on every start
#   3  the comment claiming a post-restart digest separates survival from
#      harness re-publication was FALSE for that file
#   4  `stateAfterRestart` collapsed two read moments into one field
#   5  no pre-restart operation set existed, so "no granted operation was lost"
#      was PARTIAL rather than a differential
#
# Every guard below is fed the REVERTED text as well as the shipped text. A guard
# that cannot reject its own repair is the vacuous-check failure this campaign has
# now hit three times, and the recorded instance of it here was a pure-function
# test blind to input provenance, so the reverted-text cases are the point.


def _spec_text() -> str:
    return SPEC.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """Prose with comment markers and line wrapping removed.

    An earlier version of this file asserted a sentence the source had wrapped
    across two comment lines and failed for that reason alone; stripping only the
    whitespace was not enough either, because each wrapped line keeps its own
    `//` and a needle spanning the wrap still failed. Wrapping a comment is not a
    defect, so a prose check must be insensitive to it.
    """
    stripped = [re.sub(r"^\s*(?://|\*)?\s?", "", line) for line in text.split("\n")]
    return re.sub(r"\s+", " ", " ".join(stripped))


def _node_for(text: str, tmp_path: Path) -> str:
    """Write the derivation block from `text`, not from the file on disk."""
    assert BEGIN in text and END in text
    block = text[text.index(BEGIN):text.index(END)]
    module = tmp_path / "reverted-observations.mts"
    module.write_text(block, encoding="utf-8")
    return str(module)


def _run_against(text: str, body: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    module = _node_for(text, tmp_path)
    driver = tmp_path / "reverted-driver.mts"
    driver.write_text(
        f"import * as O from '{module}'\nimport assert from 'node:assert/strict'\n{body}\nconsole.log('driver-ok')\n",
        encoding="utf-8",
    )
    return subprocess.run([NODE, str(driver)], cwd=tmp_path, capture_output=True, text=True, timeout=120)


# ── repair 2: the digest pair is a RE-PUBLICATION comparison, not survival ──


def _guard_relabel_present(text: str) -> None:
    """The repair-2 guard, as a function so a REVERT can be fed through it."""
    assert "bindingsManifestRepublishedWithEqualContent:" in text
    assert "bindingsManifestComparison: 'republished-equal-content' | 'republished-differing-content'" in text
    assert "NOT\n  // evidence that the bindings manifest file survived" in text, (
        "the interface no longer says the digest pair is not survival evidence"
    )


def _guard_false_claim_absent(text: str) -> None:
    """The repair-3 guard, as a function so a REVERT can be fed through it."""
    assert "does distinguish it." not in text, (
        "the comment still claims a post-restart digest separates survival from "
        "harness re-publication, which is false for a file re-published on every "
        "start and digested over canonicalised content"
    )
    assert "so it cannot tell an untouched file" in text, (
        "the corrected comment must state the reason, not merely drop the claim"
    )
    assert "live-core-fixture.py:733" in text, (
        "the corrected comment must name the re-publishing writer"
    )


def test_the_manifest_digest_pair_is_labelled_a_republication_comparison():
    _guard_relabel_present(_spec_text())


def test_reverting_repair_2_is_rejected():
    """Named mutation: put the digest pair back under a survival label.

    The revert restores the original interface comment and drops the derived
    re-publication fields. The guard above is then run against the REVERTED text
    and must fail. Asserting only that the replacement applied would prove
    nothing about the guard.
    """
    text = _spec_text()
    reverted = text.replace(
        "bindingsManifestComparison: 'republished-equal-content' | 'republished-differing-content'",
        "bindingsManifestSurvivedAcrossRestart: boolean",
    )
    assert reverted != text, "the mutation did not apply; the guard proves nothing"
    with pytest.raises(AssertionError):
        _guard_relabel_present(reverted)


def test_the_republication_label_has_no_surviving_wording(tmp_path):
    """The classification must never be able to say a file survived.

    A digest over canonicalised content cannot separate an untouched manifest
    from a re-published one, so the classifier's whole output space is checked
    rather than one spelling of it.
    """
    body = (
        "const equal = O.classifyManifestRepublication('aaa', 'aaa')\n"
        "const differing = O.classifyManifestRepublication('aaa', 'bbb')\n"
        "assert.equal(equal, 'republished-equal-content')\n"
        "assert.equal(differing, 'republished-differing-content')\n"
        "for (const v of [equal, differing]) { assert.ok(!String(v).includes('surviv')) }\n"
    )
    result = _run_against(_spec_text(), body, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_republication_classifier_rejects_a_survival_label_by_construction(tmp_path):
    """Reverting the classifier into a boolean 'survived' must fail its own test.

    `preserved`-style wording is the defect. This asserts the shipped function
    cannot produce it, which is what makes the relabelling a behaviour change
    rather than a comment edit.
    """
    text = _spec_text()
    body = (
        "const r = [O.classifyManifestRepublication('a','a'), O.classifyManifestRepublication('a','b')]\n"
        "for (const v of r) { assert.ok(!String(v).includes('surviv')) }\n"
    )
    result = _run_against(text, body, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr

    # And the same driver against a REVERTED classifier that does emit it.
    broken = text.replace(
        "return beforeDigest === afterDigest ? 'republished-equal-content' : 'republished-differing-content'",
        "return beforeDigest === afterDigest ? 'survived' : 'republished-differing-content'",
    )
    assert broken != text, "the mutation did not apply"
    mutated = _run_against(broken, body, tmp_path)
    assert mutated.returncode != 0, "a classifier emitting 'survived' still passed the guard"


# ── repair 3: the false comment must be gone, and say why it was false ───────


def test_the_false_survival_claim_is_removed():
    _guard_false_claim_absent(_spec_text())


def test_reverting_repair_3_is_rejected():
    """Named mutation: restore the false sentence verbatim.

    The sentence is the whole defect — it is what made a reader believe the
    digest separated survival from re-publication. Restoring it and re-running
    the guard is the only version of this test that proves the guard bites.
    """
    reverted = _spec_text() + (
        "\n// A digest taken here and again immediately after the restart does distinguish it.\n"
    )
    with pytest.raises(AssertionError):
        _guard_false_claim_absent(reverted)


# ── repair 4: two read moments, two named fields ────────────────────────────


def _guard_two_moments(text: str) -> None:
    assert "stateAfterServiceRestartBeforeInstanceRestart: string" in text
    assert "stateInEngineStatusRead: string" in text
    # Each is written from the read it claims to come from.
    assert "stateAfterServiceRestartBeforeInstanceRestart: workloadStatesAfterRestart[index]!.state," in text
    assert "stateInEngineStatusRead: row!.state," in text


def _guard_no_ambiguous_field(text: str) -> None:
    declarations = re.findall(r"^\s*stateAfterRestart\??:\s*\S+", text, flags=re.M)
    assert declarations == [], f"the ambiguous field is declared again: {declarations}"
    assignments = re.findall(r"^\s*stateAfterRestart:\s*", text, flags=re.M)
    assert assignments == [], "stateAfterRestart is written again"
    # The pre-instance-restart read must come from the pre-re-start list, not the
    # after list, which is the whole point of naming it separately.
    assert "stateAfterServiceRestartBeforeInstanceRestart: workloadStatesAfterRestart[index]!.state," in text
    assert "stateAfterServiceRestartBeforeInstanceRestart: row!.state," not in text


def test_the_two_read_moments_are_two_named_fields():
    _guard_two_moments(_spec_text())


def test_the_ambiguous_single_field_is_gone():
    _guard_no_ambiguous_field(_spec_text())


def test_reverting_repair_4_is_rejected():
    """Named mutation: collapse the pair back into one `stateAfterRestart`.

    Both halves are re-run against the reverted text: the two-field guard must
    fail because the pair is gone, and the ambiguity guard must fail because the
    single field is back. Neither alone is sufficient evidence.
    """
    reverted = _spec_text().replace(
        "        stateAfterServiceRestartBeforeInstanceRestart: workloadStatesAfterRestart[index]!.state,\n"
        "        stateInEngineStatusRead: row!.state,",
        "        stateAfterRestart: workloadStatesAfterRestart[index]!.state,",
    )
    assert reverted != _spec_text(), "the mutation did not apply; the guard proves nothing"
    with pytest.raises(AssertionError):
        _guard_two_moments(reverted)
    with pytest.raises(AssertionError):
        _guard_no_ambiguous_field(reverted)


# ── repair 5: a pre-restart operation set, so the grant claim is differential ─


def _guard_pre_restart_provenance(text: str) -> None:
    anchor = "const grantedOperationsBeforeRestart = workspaceWorkloads.map("
    assert anchor in text
    block = text[text.index(anchor) : text.index(anchor) + 400]
    assert "beforeRestart.workloads" in block, (
        "the pre-restart operation set must be read from the PRE-restart control list"
    )
    assert "afterStart" not in block, (
        "the pre-restart operation set must not be read from the post-restart read"
    )


def _guard_pre_restart_ordering(text: str) -> None:
    read = text.index("const grantedOperationsBeforeRestart = workspaceWorkloads.map(")
    before = text.index("const beforeRestart = await controlList()")
    stop = text.index("await stopChild(previousChild)")
    assert before < read < stop, (
        "the pre-restart operation set must be captured after the pre-restart "
        "control-list read and before the service child is stopped"
    )


def _guard_differential_asserted(text: str) -> None:
    assert "const operationsDelta = deriveGrantedOperationsDelta(" in text
    assert "operationsDelta.lost," in text
    assert ".toEqual([])" in text
    # And the recorded value is the asserted one, not a second computation.
    assert "grantedOperationsPreservedAcrossRestart: operationsDelta.preserved," in text
    assert "lostGrantedOperations: operationsDelta.lost," in text


def test_a_pre_restart_operation_set_exists_and_comes_from_the_pre_restart_read():
    _guard_pre_restart_provenance(_spec_text())


def test_the_pre_restart_read_happens_before_the_service_is_stopped():
    _guard_pre_restart_ordering(_spec_text())


def test_the_grant_differential_is_asserted_not_only_recorded():
    _guard_differential_asserted(_spec_text())


def test_the_grant_differential_detects_a_lost_operation(tmp_path):
    """The teeth: a real differential must FAIL on a real loss.

    A differential that cannot report a loss is the vacuous-check shape, so this
    drives the shipped function with an operation that genuinely disappeared and
    requires it to be named.
    """
    body = (
        "const before = ['start','stop','status','logs','listWorkloads','openTerminal','resizeTerminal',"
        "'signalTerminal','closeTerminal','rebuildVolume']\n"
        "const after = ['start','stop','status','logs','listWorkloads','openTerminal','resizeTerminal',"
        "'signalTerminal','closeTerminal']\n"
        "const d = O.deriveGrantedOperationsDelta(before, after)\n"
        "assert.equal(d.preserved, false)\n"
        "assert.deepEqual(d.lost, ['rebuildVolume'])\n"
    )
    result = _run_against(_spec_text(), body, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr

    # The wrong answer, pinned rather than left implicit: comparing the
    # post-restart list with ITSELF is exactly what reading both sides from
    # `afterStart` would do, and it reports `preserved` forever.
    selfcompare = (
        "const same = ['start','stop','status']\n"
        "const d = O.deriveGrantedOperationsDelta(same, same)\n"
        "assert.equal(d.preserved, true)\nassert.deepEqual(d.lost, [])\n"
    )
    ok = _run_against(_spec_text(), selfcompare, tmp_path)
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_reverting_repair_5_is_rejected():
    """Named mutation: read the pre-restart set from the post-restart control list.

    The result still type-checks and still passes every existing assertion; only
    the source-level guard can see it, which is the point of the ordering and
    provenance guards. All three repair-5 guards are then re-run against the
    reverted text and each must fail.
    """
    text = _spec_text()
    anchor = "const grantedOperationsBeforeRestart = workspaceWorkloads.map("
    reverted = text.replace(
        "      [...(beforeRestart.workloads.find(row => row.workloadId === workloadId)"
        "?.allowedOperations ?? [])].sort(),",
        "      [...(afterStart.workloads.find(row => row.workloadId === workloadId)"
        "?.allowedOperations ?? [])].sort(),",
    )
    assert reverted != text, "the mutation did not apply; the guard proves nothing"
    with pytest.raises(AssertionError):
        _guard_pre_restart_provenance(reverted)
    # Ordering and the differential assertion survive this particular revert,
    # which is exactly why they are separate guards: none of the three alone
    # covers the provenance defect. Asserted so that stays visible.
    _guard_pre_restart_ordering(reverted)
    _guard_differential_asserted(reverted)


# ── Property guards, added after an independent attack found the string pins ──
#
# The five reverting guards above are EXACT-STRING pins. An independent verifier
# demonstrated that seven mutations reinstating the exact defect class this
# increment exists to eliminate — a recorded value written as a constant, or read
# from the wrong side — all passed 34/34, because a pin matches a spelling and
# the defect is a property. Its examples, each measured to pass before this
# section existed:
#
#   grantedOperationsBeforeRestart: ['start','stop','status'],   -> 34 passed
#   grantedOperationsBeforeRestart: [...row!.allowedOperations] -> 34 passed
#   ownVolumeMarkerRetained: markerNames[index]!,               -> 34 passed
#   ownVolumeMarkerContentReadBack: markerText[index]!          -> 34 passed
#   bindingsManifestRepublishedWithEqualContent: true,           -> 34 passed
#
# So the guards below check the PROPERTY: a recorded field's right-hand side must
# be an observation, and for the fields where provenance matters, it must come
# from the named source. Each of the seven is now re-driven as a mutation and
# must FAIL.

def _reject_conditional(field: str, rhs: str) -> str:
    """Refuse a CONDITIONAL right-hand side rather than half-checking it.

    A second independent verifier defeated the string-era guards by keeping the required
    substrings in the UNUSED branch of a ternary, and defeated the comma-splitting
    extractors the same way. Matching a substring anywhere in a conditional says nothing
    about which branch the code takes, so these extractors refuse a `?` outright instead
    of pretending to have checked it.

    A guard that refuses an expression it cannot verify is honest; one that
    substring-matches it is the vacuous check this whole file was written to remove. No
    recorded field currently uses a conditional, which was measured before adding this.
    """
    if "?" in rhs:
        raise AssertionError(
            f"{field} is recorded from a CONDITIONAL expression {rhs!r}. These extractors "
            "cannot tell which branch is taken, so the guard refuses rather than "
            "substring-matching: re-derive an AST check for this shape instead."
        )
    return rhs


def _rhs(text: str, field: str) -> str:
    """The right-hand side of the one assignment that RECORDS `field`.

    Every field this increment touches is declared in an interface AND recorded
    in an object literal, so the two are told apart by the trailing comma that
    only an object-literal entry carries. Anchoring on the record site is what
    makes this a property guard: renaming the value around the field does not
    silently detach it, and the interface declaration cannot satisfy it.
    """
    matches = re.findall(rf"^\s*{re.escape(field)}:\s*(.+),\s*$", text, flags=re.M)
    assert matches, f"{field} is never recorded in the artifact"
    assert len(matches) == 1, f"{field} is recorded {len(matches)} times; the guard cannot tell which"
    return _reject_conditional(field, matches[0].strip())


def _guard_recorded_field_is_not_a_literal(text: str, field: str) -> None:
    """A recorded value must be an observation, not a constant.

    This is the property the whole increment is about, stated once so every
    field can be held to it. A literal is any RHS that is a quoted string, a
    number, a boolean or an inline array/object — the four shapes a constant
    arrives in.
    """
    rhs = _rhs(text, field)
    for literal in ("true", "false", "null", "undefined", "'", '"', "[", "{"):
        assert not rhs.startswith(literal), (
            f"{field} is recorded as the constant {rhs!r}; it must be an observation"
        )


def _guard_recorded_field_comes_from(text: str, field: str, source: str) -> None:
    assert source in _rhs(text, field), (
        f"{field} is not recorded from {source!r} but from {_rhs(text, field)!r}"
    )


def test_no_recorded_field_is_written_as_a_literal():
    """The census, run over every field this increment added or repaired.

    Held as a list rather than as separate tests so a future field cannot be
    added without appearing here, and so a failure names the field.
    """
    for field in (
        "approvedSourceDigestReverifiedInContainer",
        "ownVolumeMarkerRetained",
        "ownVolumeMarkerContentReadBack",
        "ownVolumeMarkerMatchedExpectation",
        "foreignVolumeMarkersAbsent",
        "grantedOperationsPreservedAcrossRestart",
        "lostGrantedOperations",
        "bindingsManifestRepublishedWithEqualContent",
        "bindingsManifestComparison",
    ):
        _guard_recorded_field_is_not_a_literal(_spec_text(), field)


def test_the_volume_marker_fields_are_recorded_from_the_readback_not_the_declaration():
    text = _spec_text()
    _guard_recorded_field_comes_from(text, "ownVolumeMarkerRetained", "volumeMarkerReadBack.ownMarkerRetained")
    _guard_recorded_field_comes_from(text, "ownVolumeMarkerContentReadBack", "volumeMarkerReadBack.ownMarkerContent")
    _guard_recorded_field_comes_from(text, "ownVolumeMarkerMatchedExpectation", "volumeMarkerReadBack.ownMarkerMatchedExpectation")
    _guard_recorded_field_comes_from(text, "foreignVolumeMarkersAbsent", "volumeMarkerReadBack.foreignMarkersAbsent")
    # The trap the string pin missed: `markerNames[index]!` is the DECLARED name
    # and reads almost identically to `markerText[index]!`, the old literal.
    for field, source in (
        ("ownVolumeMarkerRetained", "volumeMarkerReadBack.ownMarkerRetained"),
        ("ownVolumeMarkerContentReadBack", "volumeMarkerReadBack.ownMarkerContent"),
    ):
        assert "markerText[index]!" not in _rhs(text, field)
        assert "markerNames[index]!" not in _rhs(text, field)


def test_the_pre_restart_operation_set_is_recorded_from_the_pre_restart_read():
    """The mutation the verifier showed passing 34/34: record it as a constant,
    or record it from the POST-restart list. Both are the same defect."""
    text = _spec_text()
    _guard_recorded_field_comes_from(text, "grantedOperationsBeforeRestart", "grantedOperationsBeforeRestart[index]")
    rhs = _rhs(text, "grantedOperationsBeforeRestart")
    assert "row!.allowedOperations" not in rhs, (
        "the recorded pre-restart operation set is read from the POST-restart list"
    )
    assert "afterStart" not in rhs


def test_the_grant_delta_is_recorded_from_the_asserted_object():
    text = _spec_text()
    _guard_recorded_field_comes_from(text, "grantedOperationsPreservedAcrossRestart", "operationsDelta.preserved")
    _guard_recorded_field_comes_from(text, "lostGrantedOperations", "operationsDelta.lost")
    # And the delta itself is built from the pre-restart side, not compared to
    # itself: that is the revert that type-checks and passes every assertion.
    delta = re.search(r"const operationsDelta = deriveGrantedOperationsDelta\((.*?)\)\n", text, re.S)
    assert delta, "the delta is not constructed"
    assert "grantedOperationsBeforeRestart[index]" in delta.group(1)
    assert "row!.allowedOperations" in delta.group(1)


def test_the_manifest_republication_is_computed_once_and_asserted():
    text = _spec_text()
    # ONE computation, read twice: the verifier found the boolean and the label
    # derived independently, which is the "second computation of it" that repair
    # 5's own comment forbids.
    assert text.count("const manifestRepublication = classifyManifestRepublication(") == 1
    _guard_recorded_field_comes_from(text, "bindingsManifestComparison", "manifestRepublication")
    _guard_recorded_field_comes_from(
        text, "bindingsManifestRepublishedWithEqualContent", "manifestRepublication ==="
    )
    # And the label is ASSERTED, so a re-publication that changed the content
    # fails the leg instead of being recorded quietly.
    assert "const manifestRepublication = classifyManifestRepublication(" in text
    assert re.search(r"expect\(\s*manifestRepublication,", text), (
        "the re-publication label must be asserted, not only derived"
    )
    assert ").toBe('republished-equal-content')" in text


def test_the_second_read_field_is_named_for_its_read_not_for_an_operation():
    """Only ONE of the three instances is actually re-started.

    A field named for that operation would claim it for the other two, which is
    the same prose-disagrees-with-the-measurement class as the false comment.
    """
    text = _spec_text()
    assert "stateInEngineStatusRead: string" in text
    assert "stateInEngineStatusRead: row!.state," in text
    assert re.search(r"^\s*stateAfterInstanceRestart\??:\s*\S+", text, flags=re.M) is None
    assert "only the stopped instance is actually re-started" in _flat(text), (
        "the comment must say the re-start happens for one of three, not imply all three"
    )


def test_every_mutation_that_defeated_the_string_pins_is_now_rejected():
    """SIX of the seven mutations the verifier measured passing at 34/34.

    The seventh re-worded repair 3's false claim rather than restoring it, and is
    held by `_guard_false_claim_absent` requiring the reason as well as the
    absence of the claim; it is not a recorded field and does not belong here.

    Each of these six reinstates the recorded-as-constant or wrong-provenance
    class, and each must now fail the property guard. This is the test that would
    have caught the first version of this file being decorative.
    """
    text = _spec_text()

    # A LITERAL revert: the field is filled with a constant. Only the literal
    # guard can see this, because a constant that happens to be an array is not
    # a literal by the shape test alone.
    literal_reverts = [
        ("grantedOperationsBeforeRestart", "grantedOperationsBeforeRestart[index]!", "['start','stop','status']"),
        ("ownVolumeMarkerMatchedExpectation", "volumeMarkerReadBack.ownMarkerMatchedExpectation", "true"),
        (
            "bindingsManifestRepublishedWithEqualContent",
            "manifestRepublication === 'republished-equal-content'",
            "true",
        ),
    ]
    for field, source, replacement in literal_reverts:
        original = f"{field}: {source},"
        assert original in text, f"cannot build the revert for {field}: {original!r} not present"
        reverted = text.replace(original, f"{field}: {replacement},", 1)
        assert reverted != text, f"the revert for {field} did not apply"
        with pytest.raises(AssertionError):
            _guard_recorded_field_is_not_a_literal(reverted, field)

    # A PROVENANCE revert: the field is filled from the WRONG source. Every one
    # of these is an expression, not a constant, so no amount of literal-shaped
    # checking would catch it — which is precisely why the provenance guard had
    # to be added at all.
    provenance_reverts = [
        ("ownVolumeMarkerRetained", "volumeMarkerReadBack.ownMarkerRetained", "markerNames[index]!"),
        ("ownVolumeMarkerContentReadBack", "volumeMarkerReadBack.ownMarkerContent", "markerText[index]!"),
        (
            "grantedOperationsBeforeRestart",
            "grantedOperationsBeforeRestart[index]!",
            "[...row!.allowedOperations].sort()",
        ),
    ]
    for field, source, replacement in provenance_reverts:
        original = f"{field}: {source},"
        assert original in text, f"cannot build the revert for {field}: {original!r} not present"
        reverted = text.replace(original, f"{field}: {replacement},", 1)
        assert reverted != text, f"the revert for {field} did not apply"
        with pytest.raises(AssertionError):
            _guard_recorded_field_comes_from(reverted, field, source)



# ── the manifest assertion MESSAGE, which is the last survival word on this comparison ──
#
# An independent verifier found that after repair 2 the artifact is correctly
# relabelled, but the assertion MESSAGE at the digest comparison still read "the
# bindings manifest must survive the service restart", which is a survival claim
# attached to a republication comparison. It is an in-run failure message rather
# than artifact content, so it cannot mislead a reader of a passing artifact -- but
# it is the last place the old framing survives in the code that owns this
# comparison, and this file's entire subject is that the wording must agree with
# the measurement. Prose fixed without a guard is how the previous teeth were pins,
# so the message is guarded exactly like the fields are. The guard is a PURE
# function of the text it is handed, like every other guard here: it never reads or
# writes SPEC itself, so running it against a mutation cannot touch the repository.
_MANIFEST_EXPECT_ANCHOR = "manifestDigestAfterRestart,\n      'the bindings manifest"


def _guard_manifest_message_is_not_survival_framed(text: str) -> None:
    start = text.find(_MANIFEST_EXPECT_ANCHOR)
    assert start != -1, (
        "the manifest-digest expectation no longer carries its own opening string, so "
        "this guard cannot see the message it exists to check"
    )
    # Bound the message to the concatenated string literals between the asserted
    # value and the closing of its expect call. That bound is what keeps the check
    # honest in the other direction too: the block legitimately contains the words
    # "survival evidence" and "restart survival" in comments that correctly point at
    # the grant differential, and a whole-block search would reject those.
    end = text.index(").toBe(", start)
    message = text[start:end]
    lowered = message.lower()
    assert "survive" not in lowered, (
        "the manifest-digest assertion message still claims the manifest survived the "
        "restart, but this comparison is a RE-PUBLICATION over canonical content and "
        f"cannot tell an untouched file from a re-published one: {message!r}"
    )
    assert "re-publication" in lowered or "republication" in lowered, (
        "the manifest-digest assertion message must state that the comparison is a "
        f"re-publication comparison rather than leaving the reader to infer it: {message!r}"
    )


def test_the_manifest_assertion_message_is_not_survival_framed():
    _guard_manifest_message_is_not_survival_framed(SPEC.read_text(encoding="utf-8"))


def test_restoring_the_survival_wording_in_the_message_is_rejected():
    """Named mutation: put the old survival framing back in the message.

    The revert restores the exact string the verifier found, and the guard is then
    run against the REVERTED text and must fail. Without this the repair would be
    prose with no teeth -- measured, not assumed: before this test existed the same
    mutation passed 41 of 41.
    """
    text = SPEC.read_text(encoding="utf-8")
    reverted = text.replace(
        "'the bindings manifest must come back with the same canonical content after the '",
        "'the bindings manifest must survive the service restart byte-for-byte, '",
        1,
    )
    assert reverted != text, "the mutation did not apply; the guard proves nothing"
    with pytest.raises(AssertionError):
        _guard_manifest_message_is_not_survival_framed(reverted)


# ── the durable grant read-back must be able to find a grant ───────────────
#
# This block was added by acd39fc1 and shipped with NO coverage at all: a full
# revert of that commit left this file at 43/43. Worse, the directory it read
# from came from the fixture's `reviewedIssuance` pointer, which is only
# published when STATEPORT_UI_REVIEWED_ISSUANCE=1 -- a flag the restart leg never
# sets. So `durableGrantsDir` was null in the only leg that runs this code, every
# grant recorded `present: false`, `allDurableGrantsPresent` recorded false, and
# nothing asserted any of it. The leg passed while the evidence it added said no
# grant survived. These guards exist so that cannot come back.


def test_the_durable_grants_directory_does_not_come_from_the_reviewed_issuance_pointer():
    """The pointer is null in this leg, so deriving the path from it is vacuous."""
    text = _spec_text()
    rhs = _rhs(text, "grantsDir")
    assert "reviewedIssuance" not in rhs, (
        "grantsDir is derived from the reviewed-issuance pointer, which the "
        f"restart leg never populates, so the read-back cannot find anything: {rhs!r}"
    )
    # The record site names the variable, so the provenance is one hop further
    # out: follow it to the definition rather than expecting the receipt name to
    # appear at the record site.
    variable = rhs.strip()
    assert variable == "durableGrantsDir", (
        f"grantsDir should be recorded from the read-back variable, not from {rhs!r}"
    )
    definition = re.search(
        rf"const\s+{re.escape(variable)}\s*=\s*(.+)", text
    )
    assert definition, f"{variable} has no definition to trace"
    source = definition.group(1)
    assert "reviewedIssuance" not in source, (
        f"{variable} is derived from the reviewed-issuance pointer, which the "
        f"restart leg never populates: {source!r}"
    )
    assert "resumePreserved" in source and "state" in source and "grants" in source, (
        f"{variable} should be the resumed daemon root's state/grants directory, "
        f"not {source!r}"
    )


def test_a_grant_is_matched_by_the_workload_ids_its_own_document_declares():
    """Matching is by CONTENT, not by a guessed `grant-<workloadId>` filename.

    The file on disk is named after `grantId`. In this configuration that name
    happens to equal `grant-<workloadId>`, which is why the guess appeared to
    work; it is a coincidence, not a contract, and a rename would silently turn
    every grant into an absent one.
    """
    flat = _flat(_spec_text())
    assert "workloadIds" in flat, "the grant match must read the workloadIds the grant document declares"
    assert "grant-${workloadId}" not in _spec_text(), (
        "the read-back guesses the grant filename from the workload id; the file "
        "is named after grantId, so the guess is a coincidence that can break"
    )


def test_the_grant_directory_read_excludes_the_revocation_record():
    """revocation.json lives in the grants directory and is not a grant."""
    text = _spec_text()
    assert "'revocation.json'" in text, (
        "revocation.json shares the grants directory and must be excluded from the read-back"
    )


def test_the_grant_read_back_is_asserted_so_it_cannot_report_all_false():
    """The missing falsifier: without an assertion an all-false object still passes."""
    flat = _flat(_spec_text())
    assert "every imported workload must still have its durable grant on disk" in flat, (
        "the read-back records allDurableGrantsPresent but never asserts it, so an "
        "all-false read-back would pass the leg"
    )
    assert "the resumed daemon root must contain the durable grants directory" in flat, (
        "the grants directory existence must be asserted, or a wrong path reads as "
        "'no grants' rather than as a failure"
    )


# ── containerRestartReconnect: an honest unrun marker, with teeth ─────────────
#
# A concurrent lane bound `containerRestartReconnect` to `observedRecoveredTargetRotated`
# on 2026-09-27, on the reasoning that a hard-coded 'not_run' "claimed the behaviour was
# uncovered while an assertion for it sat 700 lines earlier". The premise is a misreading.
# The assertion it points at proves that WORKSPACE RECOVERY rotated the capsule target --
# which is removal-then-recovery, already reported honestly as `recoveredRemovedWorkspace`
# -- and not that a container was restarted. This journey never restarts a container.
#
# So the field is REVERTED to the reviewed 'not_run' marker, and the guards below exist so
# a future edit cannot quietly re-bind it to anything without noticing.

def _rhs_first_field(text: str, field: str) -> str:
    """The right-hand side up to the FIRST comma.

    `_rhs` takes everything to the LAST comma, which is right for the record sites
    it was written for and wrong for a line recording two fields, as this one does:
    `containerRestartReconnect: 'not_run', endedSessionReconnect: ...`. Taking the
    whole tail made the guard compare a two-field string against a one-field
    literal, so it failed for a formatting reason rather than for the defect.
    """
    matches = re.findall(rf"^\s*{re.escape(field)}:\s*(.+?),\s", text, flags=re.M)
    assert matches, f"{field} is never recorded in the artifact"
    assert len(matches) == 1, f"{field} is recorded {len(matches)} times; the guard cannot tell which"
    return _reject_conditional(field, matches[0].strip())


def _guard_container_restart_is_an_honest_unrun_marker(text: str) -> None:
    _rhs_field = _rhs_first_field(text, "containerRestartReconnect")
    assert _rhs_field == "'not_run'", (
        "containerRestartReconnect must read the reviewed 'not_run' marker; it currently "
        f"reads {_rhs_field!r}. Binding it to a recovery or workspace variable relabels "
        "workspace removal-and-recovery as a container restart."
    )


def test_container_restart_reconnect_is_the_honest_unrun_marker():
    _guard_container_restart_is_an_honest_unrun_marker(_spec_text())


def _guard_no_recovery_variable_bound_to_container_restart(text: str) -> None:
    """The exact regression, as a property rather than a spelling.

    `observedRecoveredTargetRotated` is the variable that was bound. Pinning the
    variable NAME would be a string pin and would miss a rename; checking that the
    right-hand side is the literal 'not_run' is the property, and this test
    additionally names the family of variables the defect lives in so the reason is
    legible to whoever reads the failure.
    """
    rhs = _rhs_first_field(text, "containerRestartReconnect")
    for family in ("Recovered", "RecoveredRemoved", "recoveryPrepare", "recoveredTargetId"):
        assert family not in rhs, (
            f"containerRestartReconnect is bound to {rhs!r}, which is a workspace-recovery "
            f"measurement ({family}); that is not a container restart"
        )
    # The honest report of the same event exists under its own name and is not lost.
    assert "recoveredRemovedWorkspace: observedRecoveredRemovedWorkspace" in text


def test_no_recovery_or_workspace_variable_is_bound_to_the_container_restart_field():
    _guard_no_recovery_variable_bound_to_container_restart(_spec_text())


def test_the_absence_of_a_container_restart_is_measured_not_asserted():
    """A guard that says 'no Restart control' should MEASURE it, not believe it.

    The claim is that this journey never drives a container restart. That is
    falsifiable from the source: if a restart control is ever clicked, the count
    changes. Measured at the pin that carried the false binding, 'Restart'
    occurred zero times in the whole file, so this is not a vacuous check -- it is
    a check whose expected value is currently zero and is re-measured every run.
    """
    text = _spec_text()
    assert text.count("'Restart'") == 0, (
        "a 'Restart' control is now referenced in the spec; the container-restart leg may "
        "have become runnable, and this marker must then be driven and measured rather than "
        "left as not_run"
    )
    assert text.count('name: "Restart"') == 0


def test_reverting_the_revert_is_rejected():
    """Named mutation: re-bind the field to the recovery rotation.

    Every guard above is re-run against the reverted text and each must fail. The
    point of the revert is that it is not a comment but a checked property.
    """
    text = _spec_text()
    reverted = text.replace(
        "containerRestartReconnect: 'not_run',",
        "containerRestartReconnect: observedRecoveredTargetRotated,",
    )
    assert reverted != text, "the mutation did not apply; the guards prove nothing"
    with pytest.raises(AssertionError):
        _guard_container_restart_is_an_honest_unrun_marker(reverted)
    with pytest.raises(AssertionError):
        _guard_no_recovery_variable_bound_to_container_restart(reverted)
    # The rotation itself must still be honestly reported under its own name.
    assert "recoveredRemovedWorkspace: observedRecoveredRemovedWorkspace" in reverted


# ── Is the container-restart leg RUNNABLE? Measure the PRODUCT, not the test ──
#
# The guard above answers "does this journey drive a restart?", by counting restart-control
# names in the spec. That is necessary and it is NOT sufficient. A leg can be undriven
# because nobody wrote the step, or because the product offers nothing to drive. The two
# need different remedies and they look identical from inside the test file.
#
# MEASURED, at the commit that carried the false binding, at three layers:
#   1. the product page apps/web/src/features/execution-host/ExecutionHostPage.tsx contains
#      ZERO case-insensitive occurrences of "restart". Its lifecycle operations are
#      startWorkload, stopWorkload and removeWorkload, plus the "Recover application
#      workspace" control.
#   2. the service API exposes NO restart route at all.
#   3. packages/execution-host/src/execution_host/workspaces.py:161 DOES define
#      WorkspaceRuntime.restart -- but it is a Python composite, `self.stop(...)` then
#      `self.start(...)`, and it is not reachable through the service control API for an
#      application workspace. The /v1/deployments/{id}/restart route is a DEPLOYMENT
#      surface, a different object from the application workspace this journey drives.
#
# So the honest reading is that the leg is UNRUNNABLE through this product surface, not
# merely unvisited. The guard below watches the PRODUCT so that if a restart affordance is
# ever added, it fails and says the leg has become drivable -- otherwise the not_run marker
# could outlive the reason it was honest.

PRODUCT_PAGE = Path(__file__).resolve().parents[1] / "apps" / "web" / "src" / "features" / "execution-host" / "ExecutionHostPage.tsx"
SERVICE_API = (
    Path(__file__).resolve().parents[1]
    / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "service_process.py"
)


def _workspace_scoped_restart_routes(api_text: str) -> list[str]:
    """Restart routes in the service API that apply to an APPLICATION WORKSPACE.

    The deployment route /v1/deployments/{id}/restart is deliberately EXCLUDED: a
    deployment is a different object from the application workspace this journey
    drives, and counting it would make this guard a no-op that can never fire --
    which is a vacuous guard wearing the costume of a check.

    This also corrects a measurement of mine that was wrong. I first grepped
    `packages/service/src/stateport/service_process.py`, a path that does not exist,
    and reported "the service API exposes no restart route at all". The empty result
    was a missing file, not an absence. Re-measured against the real path
    packages/persistent-app/src/stateport_persistent_app/service_process.py, there are
    SIX restart occurrences: the deployment route and its approval plumbing, plus two
    unrelated comments about the service's own listener restarting. The conclusion
    survives -- there are ZERO workspace-scoped restart routes -- but it now rests on
    a file that exists, which is what makes it a measurement rather than a typo.
    """
    return [
        line.strip()
        for line in api_text.splitlines()
        if re.search(r"restart", line, flags=re.I)
        and re.search(r"workspace|workload|execution-host", line, flags=re.I)
        and "deployment" not in line.lower()
    ]


def _product_offers_a_container_restart() -> tuple[bool, str]:
    """Does the application-workspace product surface offer a restart at all?

    Returned with the evidence string so a failure names WHICH layer changed, since
    'the leg became runnable' is only actionable if you know where the affordance appeared.
    """
    page = PRODUCT_PAGE.read_text(encoding="utf-8")
    if re.search(r"restart", page, flags=re.I):
        return True, f"the execution-host page now mentions restart ({PRODUCT_PAGE.name})"
    api_text = SERVICE_API.read_text(encoding="utf-8")
    scoped = _workspace_scoped_restart_routes(api_text)
    if scoped:
        return True, f"the service API now exposes a workspace-scoped restart route: {scoped[0]}"
    return False, (
        "no restart affordance in the execution-host page, and no workspace-scoped restart "
        "route in the service API (the only restart route is /v1/deployments/{id}/restart, "
        "a different object)"
    )


def test_the_container_restart_leg_is_still_unrunnable_and_that_is_measured():
    offered, where = _product_offers_a_container_restart()
    if offered:
        # The marker must now be DRIVEN, not left as not_run. Failing here is the point:
        # a not_run that outlives its reason is exactly the honesty defect this file exists
        # to prevent, and the message says what to do about it.
        raise AssertionError(
            f"the container-restart leg appears to have become runnable: {where}. The "
            "'not_run' marker in containerRestartReconnect must then be driven and measured "
            "rather than left standing."
        )
    # And the marker is still in place, so the two facts agree.
    _guard_container_restart_is_an_honest_unrun_marker(_spec_text())


def test_the_unrunnable_leg_is_watched_on_the_product_not_only_on_the_test():
    """Non-vacuity: the guard must fire when a product affordance appears.

    A guard that only counted occurrences in the spec would pass unchanged while the
    product gained a restart control, which is the failure mode this test exists to rule
    out. Driving both layers is what makes the "unrunnable" claim falsifiable.
    """
    page = PRODUCT_PAGE.read_text(encoding="utf-8")
    assert not re.search(r"restart", page, flags=re.I), (
        f"{PRODUCT_PAGE} now offers a restart affordance; the not_run marker must be driven"
    )
    scoped = _workspace_scoped_restart_routes(SERVICE_API.read_text(encoding="utf-8"))
    assert scoped == [], (
        f"the service API now exposes a workspace-scoped restart route {scoped}; the not_run "
        "marker must then be driven and measured"
    )
    # The deployment route is EXPECTED to exist and is deliberately not counted, so this
    # guard is a live check rather than one that can never fire.
    assert "/v1/deployments" in SERVICE_API.read_text(encoding="utf-8"), (
        "the deployment restart route has disappeared; the exclusion this guard relies on "
        "must be re-measured rather than inherited"
    )
    # The composite in the execution host is EXPECTED to exist and is NOT a product
    # affordance, so it is deliberately not treated as one -- otherwise this guard would
    # be reporting a file that will always match.
    workspaces = (
        Path(__file__).resolve().parents[1]
        / "packages" / "execution-host" / "src" / "execution_host" / "workspaces.py"
    ).read_text(encoding="utf-8")
    assert "def restart(" in workspaces, (
        "WorkspaceRuntime.restart is expected at workspaces.py:161; if it is gone, the "
        "reason this leg is unrunnable has changed and must be re-measured, not inherited"
    )


# ── The workspace restart IS driven, and the artifact now says so ─────────────
#
# This closes the loop opened by the false `containerRestartReconnect` binding. The journey
# ALREADY performed a genuine stop-then-start on a workspace at two click sites, and the
# product's own definition makes that a restart -- the spec says so in its own comment:
# "the product's own WorkspaceRuntime.restart() is defined as exactly stop() then start()".
#
# So the leg was never unrunnable after all. What was missing is that the artifact never
# recorded that the reconnect FOLLOWED a restart, so a reader saw a reconnect and a
# running/stopped/running sequence and had to infer the link. That is now recorded, with
# both ledger states read live at the two moments the journey already polls.

def _strip_comments(text: str) -> str:
    """Source with `//` and block-comment prose removed.

    A pattern match against commented-out code proves nothing, and one guard here was
    defeated exactly that way. Stripping prose is the difference between asserting the
    code does something and asserting the file mentions it.
    """
    without_block = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", without_block)


def test_the_workspace_restart_states_are_read_live_not_declared():
    """Both states come from the ledger at the moments the journey polls them.

    Anchored on the polling, not on the recorded text, so declaring the values instead of
    reading them detaches the guard.
    """
    text = _spec_text()
    # The read must be CODE, not prose. An independent verifier defeated the previous
    # version of this guard by replacing both live reads with COMMENTED-OUT copies of the
    # same text, which satisfied the regex while the reads no longer read anything -- 0
    # tests failed. A guard satisfied by the artefact it polices is a guard that measures
    # nothing, so the comment lines are stripped before the pattern is applied.
    code = _strip_comments(text)
    assert re.search(
        r"observedStateAfterStop = ledger\(a\)\.state", code
    ), "stateAfterStop must be read from the live ledger, in code rather than in a comment"
    assert re.search(
        r"observedStateAfterStart = ledger\(a\)\.state", code
    ), "stateAfterStart must be read from the live ledger, in code rather than in a comment"
    # And the recorded object carries the two reads, not literals.
    for field in ("stateAfterStop: observedStateAfterStop,", "stateAfterStart: observedStateAfterStart,"):
        assert field in text, f"the artifact must record {field!r} rather than a constant"
    _guard_recorded_field_is_not_a_literal(_spec_text(), "stopThenStartObserved")


def test_the_restart_leg_records_which_object_it_is_and_keeps_the_two_apart():
    """The conflation that started this thread, guarded at the source.

    A workspace restart PRESERVES the capsule target; container recovery ROTATES it. A
    reader must be able to tell which happened, and the field name must not claim the
    stronger of the two.
    """
    text = _spec_text()
    assert "productDefinition: 'stop() then start() (WorkspaceRuntime.restart)'," in text, (
        "the artifact must name the product's own definition of a restart, so it need not be "
        "read against the source"
    )
    assert "capsuleTargetPreserved: freshPreparation.target.targetId === initialPreparation.target.targetId," in text
    # The container-restart field must STILL be the honest unrun marker, now for a stated
    # reason rather than a vague one: the restart that was driven is a WORKSPACE restart.
    _guard_container_restart_is_an_honest_unrun_marker(text)
    # And the recovery rotation keeps its own honest name; it is not folded in here.
    assert "recoveredRemovedWorkspace: observedRecoveredRemovedWorkspace" in text


def test_reverting_the_restart_record_is_rejected():
    """Named mutation: declare the two states instead of reading them.

    This is the campaign's own defect class in its most ordinary form -- a value recorded
    as an observation while the code that computed it was a constant -- and it is the
    first thing a future edit would do to make this leg look recorded.
    """
    text = _spec_text()
    # (field, recorded-as, reverted-to). Each is a distinct field so the literal guard is
    # aimed at the value that was actually faked, rather than at one of the three.
    for field, recorded_as, reverted_to in (
        ("stateAfterStop", "observedStateAfterStop", "'stopped'"),
        ("stateAfterStart", "observedStateAfterStart", "'running'"),
        (
            "stopThenStartObserved",
            "observedStateAfterStop === 'stopped' && observedStateAfterStart === 'running'",
            "true",
        ),
    ):
        old_line = f"{field}: {recorded_as},"
        assert old_line in text, f"cannot build the revert for {old_line!r}"
        reverted = text.replace(old_line, f"{field}: {reverted_to},", 1)
        assert reverted != text, f"the revert for {field} did not apply"
        with pytest.raises(AssertionError):
            _guard_recorded_field_is_not_a_literal(reverted, field)

    # The live-read guards must fail against a text whose reads were removed.
    stripped = text.replace("observedStateAfterStop = ledger(a).state", "observedStateAfterStop = 'stopped'")
    assert "observedStateAfterStop = ledger(a).state" in text
    assert "observedStateAfterStop = ledger(a).state" not in stripped


# ── The recorded object must actually REACH the artifact ─────────────────────
#
# `observedEndedSessionReconnect` is assigned WHOLE into the artifact literal
# (`endedSessionReconnect: observedEndedSessionReconnect`), so the nested
# `workspaceRestart` recorded inside it is serialised. That is a property of how the
# artifact is written, not of how it is constructed, and it can be lost quietly: a
# refactor to `endedSessionReconnect: { prepareStatus, sameCapsuleTarget }` would keep
# every field this file checks and DROP the restart record, and the leg would vanish
# from the artifact with nothing failing -- a measurement that stops being recorded
# while the suite stays green, which is the shape this whole file exists to catch.

def _artifact_write_block(text: str) -> str:
    """The source region of the application-workspace-journey.json write."""
    anchor = "writeFileSync(path.join(ARTIFACT_ROOT, 'application-workspace-journey.json')"
    assert anchor in text, "the artifact writer moved; this guard must be re-derived"
    start = text.index(anchor)
    depth = 0
    opened = False
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
            opened = True
        elif text[index] == "}":
            depth -= 1
        # The termination test must wait until the literal has actually OPENED. My first
        # version tested `depth <= 0` from the anchor itself, where the next character is
        # 'r' of "path", so it returned a one-character block and the guard failed for a
        # reason that had nothing to do with the code under test.
        if opened and depth <= 0:
            return text[start:index]
    raise AssertionError("unterminated artifact write block")


def test_the_reconnect_object_is_written_whole_so_the_restart_record_survives():
    text = _spec_text()
    block = _artifact_write_block(text)
    assert "endedSessionReconnect: observedEndedSessionReconnect" in block, (
        "the reconnect object must be assigned WHOLE into the artifact literal; a destructured "
        "or rebuilt subset would drop the workspaceRestart record without any test failing"
    )
    # And it must not have grown a second, narrower assignment alongside the whole one,
    # which is how a subset sneaks in without the whole-object form being removed.
    assert block.count("endedSessionReconnect:") == 1, (
        "there is more than one endedSessionReconnect assignment in the artifact literal"
    )


def test_the_workspace_restart_fields_live_inside_the_object_that_is_written():
    """The recorded fields must be on the object, not on a local that is discarded."""
    text = _spec_text()
    declaration = text.index("const observedEndedSessionReconnect = {")
    # The restart record must be inside that literal, before it closes.
    rest = text.index("workspaceRestart: {", declaration)
    after = text[rest:]
    # A crude but sufficient bound: the object literal ends well before the artifact
    # writer, and the restart record must not have been moved past it.
    assert rest < text.index("writeFileSync(path.join(ARTIFACT_ROOT, 'application-workspace-journey.json')")
    for field in (
        "stateAfterStop: observedStateAfterStop,",
        "stateAfterStart: observedStateAfterStart,",
        "stopThenStartObserved:",
        "productDefinition: 'stop() then start() (WorkspaceRuntime.restart)',",
        "capsuleTargetPreserved:",
    ):
        assert field in after, f"{field!r} must be inside the written object"
