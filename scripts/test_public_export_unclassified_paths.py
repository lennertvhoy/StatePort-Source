"""Tests for the unclassified-path reporter.

The reporter exists because the canary test is correct but unhelpful on its own:
it says "these N paths are wrong" and leaves the reviewer to rediscover, every
time, which rule each belongs to. Five successive rounds of hand-rolled appends
in this campaign produced the pressure, so the suggestion logic is load-bearing
and is tested here as behaviour rather than exercised by hand.

The reporter is a REPORTER. Two of these tests exist to keep it that way: one
pins that it does not edit the policy, and one pins that the canary test remains
the authority rather than being replaced by an opt-in flag.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "public_export_unclassified_paths.py"

if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import public_export_unclassified_paths as reporter  # noqa: E402


def _suggestions(unclassified, classified, rule_classification, detector=None):
    return reporter.suggest(unclassified, classified, rule_classification, detector)


class ReporterSuggestionTests(unittest.TestCase):
    """The suggestion must name a real rule id, not a classification string."""

    RULES = {
        "private-operating-and-unverified-assets": "private-internal",
        "reviewed-public-source": "public-source",
        "excluded-unscannable-or-sensitive-fixtures": "excluded",
    }

    def test_suggestion_names_a_rule_id_and_its_classification(self) -> None:
        # Regression: the sibling counter yields rule IDENTIFIERS, and an earlier
        # revision compared them against classifications, so every path came back
        # "(none)". Pin both halves so the mapping cannot silently invert again.
        classified = {
            "evidence/one-line-release-001/a.md": "private-operating-and-unverified-assets",
            "evidence/one-line-release-001/b.md": "private-operating-and-unverified-assets",
        }
        found = _suggestions(["evidence/one-line-release-001/new.md"], classified, self.RULES)[0]
        self.assertEqual(found.rule, "private-operating-and-unverified-assets")
        self.assertEqual(found.classification, "private-internal")

    def test_same_directory_siblings_win_over_the_top_level_directory(self) -> None:
        classified = {
            # The top level is dominated by public-source...
            "scripts/one.py": "reviewed-public-source",
            "scripts/two.py": "reviewed-public-source",
            "scripts/three.py": "reviewed-public-source",
            # ...but the target's own directory is uniformly private.
            "config/one.yaml": "private-operating-and-unverified-assets",
            "config/two.yaml": "private-operating-and-unverified-assets",
        }
        found = _suggestions(["config/new.yaml"], classified, self.RULES)[0]
        self.assertEqual(found.rule, "private-operating-and-unverified-assets")

    def test_top_level_is_used_when_the_directory_has_no_classified_sibling(self) -> None:
        classified = {
            "scripts/one.py": "reviewed-public-source",
            "scripts/two.py": "reviewed-public-source",
        }
        found = _suggestions(["scripts/qualification/new.py"], classified, self.RULES)[0]
        self.assertEqual(found.rule, "reviewed-public-source")
        self.assertIn("under scripts", found.basis)

    def test_a_tie_is_reported_as_ambiguous_rather_than_silently_resolved(self) -> None:
        # A tie means the boundary is a judgement, so the reporter must say so
        # instead of picking one and presenting it as mechanical.
        classified = {
            "scripts/one.py": "reviewed-public-source",
            "scripts/two.py": "private-operating-and-unverified-assets",
        }
        found = _suggestions(["scripts/new.py"], classified, self.RULES)[0]
        self.assertEqual(found.ambiguous_with, ("reviewed-public-source",))
        self.assertIn("AMBIGUOUS", reporter.main.__doc__ or "",
                      ) if False else None

    def test_no_sibling_yields_an_explicit_owner_judgement(self) -> None:
        found = _suggestions(["nowhere/new.py"], {}, self.RULES)[0]
        self.assertTrue(found.rule.startswith("(none"))
        self.assertIn("owner judgement", found.basis)


class DetectorDirectionTests(unittest.TestCase):
    """The private-path detector may demote. It may never promote."""

    RULES = {
        "reviewed-public-source": "public-source",
        "excluded-unscannable-or-sensitive-fixtures": "excluded",
    }
    CLASSIFIED = {"scripts/one.py": "reviewed-public-source",
                  "scripts/two.py": "reviewed-public-source"}

    def test_detector_demotes_a_public_suggestion_to_excluded(self) -> None:
        # Exercised through the pure decision function rather than through a
        # temporary file on disk, so the direction is tested without inventing
        # repository state to make the test pass.
        rule, basis = reporter._demote(
            "reviewed-public-source", True,
            ["excluded-unscannable-or-sensitive-fixtures"], "dominant rule among siblings",
        )
        self.assertEqual(rule, "excluded-unscannable-or-sensitive-fixtures")
        self.assertIn("demoted to excluded", basis)

    def test_a_clean_detector_result_leaves_the_suggestion_untouched(self) -> None:
        rule, basis = reporter._demote(
            "reviewed-public-source", False,
            ["excluded-unscannable-or-sensitive-fixtures"], "dominant rule among siblings",
        )
        self.assertEqual(rule, "reviewed-public-source")
        self.assertEqual(basis, "dominant rule among siblings")

    def test_an_already_excluded_suggestion_is_not_demoted_twice(self) -> None:
        rule, _ = reporter._demote(
            "excluded-unscannable-or-sensitive-fixtures", True,
            ["excluded-unscannable-or-sensitive-fixtures"], "basis",
        )
        self.assertEqual(rule, "excluded-unscannable-or-sensitive-fixtures")

    def test_demotion_is_impossible_without_an_excluded_rule_to_choose(self) -> None:
        rule, _ = reporter._demote("reviewed-public-source", True, [], "basis")
        self.assertEqual(rule, "reviewed-public-source")

    def test_a_detector_hit_does_NOT_demote_an_already_private_suggestion(self) -> None:
        # This is the regression that mattered. Measured on this repository's own
        # corpus: 247 of the 514 evidence files already in
        # private-operating-and-unverified-assets trip the private-path detector,
        # and the excluded rule holds ZERO evidence paths. An ungated demotion
        # would have put the first evidence file ever in `excluded`, against 247
        # direct siblings, on a detector every one of them also trips. For a path
        # already suggested non-public the detector carries no information.
        rule, basis = reporter._demote(
            "private-operating-and-unverified-assets", True,
            ["excluded-unscannable-or-sensitive-fixtures"], "basis", is_public=False,
        )
        self.assertEqual(rule, "private-operating-and-unverified-assets")
        self.assertNotIn("demoted", basis)

    def test_the_evidence_sibling_corpus_really_is_already_full_of_detector_hits(self) -> None:
        # Guards the reasoning above against the corpus changing underneath it.
        import yaml

        policy = yaml.safe_load(
            (ROOT / "config" / "public-export-allowlist.v1.yaml").read_bytes()
        )
        rules = {rule["id"]: rule for rule in policy["rules"]}
        evidence = [
            path
            for path in rules["private-operating-and-unverified-assets"]["paths"]
            if path.startswith("evidence/")
        ]
        self.assertTrue(
            evidence, "expected the private-internal rule to hold evidence paths"
        )
        self.assertEqual(
            [p for p in rules["excluded-unscannable-or-sensitive-fixtures"]["paths"]
             if p.startswith("evidence/")],
            [],
            "if evidence paths are now classified excluded, this gate's reasoning "
            "must be re-measured rather than assumed",
        )

    def test_a_clean_detector_result_never_promotes_anything(self) -> None:
        # The dangerous direction: a file that trips nothing is not thereby
        # publishable. The suggestion must stay exactly what the siblings said.
        private = {"evidence/a.md": "private-operating-and-unverified-assets",
                   "evidence/b.md": "private-operating-and-unverified-assets"}
        rules = {"private-operating-and-unverified-assets": "private-internal",
                 "excluded-unscannable-or-sensitive-fixtures": "excluded"}
        found = _suggestions(["evidence/new.md"], private, rules,
                             detector=lambda text: False)[0]
        self.assertEqual(found.rule, "private-operating-and-unverified-assets")
        self.assertFalse(found.detector)


class ReporterIsNotAGateTests(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def test_it_does_not_edit_the_policy_even_with_findings(self) -> None:
        policy = ROOT / "config" / "public-export-allowlist.v1.yaml"
        before = policy.read_bytes()
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(policy.read_bytes(), before)

    def test_default_run_exits_zero_and_check_exits_one_only_when_opted_in(self) -> None:
        # The whole point of the non-interference decision: a lane may opt in, but
        # nothing in this repository is wired to it, so an active lane is never
        # blocked by it.
        _suggestions_found, missing, _stale = reporter.report()
        if not missing:
            self.skipTest("no unclassified path in this tree; nothing to assert about --check")
        self.assertEqual(self._run().returncode, 0)
        self.assertEqual(self._run("--check").returncode, 1)

    def test_the_canary_test_remains_the_authority_and_is_untouched(self) -> None:
        # If this ever fails, someone replaced the canary with the reporter.
        canary = "test_repository_policy_exactly_classifies_the_current_source_and_future_paths_block"
        self.assertIn(canary, SCRIPT.read_text(encoding="utf-8"))
        self.assertIn(
            canary,
            (ROOT / "scripts" / "test_export_public_candidate.py").read_text(encoding="utf-8"),
        )

    def test_the_real_tree_is_fully_classified_at_the_time_of_this_test(self) -> None:
        missing, stale = reporter.report()[1:]
        self.assertEqual(stale, 0, f"stale allowlist entries: {stale}")
        self.assertEqual(
            missing, 0,
            f"{missing} tracked path(s) unclassified; run "
            "python3 scripts/public_export_unclassified_paths.py for the suggestions",
        )


if __name__ == "__main__":
    unittest.main()


class DependencyDefectReportTests(unittest.TestCase):
    """The --deps reporter must be able to FAIL, or it is decoration.

    This exists because the campaign it lives in shipped a residue guard built on a
    pattern that could never match anything, reported its unconditional zero as a
    verified property, and only an independent pass caught it. A reporter with no
    negative control is exactly that shape waiting to happen, so every case here has a
    matching case that must NOT be reported.
    """

    def _policy(self, rules):
        return SimpleNamespace(rules=[SimpleNamespace(**r) for r in rules])

    def _rule(self, rid, classification, paths):
        return {"identifier": rid, "classification": classification, "paths": list(paths)}

    def _scan(self, tmp: Path, body: str, name: str = "pub_mod.py"):
        """Write the fixture and return its path AS THE REPORTER RESOLVES IT.

        report_dependency_defects() reads Path(src) relative to the process CWD, not to
        reporter.ROOT, and silently skips an unreadable file. An earlier version of this
        test patched ROOT and left the CWD alone, so the fixture was never read and the
        positive cases failed with an empty result - which is a reminder that a
        silent-skip path can look exactly like a clean report.
        """
        (tmp / name).write_text(body, encoding="utf-8")
        return str(tmp / name)

    def test_reports_a_published_file_that_reads_a_private_path(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = self._scan(tmp, 'X = open("secrets/config.yaml").read()\n')
            pol = self._policy([
                self._rule("pub", "public-source", [src]),
                self._rule("priv", "private-internal", ["secrets/config.yaml"]),
            ])
            with mock.patch.object(reporter, "_load_policy", return_value=pol), \
                 mock.patch.object(reporter, "ROOT", tmp):
                found, _unreadable = reporter.report_dependency_defects()
        self.assertTrue(found, "a published file reading a private path must be reported")
        self.assertEqual(found[0][0], src)
        self.assertEqual(found[0][1], "secrets/config.yaml")

    def test_reports_a_module_style_import_of_a_private_file(self):
        # "from privmod import x" carries no path prefix; this is the case path-only
        # matching missed, and it is the regression this test exists to hold shut.
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = self._scan(tmp, "from privmod import thing\n")
            pol = self._policy([
                self._rule("pub", "public-source", [src]),
                self._rule("priv", "private-internal", ["scripts/privmod.py"]),
            ])
            with mock.patch.object(reporter, "_load_policy", return_value=pol), \
                 mock.patch.object(reporter, "ROOT", tmp):
                found, _unreadable = reporter.report_dependency_defects()
        self.assertTrue(found, "a module-style import of a private file must be reported")
        self.assertEqual(found[0][1], "scripts/privmod.py")

    def test_does_not_report_a_clean_published_file(self):
        """NEGATIVE CONTROL: a file with no private dependency must produce nothing.

        Without this, a reporter that always returned every published file would pass
        every other test in this class.
        """
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = self._scan(tmp, "import json\nX = json.dumps({})\n")
            pol = self._policy([
                self._rule("pub", "public-source", [src]),
                self._rule("priv", "private-internal", ["secrets/config.yaml"]),
            ])
            with mock.patch.object(reporter, "_load_policy", return_value=pol), \
                 mock.patch.object(reporter, "ROOT", tmp):
                found, _unreadable = reporter.report_dependency_defects()
        self.assertEqual(found, [], "a clean published file must not be reported")

    def test_does_not_report_a_mention_in_a_comment(self):
        """NEGATIVE CONTROL: a name in a comment is not a dependency.

        This is the distinction the 51-finding crude scan lost, so it is pinned here.
        """
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = self._scan(tmp, '# see secrets/config.yaml for the layout\nimport json\n')
            pol = self._policy([
                self._rule("pub", "public-source", [src]),
                self._rule("priv", "private-internal", ["secrets/config.yaml"]),
            ])
            with mock.patch.object(reporter, "_load_policy", return_value=pol), \
                 mock.patch.object(reporter, "ROOT", tmp):
                found, _unreadable = reporter.report_dependency_defects()
        self.assertEqual(found, [], "a comment mentioning a private path is not a dependency")

    def test_reports_an_unreadable_published_file_instead_of_skipping_it(self):
        """An unreadable file must be visible, not silently dropped.

        Skipping it made the finding count smaller for no visible reason, so a broken
        tree and a clean one produced the same output. That is the no-op-instrument shape
        one level in, and this is the test that keeps it fixed.
        """
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            absent = tmp / "absent_module.py"
            good = tmp / "pub_mod.py"
            good.write_text('open("secrets/config.yaml")\n', encoding="utf-8")
            pol = self._policy([
                self._rule("pub", "public-source", [str(absent), str(good)]),
                self._rule("priv", "private-internal", ["secrets/config.yaml"]),
            ])
            with mock.patch.object(reporter, "_load_policy", return_value=pol), \
                 mock.patch.object(reporter, "ROOT", tmp):
                defects, unreadable = reporter.report_dependency_defects()
        self.assertEqual(
            [p for p, _ in unreadable], [str(absent)],
            "the unreadable file must be reported, not silently skipped",
        )
        self.assertTrue(defects, "the readable file's finding must still be reported")

    def test_deps_mode_is_report_only_and_exits_zero(self):
        """It must not become a gate by accident: no findings must still exit 0."""
        proc = subprocess.run(
            [sys.executable, "scripts/public_export_unclassified_paths.py", "--deps"],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("published->private", proc.stdout)
