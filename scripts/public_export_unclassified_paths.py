#!/usr/bin/env python3
"""Report tracked paths the public-export allowlist does not classify yet.

WHY THIS EXISTS, and why it is a reporter and not a guard
---------------------------------------------------------
`test_repository_policy_exactly_classifies_the_current_source_and_future_paths_block`
compares the allowlist against the LIVE git index, so it is a canary: it fires
whenever any lane adds a tracked path. That is correct behaviour, because the
policy's own default rule (`future-file-not-reviewed` / `unresolved-blocking`)
exists precisely to refuse export until a path has been reviewed. But a canary
that only says "these N paths are wrong" leaves the reviewer to rediscover, every
time, which rule each path belongs to -- and in practice that produced five
successive rounds of hand-rolled appends, each one a chance to widen the published
surface by accident.

So this tool answers the question the canary provokes, and changes nothing:

    python3 scripts/public_export_unclassified_paths.py            # report, exit 0
    python3 scripts/public_export_unclassified_paths.py --check    # report, exit 1
    python3 scripts/public_export_unclassified_paths.py --emit     # paste-ready YAML
    python3 scripts/public_export_unclassified_paths.py --deps     # report broken published->private deps

It is deliberately NOT a pre-commit hook. Refusing a commit would convert a correct
late signal into an early block across every active lane in a shared tree, and the
cost of that interference is higher than the cost of the reporter. The canary test
stays exactly as it is; this only makes its output actionable.

HOW A SUGGESTION IS DERIVED, because a suggestion that is a guess is worse than none
------------------------------------------------------------------------------------
Every suggestion is derived from the repository's own policy and its own detectors,
never from a hardcoded path list:

  1. The dominant classification among already-classified siblings in the SAME
     directory. This is the primary signal and it is what the campaign's own
     evidence files, scripts and configs have consistently matched.
  2. Failing that, the dominant classification among paths sharing the top-level
     directory.
  3. The private-local-path detector from `public_snapshot_audit` is applied to the
     file's real content. It is an OBJECTIVE tie-breaker derived from the
     `excluded-unscannable-or-sensitive-fixtures` rule's own stated criterion, and
     it is strictly one-directional: a file that trips it cannot be
     `public-source`, because every clean public-source sibling is detector-clean.
     A clean result is NOT evidence of publishability, so it never promotes a path
     on its own -- it only ever demotes.

A suggestion is a suggestion. `--check` exists so a lane may opt into treating this
as a gate in its own workflow; nothing in this repository wires it into a hook.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "public-export-allowlist.v1.yaml"

if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))


@dataclass(frozen=True)
class Suggestion:
    path: str
    rule: str
    classification: str
    basis: str
    detector: bool | None
    ambiguous_with: tuple[str, ...]


def _git(*args: str) -> list[str]:
    return subprocess.run(
        ("git", *args), cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()


def _load_policy():
    from export_public_candidate import load_policy

    return load_policy(POLICY.read_bytes())


def _detector() -> "callable | None":
    try:
        from public_snapshot_audit import _has_private_local_path
    except Exception:  # pragma: no cover - the detector is optional at runtime
        return None
    return _has_private_local_path


def _dominant(counts: Counter[str]) -> tuple[str | None, tuple[str, ...]]:
    """The most common classification, plus every class tied with it."""
    if not counts:
        return None, ()
    best = max(counts.values())
    tied = tuple(sorted(name for name, total in counts.items() if total == best))
    return tied[0], tied[1:] if len(tied) > 1 else ()


def _demote(
    rule: str | None,
    trips: bool | None,
    excluded_ids: list[str],
    basis: str,
    is_public: bool = True,
) -> tuple[str | None, str]:
    """Apply the detector's demotion, but ONLY where it can change the outcome.

    Split out as a pure function so the decision is testable without inventing a
    file on disk.

    The direction is one-directional: a file that trips the private-local-path
    detector cannot be public-source. But the demotion must be gated on the
    suggestion actually being PUBLIC, and that gate is not cosmetic. Measured on
    this repository's own corpus, 247 of the 514 evidence files already in
    `private-operating-and-unverified-assets` trip the detector, and the
    `excluded` rule contains ZERO evidence paths. An ungated demotion therefore
    would have placed the first evidence file ever in `excluded`, against 247
    direct siblings, on the strength of a detector that every one of them also
    trips. For a path that is already suggested non-public the detector carries
    no information, so it is not applied.

    This is the campaign's own recurring failure mode in one function: a rule
    that looks more careful and quietly contradicts the established convention.
    """
    if not trips or rule is None or not excluded_ids:
        return rule, basis
    if not is_public or rule.startswith("excluded"):
        return rule, basis
    return excluded_ids[0], (
        basis
        + "; demoted to excluded because the private-local-path detector fires on "
        "this file, and every clean public-source sibling is clean"
    )


def suggest(
    unclassified: Iterable[str],
    classified: dict[str, str],
    rule_classification: dict[str, str],
    detector,
) -> list[Suggestion]:
    """Suggest a rule id per unclassified path.

    `classified` maps an already-classified path to its rule IDENTIFIER, so the
    sibling counters below count identifiers, which is what we want to suggest:
    the id is what the policy file's `rules[].id` key actually needs. The
    classification is then looked up from that id for display, never the reverse.
    Comparing an identifier against a classification is the bug this comment
    exists to prevent, because it silently yields "(none)" for every path.
    """
    excluded_ids = sorted(
        name for name, classification in rule_classification.items()
        if classification == "excluded"
    )
    _public = {
        classification
        for classification in rule_classification.values()
        if classification
        in {"public-source", "public-documentation", "public-generated", "third-party-reviewed"}
    }
    out: list[Suggestion] = []
    for path in unclassified:
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        top = path.split("/", 1)[0]

        sibling = Counter(
            identifier
            for other, identifier in classified.items()
            if (other.rsplit("/", 1)[0] if "/" in other else "") == parent
        )
        basis = f"dominant rule among {sum(sibling.values())} classified siblings in {parent or 'the repository root'}"
        rule, tied = _dominant(sibling)

        if rule is None:
            top_counts = Counter(
                identifier
                for other, identifier in classified.items()
                if other.split("/", 1)[0] == top
            )
            basis = f"dominant rule among {sum(top_counts.values())} classified paths under {top}"
            rule, tied = _dominant(top_counts)

        if rule is None:
            rule, basis = None, "no classified sibling exists; this is an owner judgement"

        trips: bool | None = None
        absolute = ROOT / path
        if detector is not None and absolute.is_file():
            try:
                trips = bool(detector(absolute.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError):
                trips = None
        # The demotion only applies when the sibling-derived suggestion is
        # PUBLIC: for an already-private path the detector adds no information,
        # and applying it anyway would contradict 247 existing evidence siblings.
        is_public = rule_classification.get(rule, "") in _public
        rule, basis = _demote(rule, trips, excluded_ids, basis, is_public=is_public)

        out.append(
            Suggestion(
                path=path,
                rule=rule or "(none: no classified sibling to match)",
                classification=rule_classification.get(rule, "(undecided)"),
                basis=basis,
                detector=trips,
                ambiguous_with=tied,
            )
        )
    return out


def report() -> tuple[list[Suggestion], int, int]:
    policy = _load_policy()
    classified = {path: rule.identifier for rule in policy.rules for path in rule.paths}
    rule_classification = {rule.identifier: rule.classification for rule in policy.rules}
    tracked = set(_git("ls-files", "--cached"))
    missing = sorted(tracked - set(classified))
    stale = sorted(set(classified) - tracked)
    return suggest(missing, classified, rule_classification, _detector()), len(missing), len(stale)


def _stale_paths() -> list[str]:
    """Allowlist entries whose path is no longer tracked.

    Split out because the count is what the summary line needs and the LIST is
    what the detail needs, and an earlier revision returned the count and then
    iterated it, so the tool crashed with TypeError precisely when it had
    something to report. A check that only works when there is nothing to say
    is the same defect class this campaign keeps finding.
    """
    policy = _load_policy()
    tracked = set(_git("ls-files", "--cached"))
    return sorted({path for rule in policy.rules for path in rule.paths} - tracked)


COPYABLE = {"public-source", "public-documentation", "public-generated", "third-party-reviewed"}
_PRIVATE = "private-internal"


def report_dependency_defects() -> list[tuple[str, str, int, str]]:
    """Published files that reference a path classified private-internal.

    The classification canary only proves every tracked path is *classified*
    (missing == 0). It cannot see that a published test loads a private module, which
    makes the published tree unrunnable. This was a real defect once already: three tests
    were published whose subject-under-test or fixtures were private-internal, and the
    canary stayed green because it never looked.

    Only LOAD-TIME references count. A name mentioned in a docstring, comment or log
    string is not a dependency, and counting those produced a 51-item false positive
    against the real count, so this deliberately under-reports: it looks for the repo path
    appearing in an import/load context, not merely anywhere in the file.

    This is a REPORT, not a gate. It does not exit non-zero on its own and nothing wires
    it in, for the same reason `--check` is opt-in: a suggestion is a suggestion, and
    promoting this to blocking is a decision about release policy, not a repair.

    KNOWN LIMITATIONS - the count is a FLOOR, not a total:
      * module-style imports are matched by top-level module NAME only, so
        `from pkg.mod import x` is not resolved to a nested private file, and a
        module whose name differs from its filename would be missed.
      * it only reads files that are themselves classified copyable, so a dependency
        reached only from a private file is out of scope by construction.
      * it does not resolve conditionals, so a load behind a platform check is reported
        the same as an unconditional one.
    It is tuned to under-report rather than over-report, because the earlier crude
    scan that counted every textual mention produced 51 findings against a real count
    far below that, and a noisy instrument is worse than an incomplete one.
    """
    policy = _load_policy()
    rules = list(policy.rules)
    # policy.rules yields Rule objects, not dicts: identifier / classification / paths.
    private: set[str] = {
        path
        for rule in rules
        if rule.classification == _PRIVATE
        for path in rule.paths
    }
    # Import statements name a MODULE, not a path. "from projectstate_gate import
    # validate" carries no "scripts/" prefix, so path matching alone cannot see it.
    # Map each private path to the module names it could be imported as.
    private_modules: dict[str, str] = {}
    for dep in private:
        if not dep.endswith(".py"):
            continue
        stem = dep[: -len(".py")].rsplit("/", 1)[-1]
        if stem == "__init__":
            stem = dep[: -len("/__init__.py")].rsplit("/", 1)[-1]
        private_modules.setdefault(stem, dep)
        dotted = stem.replace("_", "-")
        if dotted != stem:
            private_modules.setdefault(dotted, dep)
    published = {
        path
        for rule in rules
        if rule.classification in COPYABLE
        for path in rule.paths
    }

    defects: list[tuple[str, str, int, str]] = []
    unreadable: list[tuple[str, str]] = []
    for src in sorted(published):
        if not src.endswith((".py", ".sh")):
            continue
        try:
            text = Path(src).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # A file we cannot read is NOT evidence of a clean result. Skipping it
            # silently makes the finding count smaller for no visible reason, which is
            # the same shape as a no-op instrument: the number looks authoritative and is
            # quietly wrong. Collect it and report it instead.
            unreadable.append((src, exc.__class__.__name__))
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            # LOAD-TIME contexts only: an import statement, a path built for open()/read,
            # or a literal path argument. A bare mention in prose is skipped.
            is_load = (
                stripped.startswith(("import ", "from "))
                or "read_text(" in stripped
                or "open(" in stripped
                or "Path(" in stripped
                or "SCRIPT" in stripped or "ROOT /" in stripped
            )
            if not is_load or stripped.startswith("#"):
                continue
            for dep in private:
                if dep == src:
                    continue
                if dep in stripped or f'"{dep}"' in stripped:
                    defects.append((src, dep, lineno, "path"))
                    break
            else:
                # module-style import of a private file
                if stripped.startswith("import ") or stripped.startswith("from "):
                    token = stripped.split()[1].split(".")[0]
                    hit = private_modules.get(token)
                    if hit and hit != src:
                        defects.append((src, hit, lineno, f"import:{token}"))
    return defects, unreadable


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 when a tracked path is unclassified (opt-in; nothing wires this in)",
    )
    parser.add_argument(
        "--emit",
        action="store_true",
        help="print paste-ready YAML lines for the suggested rule, without editing anything",
    )
    parser.add_argument(
        "--deps",
        action="store_true",
        help="report published files that reference a private-internal path at load time",
    )
    args = parser.parse_args(argv)


    if args.deps:
        defects, unreadable = report_dependency_defects()
        if unreadable:
            print(
                f"WARNING: {len(unreadable)} published file(s) could not be read; the "
                f"finding count below EXCLUDES them and is a floor by at least that much:"
            )
            for path, why in unreadable[:10]:
                print(f"  unreadable: {path} ({why})")
        if not defects:
            print("published->private load-time dependencies: none found")
            return 0
        print(f"published->private load-time dependencies: {len(defects)} finding(s)")
        for src, dep, lineno, how in defects:
            print(f"  {src}:{lineno} loads {dep}  [{how}]")
        print(
            "\nThis is a report, not a gate. Promoting it to blocking, and deciding whether"
            "\n each finding is fixed by reclassifying the source or by publishing the"
            "\n dependency, are release-policy decisions."
        )
        return 0

    suggestions, missing, stale_count = report()
    stale = _stale_paths()

    print(
        f"public-export allowlist: {missing} unclassified, {len(stale)} stale tracked path(s). "
        "Unclassified paths fall to the default rule "
        "'future-file-not-reviewed' / 'unresolved-blocking', which blocks public export "
        "by design. This is a report, not a gate: the canary test "
        "test_repository_policy_exactly_classifies_the_current_source_and_future_paths_block "
        "remains the authority."
    )
    # A zero in the headline above is NOT a pass, and it was read as one. Independent
    # verification caught a live instance of exactly that: the reporter printed
    # "0 unclassified" while the canary was failing with `AssertionError: 14 != 0`,
    # and the passing verdict was recorded. 26 recurrence commits later, the reader
    # cannot tell from this line whether the class is closed, so say it explicitly.
    print(
        "HEADLINE IS NOT A VERDICT: the count above describes the allowlist file only. "
        "It does NOT show that the class is closed. Run the authority and read ITS exit "
        "status before recording any closure claim:"
    )
    print(
        "  python3 -m pytest scripts/test_public_export_unclassified_paths.py -q"
    )
    print(
        "Only a PASS there means the tree is fully classified. A green headline with a "
        "failing canary means the opposite of 'closed'."
    )
    for item in suggestions:
        flag = " detector=private-path" if item.detector else ""
        print(f"\n  {item.path}")
        print(f"    suggest rule : {item.rule}  [{item.classification}]{flag}")
        print(f"    because      : {item.basis}")
        if item.ambiguous_with:
            print(
                "    AMBIGUOUS    : tied with "
                + ", ".join(item.ambiguous_with)
                + " -- an owner judgement, not a mechanical classification"
            )
        if args.emit and not item.rule.startswith("(none"):
            print(f"    emit         :   - {item.path}")
    if stale:
        print("\n  stale paths (listed but no longer tracked):")
        for path in stale:
            print(f"    {path}")

    if not missing:
        print("\n  nothing to classify.")
    return 1 if (args.check and missing) else 0


if __name__ == "__main__":
    raise SystemExit(main())
