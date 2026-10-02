"""A pending approval is silently dropped when the repository's cleanliness changes.

`pending_approval_sources` compares `project_identity()` against the identity stored
in the plan and, on mismatch, executes a bare `continue`. The plan therefore
disappears from the approvals projection with no record of why.

The existing coverage cannot see this, and the reason is structural rather than an
oversight that a second reading would catch:

- `scripts/test_infrastructure.py` exercises the real round trip, but with a
  `FakeRunner` whose `dirty_status` is always empty, so `project_identity()` is
  constant and the equality holds trivially;
- `scripts/test_approvals_projection.py` stubs the method outright.

So the plan branch has never been read against a repository whose cleanliness
changed between planning and reading.

WHAT THIS TEST ASSERTS, AND WHY THIS AND NOT THE OTHER
------------------------------------------------------
The recorded next action offered two assertions and required stating which one is
claimed and why:

1. *the approval is still actionable*, or
2. *the drop is reported rather than silent*.

**This asserts (2), and the choice is settled by the module's own vocabulary rather
than by taste.** The identical condition is raised loudly elsewhere in the same file
as `InfrastructureError("plan_stale", "the repository identity changed; prepare a new
plan")` — at the approve path and again at the apply path. So the codebase already
classifies an identity mismatch as `plan_stale`, and the projection call site is the
one place that swallows an error its own siblings raise.

Asserting (1) would be a **security decision**, not a measurement: the binding exists
to stop commands running against content that changed after planning, and relaxing it
is not this test's to do. Asserting a *raise* is also wrong, for a different reason:
`pending_approval_sources` is a list projection, so one stale plan must not break the
whole view. The defect is the silence, so the fix is a report, and the test pins the
report.

THE ONE NAME THIS TEST ASSUMES
-------------------------------
The repair has to expose dropped plans somewhere. This test reads
`pending_approval_drop_reasons()`, a mapping of plan digest to the reason the file
already uses (`plan_stale` and its message). That accessor does not exist yet, so
**this test fails today**, which is the point. If the repair names the surface
differently, this is a one-line change here and the assertions below stand unchanged —
that is deliberate, so the decision about naming does not hide inside the evidence.

TEETH
-----
The control and the mutation differ in exactly one thing — whether the working tree's
cleanliness changed between planning and reading — so a run of this test that never
changes cleanliness would pass without ever exercising the defect. Asserting both
directions is what makes it non-vacuous.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
import sys

import pytest

# The sibling packages must be on sys.path BEFORE the application module is imported, and the
# list mirrors scripts/test_infrastructure.py deliberately. This file used to add only
# persistent-app/src, and because `governed_runner.lease` is an OPTIONAL import inside
# infrastructure.py, whichever test file imported first won: this one left InstanceLease
# bound to None, the module was cached that way for the whole pytest session, and eight
# unrelated tests in test_infrastructure.py then failed with "the instance lease contract
# is unavailable". It passed alone and passed in reverse order, which is exactly why it
# nearly shipped. A shared helper would be tidier than this duplicated list, but rewriting
# the existing convention mid-slice is a larger change than this defect warrants.
_ROOT = Path(__file__).resolve().parents[1]
for _relative in (
    "packages/persistent-app/src",
    "packages/governed-runner/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
):
    _entry = str(_ROOT / _relative)
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

from stateport_persistent_app.infrastructure import (  # noqa: E402
    InfrastructureError,
    LocalLibvirtAdapter,
)


class RealGitRunner:
    """A runner that really executes git, so `project_identity()` is really read.

    The existing suite's `FakeRunner` returns a constant empty `status`, which is
    precisely why the plan branch has never been exercised against a real
    repository whose cleanliness changes.
    """

    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, command: tuple[str, ...], **kwargs: object):
        self.commands.append(tuple(command))
        # The adapter passes `cwd` to the runner, defaulting to the repository root.
        # Discarding it is not a cosmetic omission: git then runs wherever pytest
        # happens to be, and `project_identity()` silently reports a DIFFERENT
        # repository. That mistake was made and caught while writing this test.
        cwd = kwargs.get("cwd")
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(cwd) if cwd else None,
            )
        except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
            return subprocess.CompletedProcess(command, 127, "", str(exc))


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


def _real_repository(tmp_path: Path) -> Path:
    """A REAL git repository, in the shape the adapter requires.

    The name and the two files are the adapter's own preconditions, taken from the
    existing suite's fixture: it only supports the `nixos-homelab` project, and a
    plan needs a flake and a Makefile target to build against.
    """
    repo = tmp_path / "nixos-homelab"
    repo.mkdir()
    (repo / "flake.nix").write_text('{ description = "real repository fixture"; }\n', encoding="utf-8")
    (repo / "Makefile").write_text("vm-persistent-create:\n\ttrue\n", encoding="utf-8")
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    # A local origin: the identity deliberately discards file:// and path remotes,
    # so the stored binding is branch, commit, tree, dirty and dirtyDigest -- which
    # is exactly the pair that changes when the working tree is cleaned.
    _git(repo, "init", "--bare", str(tmp_path / "origin.git"))
    _git(repo, "remote", "add", "origin", str(tmp_path / "origin.git"))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "initial")
    return repo


def _adapter(repo: Path, tmp_path: Path) -> LocalLibvirtAdapter:
    return LocalLibvirtAdapter(
        repo,
        instance_id="nixos.instance",
        state_root=tmp_path / "state",
        runner=RealGitRunner(),
    )


def _plan_needing_approval(adapter: LocalLibvirtAdapter) -> dict:
    plan = adapter.plan("create_or_update")
    assert plan["approvalRequired"] is True
    return plan



def _drop_reasons(adapter) -> list[str]:
    """Read the shipped drop-reporting surface.

    The first version of this test assumed an accessor named
    `pending_approval_drop_reasons()`. That name was never implemented: the repair
    that landed exposes the drops as `adapter.last_skipped_plans`, a list of
    {"planDigest", "reason", "detail"}. Asserting a name I had merely wished for would
    have made this test fail for a reason that has nothing to do with the behaviour, so
    it reads the surface that actually ships and names both.
    """
    return [(entry["planDigest"], entry["reason"]) for entry in getattr(adapter, "last_skipped_plans", [])]


def test_an_unchanged_repository_keeps_its_pending_approval_the_control(tmp_path: Path) -> None:
    """The control: nothing changed, so the approval must remain actionable.

    Without this, the mutation test below could pass for the wrong reason — a plan
    that is never actionable at all would satisfy "it was dropped".
    """
    repo = _real_repository(tmp_path)
    adapter = _adapter(repo, tmp_path)

    # Plan while DIRTY, then read while still dirty in exactly the same way: same
    # content, so porcelain v2 is byte-identical and dirtyDigest still matches.
    (repo / "scratch.txt").write_text("in flight\n", encoding="utf-8")
    plan = _plan_needing_approval(adapter)
    assert plan["repository"]["dirty"] is True

    digests = {entry["plan"]["planDigest"] for entry in adapter.pending_approval_sources()}
    assert plan["planDigest"] in digests, (
        "an approval whose repository binding is unchanged must remain actionable; "
        "if this fails the drop is not caused by the identity comparison"
    )


def test_a_cleaned_repository_drops_the_approval_and_REPORTS_it(tmp_path: Path) -> None:
    """A cleaned repository drops the approval AND says so.

    The drop is deliberate and stays: the binding exists so commands cannot run against
    content that changed after planning. What this pins is that the drop is not SILENT.
    """
    repo = _real_repository(tmp_path)
    adapter = _adapter(repo, tmp_path)

    (repo / "scratch.txt").write_text("in flight\n", encoding="utf-8")
    plan = _plan_needing_approval(adapter)          # planned while DIRTY
    assert plan["repository"]["dirty"] is True
    (repo / "scratch.txt").unlink()                 # now clean: dirty True -> False
    assert _git(repo, "status", "--porcelain=v2") == ""

    surfaced = {entry["plan"]["planDigest"] for entry in adapter.pending_approval_sources()}
    assert plan["planDigest"] not in surfaced, (
        "an approval must not stay actionable after its repository binding changed; "
        "if this fails the identity binding has been weakened"
    )

    reasons = _drop_reasons(adapter)
    assert (plan["planDigest"], "repository-identity-changed") in reasons, (
        "a plan dropped for a changed repository identity must be reported, not "
        "silently omitted: today pending_approval_sources() continues past it with "
        "no record, so a user sees the approval simply disappear"
    )


def test_a_dirtied_repository_drops_the_approval_and_REPORTS_it(tmp_path: Path) -> None:
    """The mutation in the other direction: clean at planning, dirty at reading.

    A single direction would still be satisfied by a rule that always drops, so both
    are asserted and the pair is what gives the test teeth.
    """
    repo = _real_repository(tmp_path)
    adapter = _adapter(repo, tmp_path)
    plan = _plan_needing_approval(adapter)

    (repo / "scratch.txt").write_text("changed after planning\n", encoding="utf-8")

    surfaced = {entry["plan"]["planDigest"] for entry in adapter.pending_approval_sources()}
    assert plan["planDigest"] not in surfaced

    reasons = _drop_reasons(adapter)
    assert (plan["planDigest"], "repository-identity-changed") in reasons, (
        "a plan dropped for a changed repository identity must be reported, not "
        "silently omitted: without a record the user sees the approval simply vanish"
    )


def test_the_reporting_surface_exists_under_the_name_that_shipped(tmp_path: Path) -> None:
    """Pin the name, so a future rename fails here instead of silently weakening the test.

    The first draft asserted the ABSENCE of an accessor I had invented,
    `pending_approval_drop_reasons()`. The repair that landed never used that name: it
    records each drop on `adapter.last_skipped_plans` as (planDigest, reason, detail).
    A test that pins an invented name fails for a reason unrelated to behaviour, and a
    test that pins nothing can be quietly rewritten into meaninglessness. This pins the
    shipped name and keeps the history visible, so the next reader sees why it is
    spelled this way instead of assuming a typo.
    """
    repo = _real_repository(tmp_path)
    adapter = _adapter(repo, tmp_path)
    (repo / "scratch.txt").write_text("in flight\n", encoding="utf-8")
    _plan_needing_approval(adapter)
    (repo / "scratch.txt").unlink()
    adapter.pending_approval_sources()
    assert hasattr(adapter, "last_skipped_plans"), (
        "the drop-reporting surface is gone: the other tests in this file read "
        "adapter.last_skipped_plans, and a silent rename would leave them asserting "
        "against an attribute that no longer exists"
    )
