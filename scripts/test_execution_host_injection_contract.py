"""Text-level contract for the execution-host Containerfile's linker injection.

This test exists because a green build cannot observe an inert `-X`. Go's linker
ignores `-X` for a missing symbol SILENTLY: no warning, no error, and the build
still succeeds and still produces a working `podman-remote`. A build result is
therefore not evidence that an injected value reached the program.

Three measured reasons this defect class had to be made structurally
impossible to reintroduce (measured at the Group A v6 re-pin, commit
4b94ccce9f4474155b4bf3da1b8218230e898595, 2026-09-27; see
images/stateport-execution-host/Containerfile lines 10-36 and
evidence/one-line-release-001/groupa-ldflags-assertion-gap-20260926.md):

1. `libpod/config._installPrefix` and `libpod/config._etcDir` targeted a symbol
   that does not exist anywhere in the tree outside vendor/. The flags had been
   carried forward for years doing nothing, and every build stayed green.
2. `pkg/systemd/quadlet._binDir` IS declared
   (pkg/systemd/quadlet/podmancmdline.go:12), so a source-tree symbol search
   finds it, but its package is never LINKED into podman-remote: every importer
   in cmd/podman's graph is gated `//go:build !remote` while this build passes
   `-tags remote`. Source existence is not linking, and a module-path migration
   that merely re-paths the flag would carry it across the v6 bump inert.
3. Grepping the built binary for the injected strings is also forbidden, because
   the `-ldflags` text itself is embedded in the Go build info: such a grep
   passes even when `-X` did nothing. The only admissible observation routes
   the value through the program (`podman-remote version --format json`).

So this module asserts the injection contract by PARSING the Containerfile
text: no build, no network, no container runtime. Every invariant is its own
test function so a failure names the specific thing that broke, and the
assertions are deliberately over-specified (exact set, exact values, exact
module path) so that re-adding an inert flag, reverting to the v5 module path,
or abbreviating the commit is a test failure rather than a silent no-op.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shlex

import yaml


ROOT = Path(__file__).resolve().parents[1]

CONTAINERFILE = "images/stateport-execution-host/Containerfile"
LOCK = ROOT / "config/container-build-inputs.yaml"

# The exact Group A remediation pin this Containerfile is allowed to build.
PINNED_COMMIT = "4b94ccce9f4474155b4bf3da1b8218230e898595"
PINNED_VERSION = "6.2.0-dev"
PINNED_TARBALL_SHA256 = "d8829f954519de28563351cda90bb7b9795b935360419d20bf8308a57821c187"
# The repo's tarball filename convention abbreviates the commit to 8 hex chars.
# This abbreviation is allowed in the file NAME only, never in an -X value.
TARBALL_STEM = f"podman-{PINNED_COMMIT[:8]}"

MODULE = "go.podman.io/podman/v6"
LEGACY_MODULE = "github.com/containers/podman/v5"

GIT_COMMIT_SYMBOL = f"{MODULE}/libpod/define.gitCommit"
BUILD_INFO_SYMBOL = f"{MODULE}/libpod/define.buildInfo"

# libpod/define/version.go parses define.buildInfo as a Unix epoch; this is the
# pinned commit's committer time.
PINNED_BUILD_INFO = "1788082111"

# The ONLY two -X targets that are effective at this pin: package-level `var`s
# in libpod/define/version.go, measured present and consumed (GitCommit, Built,
# BuiltTime). The set is asserted exactly -- no more, no fewer.
EFFECTIVE_SYMBOLS = frozenset({GIT_COMMIT_SYMBOL, BUILD_INFO_SYMBOL})

# Historically injected, measured inert, must never be injected again.
INERT_SYMBOL_SUFFIXES = (
    "config._installPrefix",
    "config._etcDir",
    "quadlet._binDir",
)

_LDFLAGS = re.compile(r'-ldflags\s+"([^"]*)"')


# --------------------------------------------------------------------------
# parsing helpers (take text, so a mutation can be exercised without writing)
# --------------------------------------------------------------------------


def _ldflag_strings(text: str) -> list[str]:
    """Return every `-ldflags "..."` value, in order."""
    return _LDFLAGS.findall(text)


def _ldflag_tokens(text: str) -> list[str]:
    """Whitespace-independent tokenization of every -ldflags value."""
    tokens: list[str] = []
    for value in _ldflag_strings(text):
        tokens.extend(shlex.split(value))
    return tokens


def _injections(text: str) -> dict[str, str]:
    """Map every `-X <symbol>=<value>` pair to its value.

    Go's -ldflags is a space-separated flag/value list, so the two forms are
    both accepted: `-X sym=value` and the concatenated `-Xsym=value`.
    """
    found: dict[str, str] = {}
    tokens = _ldflag_tokens(text)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        argument: str | None = None
        if token == "-X":
            index += 1
            if index >= len(tokens):
                raise AssertionError("dangling -X at the end of the ldflags")
            argument = tokens[index]
        elif token.startswith("-X") and len(token) > 2:
            argument = token[2:]
        if argument is None:
            index += 1
            continue
        symbol, separator, value = argument.partition("=")
        assert separator, f"malformed -X argument (no '='): {argument!r}"
        found[symbol] = value
        index += 1
    return found


def _sha256_of(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _lock() -> dict:
    return yaml.safe_load(LOCK.read_text())


def _containerfile() -> str:
    return (ROOT / CONTAINERFILE).read_text()


# --------------------------------------------------------------------------
# 1. the pin is bound at every site that consumes it
# --------------------------------------------------------------------------


def test_pinned_source_commit_is_bound_at_every_consuming_site() -> None:
    text = _containerfile()
    injections = _injections(text)
    assert GIT_COMMIT_SYMBOL in injections, (
        f"no -X injects {GIT_COMMIT_SYMBOL}; found {sorted(injections)}"
    )
    # (a) the shallow fetch names the exact commit
    assert re.search(
        rf"fetch\s+--depth\s+1\s+origin\s+{re.escape(PINNED_COMMIT)}\b", text
    ), f"git fetch --depth 1 origin {PINNED_COMMIT} not found"
    # (b) the archive prefix carries the same commit, so the tarball is built
    # from exactly the fetched tree
    assert f"--prefix=podman-{PINNED_COMMIT}/" in text
    # (c) the injected gitCommit is the full 40-char commit at this pin
    assert injections[GIT_COMMIT_SYMBOL] == PINNED_COMMIT
    # (d) the digest check must verify the tarball produced from this same
    # commit, addressed by the repo's 8-hex tarball stem and the exact digest
    # (the full commit cannot appear here: the filename is abbreviated by
    # convention, and requirement 6 forbids abbreviations in -X values only)
    assert (
        f'echo "{PINNED_TARBALL_SHA256}  /tmp/{TARBALL_STEM}.tar" | sha256sum -c -'
        in text
    ), f"sha256 assertion for /tmp/{TARBALL_STEM}.tar not found"


def test_tarball_digest_assertion_value_is_exact() -> None:
    text = _containerfile()
    assert (
        f'echo "{PINNED_TARBALL_SHA256}  /tmp/{TARBALL_STEM}.tar" | sha256sum -c -'
        in text
    )
    # Exactly one fail-closed digest check for this tarball, with this digest:
    # a drifted or duplicated assertion must not slip in beside the real one.
    checked = re.findall(
        rf"([0-9a-f]{{64}})  /tmp/{re.escape(TARBALL_STEM)}\.tar", text
    )
    assert checked == [PINNED_TARBALL_SHA256], (
        f"expected one digest check for {TARBALL_STEM}.tar, found {checked}"
    )
    assert text.count("sha256sum -c -") == 1


# --------------------------------------------------------------------------
# 2. module path of every injection
# --------------------------------------------------------------------------


def test_no_ldflag_targets_the_legacy_v5_module_path() -> None:
    text = _containerfile()
    symbols = _injections(text)
    assert symbols, "expected the two define -X injections to be present"
    for symbol in symbols:
        assert not symbol.startswith(LEGACY_MODULE), (
            f"-X still targets the pre-v6 module path: {symbol}"
        )
        assert symbol.startswith(MODULE + "/"), (
            f"-X symbol is outside the v6 module: {symbol}"
        )
    for value in _ldflag_strings(text):
        assert LEGACY_MODULE not in value, (
            f"the ldflags string still mentions {LEGACY_MODULE}: {value}"
        )


# --------------------------------------------------------------------------
# 3. THE load-bearing assertion: exact effective injection set
# --------------------------------------------------------------------------


def test_x_injection_set_is_exactly_the_two_effective_define_symbols() -> None:
    symbols = set(_injections(_containerfile()))
    assert symbols == set(EFFECTIVE_SYMBOLS), (
        "the -X injection set changed; expected exactly "
        f"{sorted(EFFECTIVE_SYMBOLS)}, got {sorted(symbols)}"
    )


def test_exactly_one_ldflags_string_is_present() -> None:
    # A second `-ldflags` string is how an inert flag would be smuggled back in.
    values = _ldflag_strings(_containerfile())
    assert len(values) == 1, f"expected one -ldflags string, found {len(values)}: {values}"


def test_no_measured_inert_symbol_is_injected() -> None:
    symbols = _injections(_containerfile())
    for suffix in INERT_SYMBOL_SUFFIXES:
        offenders = sorted(s for s in symbols if s.endswith(suffix))
        assert not offenders, (
            f"inert -X symbol(s) re-added ({suffix}): {offenders}; "
            "see the Containerfile comment on why these can never take effect"
        )


# --------------------------------------------------------------------------
# 4. injected values
# --------------------------------------------------------------------------


def test_build_info_is_the_pinned_committer_time_and_commit_is_not_abbreviated() -> None:
    injections = _injections(_containerfile())
    for symbol in (BUILD_INFO_SYMBOL, GIT_COMMIT_SYMBOL):
        assert symbol in injections, f"no -X injects {symbol}; found {sorted(injections)}"
    assert injections[BUILD_INFO_SYMBOL] == PINNED_BUILD_INFO
    assert re.fullmatch(r"\d+", injections[BUILD_INFO_SYMBOL])
    assert injections[GIT_COMMIT_SYMBOL] == PINNED_COMMIT
    assert re.fullmatch(r"[0-9a-f]{40}", injections[GIT_COMMIT_SYMBOL]), (
        "define.gitCommit must be the full 40-char commit; an abbreviation would "
        "make the program's own GitCommit assertion below unmatchable"
    )


# --------------------------------------------------------------------------
# 5. the injected values are observed THROUGH THE PROGRAM
# --------------------------------------------------------------------------


def test_injected_values_are_observed_through_the_program_not_the_binary() -> None:
    # Forbidden by design: grepping /out/podman-remote for the injected strings
    # passes even when -X did nothing, because the -ldflags text is itself
    # embedded in the Go build info. The only admissible observation is the
    # program's own output.
    text = _containerfile()
    assert "podman-remote version --format json" in text
    assert '"GitCommit"' in text
    assert '"Built"' in text
    assert (
        f'grep -q \'"GitCommit": *"{PINNED_COMMIT}"\' /tmp/podman-version.json' in text
    )
    assert (
        f'grep -q \'"Built": *{PINNED_BUILD_INFO}\' /tmp/podman-version.json' in text
    )
    # ... and nothing may grep the binary for an injected value.
    for line in text.splitlines():
        if "/out/podman-remote" not in line or "grep" not in line:
            continue
        assert PINNED_COMMIT not in line, (
            "the binary is being grepped for the injected commit; the -ldflags "
            f"text is embedded in build info: {line.strip()}"
        )
        assert PINNED_BUILD_INFO not in line, (
            f"the binary is being grepped for the injected buildInfo: {line.strip()}"
        )


def test_program_observation_tolerates_only_the_expected_connect_error_exit() -> None:
    # Regression guard for a build breaker found by independent verification of
    # commit 972627a5: `podman-remote version --format json` is NOT a pure
    # client-info command. In tunnel mode it calls registry.NewContainerEngine ->
    # pingNewConnection, and this builder stage has no podman service, so it
    # exits 125 (define.ExecErrorCodeGeneric) *after* printing the client report.
    # Chained with a bare `&&` the whole image build fails at this line.
    #
    # The tolerance must stay pinned to 125. `|| true` would also swallow a
    # genuine failure, and a bare `&&` is the breaker itself, so this asserts the
    # exact group form and rejects both wrong shapes.
    text = _containerfile()
    # Only real command lines: the explanatory comment block above the RUN step
    # names the same command, and matching it would make this test vacuous.
    observation = [
        ln
        for ln in text.splitlines()
        if "version --format json" in ln and not ln.lstrip().startswith("#")
    ]
    assert len(observation) == 1, (
        "expected exactly one program-observation line, found "
        f"{len(observation)}: {observation}"
    )
    line = observation[0]
    assert '"$?" -eq 125' in line, (
        "the program observation must tolerate exactly the ConnectError exit 125; "
        f"a bare && fails the build and `|| true` hides real failures: {line.strip()}"
    )
    assert "|| true" not in line, (
        f"unconditional exit swallowing would accept a genuine failure: {line.strip()}"
    )
    # The tolerance must be scoped to that one command, not to the whole chain:
    # the two value greps after it must still be && -chained so a missing or
    # malformed report fails the build.
    after = text.split(line, 1)[1]
    for expected in ('"GitCommit"', '"Built"'):
        assert f'&& grep -q \'{expected}' in after, (
            f"the {expected} assertion must remain && -chained after the "
            "tolerated observation"
        )
    # And the group form itself must be present, not just the 125 test.
    assert "|| [ \"$?\" -eq 125 ];" in line, (
        f"expected the {chr(123)} cmd || [ \"$?\" -eq 125 ] {chr(125)} group form: "
        f"{line.strip()}"
    )


def test_version_literal_is_asserted_exactly() -> None:
    text = _containerfile()
    assert (
        '/out/podman-remote --version | grep -Fx "podman-remote version '
        f'{PINNED_VERSION}"' in text
    )


# --------------------------------------------------------------------------
# 6. cross-file agreement with the locked build inputs
# --------------------------------------------------------------------------


def test_locked_source_built_tool_agrees_with_the_containerfile() -> None:
    tool = _lock()["sourceBuiltTools"]["podman-remote"]
    text = _containerfile()
    injections = _injections(text)
    assert GIT_COMMIT_SYMBOL in injections, (
        f"no -X injects {GIT_COMMIT_SYMBOL}; the lock claims "
        f"{tool['sourceCommit']} but the Containerfile injects {sorted(injections)}"
    )
    assert tool["sourceCommit"] == injections[GIT_COMMIT_SYMBOL]
    assert tool["sourceCommit"] == PINNED_COMMIT
    assert tool["version"] == PINNED_VERSION
    assert f"podman-remote version {PINNED_VERSION}" in text
    assert tool["digest"].startswith("sha256:")
    assert tool["digest"].removeprefix("sha256:") == PINNED_TARBALL_SHA256
    assert PINNED_TARBALL_SHA256 in text


def test_locked_definition_digest_matches_the_containerfile_bytes() -> None:
    assert _lock()["definitions"][CONTAINERFILE] == _sha256_of(ROOT / CONTAINERFILE)
