#!/usr/bin/env python3
"""Validate application-experience and functionality-preservation contracts."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packages" / "application-experience" / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from stateport_application_experience import ExperienceRegistry, load_experience_policy  # noqa: E402


PRESERVATION_EXTENSION_FORMAT = "stateport.functionality-preservation-extension/v1"
PRESERVATION_EXTENSION_ROOT = ROOT / "config" / "functionality-preservation.extensions"

# Populated by validate() so main() can report the shape of the census it just
# computed. Held here rather than added to validate()'s return value because
# that return value is the published figure set and is pinned by exact
# equality in test_application_experience; adding keys to it would change the
# meaning of a figure other consumers already read. The breakdown is reported
# ALONGSIDE the figures, which is also what the owner needs: a new key in a
# count object invites being summed with the others, and these must not be.
_CENSUS: dict[str, Any] = {}

# Populated by validate() for the same reason as _CENSUS: the citation
# measurement is a REPORT, and adding a key to validate()'s return value would
# change the meaning of a published figure set that other consumers already
# read by exact equality. Nothing in the measurement can refuse, so nothing in
# the measurement belongs in the verdict.
_CITATIONS: dict[str, list[str]] = {
    "supported": [],
    "unsupported": [],
    "unresolved": [],
}


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain an object")
    return value


def _merge_preservation_extensions(manifest: dict[str, Any]) -> dict[str, Any]:
    """Merge schema-compatible API operations from bounded extension files.

    The merged manifest is validated by the existing v1 JSON schema, so an
    extension can only add ordinary preservation entries; it cannot weaken or
    replace any base route, control, capability, alias, or API contract.
    """

    operations = manifest.get("apiOperations")
    if not isinstance(operations, list):
        raise ValueError("functionality-preservation apiOperations must be a list")
    if not PRESERVATION_EXTENSION_ROOT.exists():
        return manifest
    if PRESERVATION_EXTENSION_ROOT.is_symlink() or not PRESERVATION_EXTENSION_ROOT.is_dir():
        raise ValueError("functionality-preservation extension root is unsafe")
    for path in sorted(PRESERVATION_EXTENSION_ROOT.glob("*.yaml")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"preservation extension path is unsafe: {path.relative_to(ROOT)}")
        extension = _load_yaml(path)
        if set(extension) != {"formatVersion", "scope", "apiOperations"}:
            raise ValueError(f"{path.relative_to(ROOT)} has an invalid extension shape")
        if extension["formatVersion"] != PRESERVATION_EXTENSION_FORMAT:
            raise ValueError(f"{path.relative_to(ROOT)} has an unsupported formatVersion")
        scope = extension["scope"]
        items = extension["apiOperations"]
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError(f"{path.relative_to(ROOT)} scope is invalid")
        if not isinstance(items, list) or not items:
            raise ValueError(f"{path.relative_to(ROOT)} apiOperations must be a non-empty list")
        operations.extend(items)
    return manifest


def _safe_repo_file(relative: str) -> Path:
    candidate = ROOT / relative
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"preservation evidence path is missing or unsafe: {relative}")
    resolved = candidate.resolve()
    resolved.relative_to(ROOT.resolve())
    return resolved


def _check_preservation_item(item: dict[str, Any]) -> None:
    """Validate one preservation entry's evidence and its cited test.

    Split out of validate() so the refusal behaviour is directly testable
    without mutating the canonical manifest on disk.
    """
    evidence = item["evidence"]
    content = _safe_repo_file(evidence["file"]).read_text(encoding="utf-8")
    if evidence["contains"] not in content:
        raise ValueError(f"preservation evidence is stale for {item['id']}")
    # The cited test is a coverage claim, so it must resolve to a real file.
    # The schema checks `test` is a non-empty string and nothing more, so a
    # refactor that deletes or renames a cited test left the manifest claiming
    # coverage it no longer had, and this validator -- which otherwise checks
    # evidence staleness with real care -- never noticed. Reusing
    # _safe_repo_file keeps the test path under the same existence, symlink
    # and repository-escape rules as the evidence path.
    try:
        _safe_repo_file(item["test"])
    except ValueError as exc:
        raise ValueError(
            f"preservation test path is missing or unsafe for {item['id']}: {item['test']}"
        ) from exc


def _api_literals(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        value.value
        for value in ast.walk(tree)
        if isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and (value.value.startswith("/v1/") or value.value in {"/session", "/health"})
    }


def _path_covers(literal: str, declared: list[str]) -> bool:
    if literal in declared:
        return True
    if literal.endswith("/"):
        return any(item.startswith(literal) for item in declared)
    return any(item.startswith(literal + "/") for item in declared)


# Every literal route path in apps/web/src/App.tsx must be classified by a
# declared preservation route; unclassified routes fail validation, which is
# the React-era equivalent of the old static-HTML hash-link allowlist. The
# app-scoped "settings" path doubles as the advanced-control surface.
ROUTE_CLASSIFICATION: dict[str, set[str]] = {
    "platform": {"platform-hub-route"},
    "settings/provider": {"provider-settings-route"},
    "applications": {"home-route"},
    "catalog": {"catalog-route"},
    "sources": {"platform-route"},
    "sources/:sourceId": {"platform-route"},
    "statebench": {"platform-route"},
    # The `deployments` path literal is shared by the top-level platform
    # deployments surface and the per-instance workbench infrastructure tool;
    # both preservation contracts cover it.
    "deployments": {"platform-deployments-route", "workbench-route"},
    "authority": {"platform-authority-route"},
    "updater": {"platform-updater-route"},
    "preview-routes": {"platform-preview-routes-route"},
    "execution-host": {"platform-execution-host-route"},
    # ec6dc69b added an operator capsule-only workspace terminal under the same
    # global surface. It is the execution-host route, not a workbench capability,
    # and it is a terminal surface rather than a diagnostics one, so the entry's
    # own description was widened to say so rather than inheriting "diagnostics".
    "execution-host/workspaces/:instanceId/terminal": {"platform-execution-host-route"},
    "approvals": {"approvals-route"},
    "approvals/:approvalId": {"approvals-route"},
    "settings": {"settings-route", "advanced-route"},
    "settings/:group": {"settings-route", "advanced-route"},
    "app/:instanceId": {"application-route"},
    "conversation": {"conversation-route"},
    "workbench": {"workbench-route"},
    "files": {"workbench-route"},
    "terminal": {"workbench-route"},
    "orchestration": {"workbench-route"},
    "runs": {"workbench-route"},
    # The same nested path literal is used by the native application receipt
    # surface and the optional Workbench receipt tool; both contracts must be
    # preserved without making either route globally available.
    "receipts": {"application-receipts-route", "workbench-route"},
    "receipts/:receiptId": {"application-receipts-route", "workbench-route"},
    "*": set(),  # explicit NotFound handler, not a product route
}


def _validate_router_surface(manifest: dict[str, Any]) -> None:
    app = (ROOT / "apps" / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
    paths = set(re.findall(r'path="([^"]+)"', app))
    unclassified = sorted(path for path in paths if path not in ROUTE_CLASSIFICATION)
    if unclassified:
        raise ValueError(f"unclassified router paths: {unclassified}")
    declared_routes = {item["id"] for item in manifest["uiRoutes"]}
    covered = set().union(*(ROUTE_CLASSIFICATION[path] for path in paths))
    uncovered = sorted(declared_routes - covered)
    if uncovered:
        raise ValueError(f"declared preservation routes without a router path: {uncovered}")
    unknown_classifications = sorted(covered - declared_routes)
    if unknown_classifications:
        raise ValueError(f"router paths reference undeclared preservation routes: {unknown_classifications}")

    legacy = (ROOT / "apps" / "web" / "src" / "legacyRoutes.ts").read_text(encoding="utf-8")
    block = re.search(r"LEGACY_BARE_ROUTES[^{]*\{(?P<body>.*?)\}", legacy, re.DOTALL)
    if block is None:
        raise ValueError("legacy hash normalization table is missing")
    targets = set(re.findall(r":\s*'(/[^']+)'", block.group("body")))
    router_targets = {f"/{path.split(':')[0].rstrip('/')}" for path in paths if path != "*"}
    unmapped = sorted(target for target in targets if target not in router_targets)
    if unmapped:
        raise ValueError(f"legacy hash aliases resolve to unknown routes: {unmapped}")
    if not re.search(r"platform:\s*'/applications'", legacy):
        raise ValueError("legacy #platform hash must normalize to the application-first home")

    # Preservation aliases are executable compatibility contracts, not prose
    # that may be relabelled deprecated when a replacement frontend lands.
    # Keep both bare aliases and application-scoped aliases declarative so the
    # validator can compare them with the manifest without executing browser
    # code or accepting a NotFound route as a "replacement".
    bare_entries = dict(re.findall(r"^\s*(\w+):\s*'([^']+)'", block.group("body"), re.MULTILINE))
    required_bare = {
        "instances": "/applications",
        "advanced": "/settings",
    }
    missing_bare = {
        key: target
        for key, target in required_bare.items()
        if bare_entries.get(key) != target
    }
    scoped_name_match = re.search(
        r"(LEGACY_(?:SCOPED|INSTANCE)_ROUTES)[^{]*\{(?P<body>.*?)\}",
        legacy,
        re.DOTALL,
    )
    scoped_entries = (
        {}
        if scoped_name_match is None
        else dict(re.findall(r"^\s*(\w+):\s*'([^']*)'", scoped_name_match.group("body"), re.MULTILINE))
    )
    required_scoped = {
        "instance": "",
        "conversation": "/conversation",
        "advanced": "/settings",
        "workbench": "/workbench",
    }
    missing_scoped = {
        key: target
        for key, target in required_scoped.items()
        if scoped_entries.get(key) != target
    }
    scoped_name = None if scoped_name_match is None else scoped_name_match.group(1)
    if missing_bare or missing_scoped or scoped_name is None or legacy.count(scoped_name) < 2:
        raise ValueError(
            "preserved legacy aliases are not implemented; "
            f"bare={missing_bare}, scoped={missing_scoped}"
        )


def _frontend_api_templates() -> set[str]:
    """Normalized endpoint templates declared by the typed HTTP client.

    apps/web/src/client/http/endpoints.ts is the single source of frontend
    paths; `${enc(name)}` segments normalize to `{name}` so they can be
    compared exactly against manifest apiOperations paths.
    """
    source = (ROOT / "apps" / "web" / "src" / "client" / "http" / "endpoints.ts").read_text(encoding="utf-8")
    templates: set[str] = set()
    for literal in re.findall(r"'(/v1/[^']*|/session)'", source):
        templates.add(literal)
    for template in re.findall(r"`(/v1/[^`]*|/session)`", source):
        normalized = re.sub(r"\$\{enc\((\w+)\)\}", r"{\1}", template)
        templates.add(normalized)
    return templates


# The control population is enumerated from the SHIPPED frontend source, not
# from a manifest-derived or test-derived list, because the defect being closed
# is precisely that a control present in apps/web/src and absent from every
# manifest was invisible to both label censuses. A census drawn from the
# manifest could not see its own blind spot.
#
# The identity vocabulary is REUSED, not invented. 25 of the 77 userControls
# entries pin an evidence literal of the exact form `data-testid="<name>"`, so a
# data-testid is already a declared control identity in this manifest's own
# contract. Matching on anything else (button prose, a11y labels) would measure
# a population the manifest was never written to hold; see
# evidence/one-line-release-001/owner-decision-brief-control-population-boundary-20260927.md,
# which records that a label-anchored metric would be measuring the wrong thing.
#
# CORRECTION, measured at this commit rather than assumed: the figure this
# comment used to state was 31, and 31 does not match what this code counts.
# `CONTROL_IDENTITY_PATTERN` finds a name in 25 userControls `contains` strings,
# 26 contain the substring `data-testid` (the extra one is the JSX-expression
# form `data-testid={`install-${pkg.name}`}`, which the pattern deliberately
# does not match), and a 27th is anchored on a `testId=` prop rather than a
# data-testid at all. The 31 was never re-derived. The NUMBER is corrected
# here and the ARGUMENT is untouched, because the argument is about the
# vocabulary being reused and survives 25 exactly as it survived 31. No pattern,
# no filter and no population was changed to make any of these numbers come out
# differently -- see _uncredited_declared_controls below, which reports the
# 52 declared userControls that credit NO data-testid identity.
#
# "Declared" means: some manifest or dynamic-manifest entry already carries an
# evidence literal naming this control, IN THE FILE WHERE THE CONTROL LIVES.
# That is exactly the anchor the freshness loop above already verifies, so this
# check audits the same identities the staleness check proves exist rather than
# a second, more forgiving notion of coverage.
FRONTEND_SOURCE_ROOT = ROOT / "apps" / "web" / "src"
# Not shipped UI. Test sources, the dev-only mock adapter and the test support
# tree are excluded because no user can reach them. The test directories are
# matched as PATH SEGMENTS anywhere in the tree, not as a leading prefix, which
# is what test_application_experience._frontend_sources already does: `__tests__`
# appears mid-path in a real shipped-surface pattern and a prefix test would
# silently keep counting test-only controls as product ones.
FRONTEND_SOURCE_EXCLUDED_DIRS = ("__tests__",)
FRONTEND_SOURCE_EXCLUDED_PREFIXES = ("client/mock/", "test/")
CONTROL_IDENTITY_PATTERN = re.compile(r'data-testid="([^"{}$`]+)"')


def _is_shipped_frontend_source(relative: str) -> bool:
    if relative.startswith(FRONTEND_SOURCE_EXCLUDED_PREFIXES):
        return False
    return not any(part in FRONTEND_SOURCE_EXCLUDED_DIRS for part in relative.split("/"))


def _shipped_frontend_sources() -> dict[str, str]:
    """Repo-relative contents of every shipped frontend source file."""
    sources: dict[str, str] = {}
    for path in sorted(FRONTEND_SOURCE_ROOT.rglob("*")):
        if path.suffix not in {".ts", ".tsx"} or not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(FRONTEND_SOURCE_ROOT).as_posix()
        if not _is_shipped_frontend_source(relative):
            continue
        sources[f"apps/web/src/{relative}"] = path.read_text(encoding="utf-8")
    return sources


def _control_identities(sources: dict[str, str]) -> dict[str, set[str]]:
    """File -> the set of control identities declared by that file's source."""
    return {
        file: set(CONTROL_IDENTITY_PATTERN.findall(content))
        for file, content in sources.items()
    }


def _declared_control_literals(evidence_items: list[dict[str, Any]]) -> dict[str, set[str]]:
    """File -> the control identity literals some manifest entry already pins.

    Only literals that actually name a control are indexed, so a prose evidence
    string that happens to be read from the right file cannot stand in for a
    declaration the operator never wrote.
    """
    declared: dict[str, set[str]] = {}
    for item in evidence_items:
        contains = str(item["evidence"]["contains"])
        names = set(CONTROL_IDENTITY_PATTERN.findall(contains))
        if names:
            declared.setdefault(str(item["evidence"]["file"]), set()).update(names)
    return declared


def _undeclared_controls(sources: dict[str, str], evidence_items: list[dict[str, Any]]) -> list[str]:
    """Shipped controls with no manifest entry, named by file and literal.

    Anchoring a declaration to the file the control lives in, rather than
    matching the identity anywhere in the manifest, is what keeps this a
    coverage census: a `data-testid` pinned on an unrelated row would otherwise
    silently cover a different control that happens to share the name.
    """
    declared = _declared_control_literals(evidence_items)
    undeclared = {
        f'{file}: data-testid="{identity}"'
        for file, identities in _control_identities(sources).items()
        for identity in identities - declared.get(file, set())
    }
    return sorted(undeclared)


# ---------------------------------------------------------------------------
# WHAT THE UNDECLARED FIGURE COUNTS.
#
# `_undeclared_controls` answers "which control identities are undeclared?", and
# that is a real coverage census. It does NOT answer "what kind of thing is
# each of those identities?", and the two are not the same question: 511 is a
# single number standing for a population whose members are not interchangeable.
# A `data-testid` on a `<Button>` an operator presses and a `data-testid` on a
# `<div>` that only exists to be a layout anchor are both "undeclared", but only
# one of them is the thing a functionality-preservation manifest is written
# about.
#
# The population boundary is still the OWNER's undecided call, so this section
# deliberately does NOT choose one. It partitions the SAME population into
# disjoint classes and reports the size of each, so the choice can be made with
# numbers in hand. Nothing here filters, narrows, suppresses or reorders the
# census: `_undeclared_controls` above is untouched, `undeclaredControls` below
# is the same `len()` of the same list, and the class counts are proven to sum
# back to it by a test. Narrowing is the owner's decision to make with these
# numbers visible, not this function's to make by omission.
#
# METHOD, stated plainly because a breakdown whose provenance is vague is worse
# than no breakdown: every class below is DERIVED FROM A SCAN OF SHIPPED SOURCE.
# There is no hand-written list of identities anywhere in this file, and no
# hand-maintained list of "our components are interactive" -- that second kind
# of list is exactly what goes stale silently, leaving a control reported as a
# container after it was turned into a button. The scan is LEXICAL, not a
# TypeScript/JSX parse, so it has known limits, and they are measured and
# reported rather than assumed away (see _control_shape_classes and the
# reported `componentHostUnresolved` / `nonElementReference` classes, which
# exist precisely so the scan's own uncertainty is visible as a number instead
# of being resolved by guessing).
# ---------------------------------------------------------------------------

# A JSX opening tag that carries one of these is something a person operates.
# `summary` and `option` are included because they are natively operable
# elements; `label` is deliberately NOT here, because a label is a text
# association rather than an action.
INTERACTIVE_DOM_TAGS = frozenset(
    {"button", "a", "input", "select", "textarea", "summary", "option"}
)
# The standard HTML element names, used to tell a real rendered element from a
# TypeScript generic. Unlike a list of this repository's own components -- which
# would go stale and quietly reclassify a control the day someone turned a div
# into a button -- this vocabulary is fixed by the HTML specification, so it
# cannot drift out of date with the codebase.
HTML_ELEMENT_TAGS = frozenset(
    """a abbr address area article aside audio b base bdi bdo blockquote body br
    button canvas caption cite code col colgroup data datalist dd del details dfn
    dialog div dl dt em embed fieldset figcaption figure footer form h1 h2 h3 h4
    h5 h6 head header hgroup hr html i iframe img input ins kbd label legend li
    link main map mark menu meta meter nav noscript object ol optgroup option
    output p param picture pre progress q rp rt ruby s samp script section select
    slot small source span strong style sub summary sup table tbody td template
    textarea tfoot th thead time title tr track u ul var video wbr""".split()
)
# An event handler on the host element is direct evidence of an action
# mechanism, and it is evidence about the ELEMENT, not about its name, so it
# outranks any name-based guess below.
HOST_EVENT_HANDLER = re.compile(
    r"\bon(?:Click|DoubleClick|KeyDown|KeyUp|KeyPress|PointerDown|PointerUp"
    r"|MouseDown|MouseUp|Change|Input|Submit|TouchStart|ContextMenu|Drag"
    r"|Drop|Scroll|ScrollEnd|Wheel|Focus|Blur)\s*="
)
# Placeholder vocabulary, matched against the identity AND the host's own
# markup. This is a NAME heuristic and is reported as such: it is the only
# name-based rule in the partition, and it is deliberately narrow. It exists
# because a loading placeholder is the clearest real case in this population of
# a data-testid that is emphatically not an operator action, and because a
# scan that filed `route-skeleton` under "container" would bury it. It is a
# named, inspectable vocabulary rather than a hand-listed set of identities.
PLACEHOLDER_VOCABULARY = re.compile(r"skeleton|shimmer|placeholder|stub", re.IGNORECASE)
# The disjoint classes, in the precedence order used to fold the several
# source SITES of one identity into the single class that identity is reported
# under. Precedence is evidence-ordered, strongest evidence first:
#   interactive            a real action mechanism exists
#   skeleton_placeholder   the identity or its host markup says placeholder
#   container_or_layout    a real non-interactive DOM element hosts it
#   component_host_unresolved
#                          the host is a component with no shipped definition
#   non_element_reference  the literal is not on a JSX element at all
# The partition is strict and exhaustive: every undeclared identity lands in
# exactly one class, and the test pins that the counts sum to the total.
CONTROL_SHAPE_CLASSES = (
    "interactive",
    "skeleton_placeholder",
    "container_or_layout",
    "component_host_unresolved",
    "non_element_reference",
)
_JSX_TAG = re.compile(r"<([A-Za-z][A-Za-z0-9._:-]*)")


def _lexical_context(content: str) -> list[str]:
    """Per-character "code" | "comment" | "string" classification.

    Needed because CONTROL_IDENTITY_PATTERN is a text scan, and a text scan
    also matches `data-testid="drawer"` inside a `document.querySelector(...)`
    string or inside a doc comment. Those matches are real occurrences of the
    literal and they DO count towards the population -- the population is not
    narrowed to fix this -- but they are not elements, and reporting them as
    though they were would be the dishonest outcome. Masking lets the census
    keep every one of them while classifying them honestly.

    The quote rule matters more than it looks. JSX text and comments contain
    bare apostrophes ("couldn't", "the operator's"), and a scanner that treats
    every `'` as a string OPENER pairs it with the next apostrophe in the file
    and masks everything between as string text. That silently reclassified
    this entire population as non-elements on the first attempt. A quote only
    opens a string when the character before it cannot end a word.
    """
    mask = ["code"] * len(content)
    index = 0
    while index < len(content):
        char = content[index]
        pair = content[index : index + 2]
        if pair == "//":
            end = content.find("\n", index)
            end = len(content) if end < 0 else end
            for offset in range(index, end):
                mask[offset] = "comment"
            index = end
            continue
        if pair == "/*":
            end = content.find("*/", index + 2)
            end = len(content) if end < 0 else end + 2
            for offset in range(index, end):
                mask[offset] = "comment"
            index = end
            continue
        if char in "\"'`":
            preceding = content[index - 1] if index else ""
            if char != "`" and preceding.isalnum() and preceding not in "_$":
                index += 1
                continue
            cursor = index + 1
            while cursor < len(content):
                if content[cursor] == "\\":
                    cursor += 2
                    continue
                if content[cursor] == char:
                    break
                # An unterminated single/double-quoted string ends at the line
                # end rather than swallowing the rest of the file; a template
                # literal is allowed to span lines.
                if content[cursor] == "\n" and char != "`":
                    break
                cursor += 1
            for offset in range(index + 1, min(cursor, len(content))):
                mask[offset] = "string"
            index = cursor + 1
            continue
        index += 1
    return mask


def _host_opening_tag(content: str, index: int) -> tuple[str | None, str | None]:
    """The JSX opening tag carrying the attribute at `index`, or (None, None).

    Walks backwards to the nearest `<` that opens a tag, tracking brace depth
    and string/comment context so that a `<` inside an expression, a string or
    a comparison is not mistaken for a tag. Returns the tag name and the
    attribute region between the tag name and its closing `>`.
    """
    cursor = index - 1
    depth = 0
    while cursor >= 0:
        char = content[cursor]
        if char in "}]":
            depth += 1
        elif char in "[{(":
            if depth:
                depth -= 1
        elif depth == 0 and char == "<":
            following = content[cursor + 1] if cursor + 1 < len(content) else ""
            preceding = content[cursor - 1] if cursor else ""
            if following.isalpha() and preceding not in "<>=!&|/":
                match = _JSX_TAG.match(content, cursor)
                if match is None:
                    return None, None
                region_end = match.end()
                braces = 0
                while region_end < len(content):
                    inner = content[region_end]
                    if inner == "{":
                        braces += 1
                    elif inner == "}":
                        braces -= 1
                    elif inner == ">" and braces == 0:
                        return match.group(1), content[match.end() : region_end]
                    region_end += 1
                return match.group(1), None
        cursor -= 1
    return None, None


def _local_component_modules(sources: dict[str, str]) -> dict[str, dict[str, str]]:
    """file -> {component name: shipped file that declares it}.

    Resolves named imports and, for a barrel such as components/index.ts, the
    `export { X } from './Y'` re-exports behind them, because the shipped
    frontend imports shared components through that barrel and a resolver that
    stopped at the barrel would report every one of them as unresolvable.
    """
    resolved: dict[str, dict[str, str]] = {}
    for file, content in sources.items():
        found: dict[str, str] = {}
        relative_dir = os.path.dirname(file[len("apps/web/src/") :])
        for pattern in (
            r"import\s+(?:type\s+)?\{([^}]*)\}\s*from\s*['\"]([^'\"]+)['\"]",
            r"export\s+(?:type\s+)?\{([^}]*)\}\s*from\s*['\"]([^'\"]+)['\"]",
        ):
            for match in re.finditer(pattern, content):
                names, module = match.group(1), match.group(2)
                if module.startswith("@/"):
                    base = module[2:]
                elif module.startswith("."):
                    base = os.path.normpath(os.path.join(relative_dir, module))
                else:
                    continue  # third-party: not resolvable from shipped source
                for candidate in (base + ".tsx", base + ".ts", base + "/index.tsx", base + "/index.ts"):
                    target = "apps/web/src/" + candidate
                    if target in sources:
                        for part in names.split(","):
                            part = part.strip()
                            if not part:
                                continue
                            found.setdefault(part.split(" as ")[-1].strip(), target)
                        break
        resolved[file] = found
    return resolved


def _declared_in_file(content: str, name: str) -> bool:
    return bool(
        re.search(r"(?:export\s+)?(?:function|const)\s+" + re.escape(name) + r"\b", content)
    )


def _resolve_dom_host(
    tag: str,
    host_file: str,
    sources: dict[str, str],
    modules: dict[str, dict[str, str]],
    depth: int = 0,
    seen: frozenset[tuple[str, str]] = frozenset(),
) -> str | None:
    """The DOM tag a JSX host renders, or None when source cannot say.

    A lowercase tag is already the answer. A component is followed through its
    local definition to the first DOM tag in its body, bounded in depth and
    cycle-guarded. Returns None -- rather than a guess -- for a third-party
    component (react-router's `Link`, a Radix `DialogPrimitive.Content`), a
    namespace whose base is third-party, a context Provider, and any component
    whose local definition renders no DOM tag directly. Those are the honest
    "this scan cannot see it" cases, and they are reported as their own class
    so the uncertainty is a number instead of a silent reclassification.
    """
    # The guard is keyed on (name, file), not on the name alone: following a
    # re-export barrel re-enters the SAME component name in a different
    # file, which a name-keyed guard would mistake for a cycle and abandon.
    if depth > 3 or (tag, host_file) in seen:
        return None
    seen = seen | {(tag, host_file)}
    if not tag[:1].isupper():
        return tag
    base = tag.split(".")[0]
    if "." in tag and not _declared_in_file(sources.get(host_file, ""), base):
        # A namespace such as `DialogPrimitive.Content` resolves only if the
        # namespace itself is declared locally; otherwise its base is a
        # third-party package and no shipped file can answer this.
        return None
    target = modules.get(host_file, {}).get(base)
    if target is None or target == host_file:
        return None
    body = sources[target]
    declaration = re.search(
        r"(?:export\s+)?(?:function|const)\s+" + re.escape(base) + r"\b", body
    )
    if declaration is None:
        # The target is a barrel rather than the definition -- the shipped
        # frontend imports its shared components through components.ts, which
        # only re-exports them. The barrel's own import map names the real
        # file, so the walk continues there; a genuine dead end still returns
        # None and is reported as unresolved.
        return _resolve_dom_host(base, target, sources, modules, depth + 1, seen)
    segment = body[declaration.end() :]
    following = re.search(r"\n(?:export\s+)?(?:function|const)\s", segment)
    if following:
        segment = segment[: following.start()]
    nested: str | None = None
    fallback: str | None = None
    for match in _JSX_TAG.finditer(segment):
        candidate = match.group(1).split(".")[0]
        if candidate in HTML_ELEMENT_TAGS:
            # A standard HTML element name is the most reliable signal
            # available, so it wins over whatever tag came first. This is not
            # cosmetic: a TypeScript generic such as `Record<string, unknown>`
            # is lexically indistinguishable from a `<string>` JSX tag, and
            # first-match resolved a component to the literal name `string`.
            return candidate
        if candidate[:1].isupper():
            # Only reached when no HTML tag exists in the body, i.e. the
            # component renders other components.
            if nested is None:
                nested = candidate
        elif fallback is None:
            fallback = candidate
    nested = nested or fallback
    if nested is not None:
        resolved = _resolve_dom_host(nested, target, sources, modules, depth + 1, seen)
        if resolved is not None:
            return resolved
    # The element a component renders is often a local alias rather than a
    # literal: `const Comp = asChild ? Slot : "button"; return <Comp {...} />`,
    # which is how the shared Button, Input and menu components in this
    # frontend are written. `<Comp>` is a component name no import map can
    # resolve, so the default branch of such a binding is what actually names
    # the element, and it is read from the source rather than leaving 81 real
    # operator actions filed as unresolvable. Only names in the HTML vocabulary
    # are accepted, and only the FIRST such binding, so a stray string in the
    # body cannot be mistaken for the rendered element.
    for match in re.finditer(
        r"\bconst\s+\w+\s*=[^;\n]*?['\"]([a-z][a-z0-9]*)['\"]", segment
    ):
        if match.group(1) in HTML_ELEMENT_TAGS:
            return match.group(1)
    return None


def _control_shape_classes(
    sources: dict[str, str], undeclared: list[str]
) -> dict[str, list[str]]:
    """Partition the undeclared population into disjoint shape classes.

    Returns class name -> the sorted `file: data-testid="..."` identities in
    it. The classes partition the input exactly: the sum of their lengths
    equals len(undeclared), which is what makes the breakdown a description of
    the same 511 rather than a second, differently-sized population.
    """
    modules = _local_component_modules(sources)
    sites: dict[str, list[tuple[str, str | None, str]]] = {}
    for entry in undeclared:
        file, _, identity = entry.partition(': data-testid="')
        identity = identity.rstrip('"')
        content = sources.get(file)
        if content is None:
            sites[entry] = [(identity, None, "")]
            continue
        mask = _lexical_context(content)
        collected: list[tuple[str, str | None, str]] = []
        for match in CONTROL_IDENTITY_PATTERN.finditer(content):
            if match.group(1) != identity:
                continue
            if mask[match.start()] != "code":
                # A real occurrence of the literal that is not on a JSX
                # element: a querySelector string, a doc comment, a type
                # reference. It stays in the population; it is not an element.
                # Only the START of the attribute is tested, not its span: the
                # mask necessarily marks the quoted value as string text, so
                # testing the whole span flags every genuine attribute. The
                # attribute NAME sits in code for a real element and inside the
                # enclosing string or comment for a textual occurrence, which
                # is exactly the distinction being made here.
                collected.append((identity, None, ""))
                continue
            tag, region = _host_opening_tag(content, match.start())
            collected.append((identity, tag, region or ""))
        sites[entry] = collected or [(identity, None, "")]

    classified: dict[str, list[str]] = {name: [] for name in CONTROL_SHAPE_CLASSES}
    for entry, entry_sites in sites.items():
        found: set[str] = set()
        identity = entry_sites[0][0]
        for _, tag, region in entry_sites:
            if tag is None:
                found.add("non_element_reference")
                continue
            dom = (
                tag
                if not tag[:1].isupper()
                else _resolve_dom_host(
                    tag, entry.split(': data-testid="')[0], sources, modules
                )
            )
            # Order within a site, and it is not the same order as the
            # precedence across classes. Resolvability GATES the two claims
            # that are about the element: an identity is only called
            # `interactive` or `container_or_layout` when the scan actually saw
            # which element it is. The placeholder test is different, because it
            # reads the identity name and the host's own attribute region, both
            # of which are available whether or not the host component resolves.
            # Putting the placeholder test after the resolvability test filed
            # `overview-skeleton` -- a data-testid on <SkeletonRows> -- under
            # component_host_unresolved, which is the one class where nobody
            # would think to look for a loading placeholder.
            if dom is not None and (
                dom in INTERACTIVE_DOM_TAGS or HOST_EVENT_HANDLER.search(region)
            ):
                found.add("interactive")
            elif PLACEHOLDER_VOCABULARY.search(identity) or PLACEHOLDER_VOCABULARY.search(region):
                found.add("skeleton_placeholder")
            elif dom is not None:
                found.add("container_or_layout")
            else:
                found.add("component_host_unresolved")
        for name in CONTROL_SHAPE_CLASSES:
            if name in found:
                classified[name].append(entry)
                break
    return {name: sorted(values) for name, values in classified.items()}


def _uncredited_declared_controls(
    evidence_items: list[dict[str, Any]]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Declared entries split by whether they can credit a data-testid identity.

    Returns (credited, uncredited). An entry is CREDITED only when its own
    `evidence.contains` string contains a literal of the exact form
    `data-testid="<name>"` -- that is the only thing `_declared_control_literals`
    reads, so it is the only thing that can discharge an identity in the census.

    The uncredited half is reported rather than treated as an error, and the
    distinction matters for anyone reading the two numbers side by side: an
    entry anchored on button prose, an `aria-label`, a client method or a JSX
    fragment is very likely correct, fresh evidence -- `_check_preservation_item`
    verifies it is fresh -- but it names no control identity, so it removes
    nothing from `undeclaredControls`. A declared row and an undeclared
    identity are therefore NOT two halves of one quantity and must not be
    summed or subtracted into a coverage percentage.
    """
    credited: list[dict[str, str]] = []
    uncredited: list[dict[str, str]] = []
    for item in evidence_items:
        row = {
            "id": str(item.get("id", "")),
            "file": str(item["evidence"]["file"]),
            "contains": str(item["evidence"]["contains"]),
        }
        if CONTROL_IDENTITY_PATTERN.search(row["contains"]):
            credited.append(row)
        else:
            uncredited.append(row)
    return credited, uncredited


# ---------------------------------------------------------------------------
# CITATION MEASUREMENT. REPORTING ONLY.
#
# `_check_preservation_item` proves a cited test FILE exists, is not a symlink
# and does not escape the repository. It never reads the file's CONTENT, so a
# manifest row can cite a test containing no request at all and still pass.
# That is not hypothetical: three real rows did exactly this before this block
# existed, and one of them has no supporting test anywhere.
#
# WHAT THIS BLOCK IS NOT. Not a gate, not a coverage percentage, not a
# substitute for reading a test. It refuses nothing, changes no count, adds no
# key to validate()'s return value, and cannot alter the exit code. If every
# number here were wrong the validator would still exit 0. That is deliberate:
# a static-analysis verdict must not be able to block a release, and a metric
# that can block is a metric that gets tuned until it stops blocking.
#
# WHY AST AND NOT GREP. A grep for the literal route string returns NOTHING for
# a test that composes the route at a sink from a parameter, and the correct
# answer for such a test is "supported", not "unsupported". Concretely:
#   * scripts/test_provider_setup.py         composes f'/v1/provider/{action}'
#                                             at the sink, verb from a ternary.
#   * scripts/test_conversation_service.py   composes .../{operation} inside a
#                                             helper whose method= supplies the
#                                             verb; call sites supply 'export'
#                                             and 'clear'.
#   * scripts/test_activity_receipts_service.py picks the verb with
#                                             method="POST" if body is not None
#                                             else "GET" inside a request helper.
# A grep version of this metric would report all three as UNSUPPORTED -- a
# confident false negative accusing three correct, live tests. So the resolver
# walks the AST, binds helper parameters back to their call sites, and expands
# module-level tables that a loop iterates. Anything it still cannot resolve is
# reported `unresolved`, NEVER as supported or unsupported: a wrong confident
# answer here would invent a defect in a correct test, so the honest unknown is
# the only safe output and `unresolved` is the default under uncertainty.
# ---------------------------------------------------------------------------
# The resolvers below are reporting-only; none of them can refuse.
_TRANSPORT_NAMES = frozenset(
    {
        "urlopen",
        "Request",
        "urlretrieve",
        "request",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "head",
        "options",
    }
)

# Verbs the resolver will name. Anything else stays unresolved.
_HTTP_VERBS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})

# A declared segment written {name} matches any single segment. This is what
# lets a test's /v1/instances/project-one/activity satisfy the declared
# /v1/instances/{instanceId}/activity.
_TEMPLATE_SEGMENT = re.compile(r"^\{[A-Za-z0-9_]+\}$")

# Holes are NUL-delimited and NAME-CARRYING (see _hole). A composed path that
# still holds one is refused by _path_matches, so an unresolved composition can
# never be reported as a confirmed match.


def _is_template_segment(segment: str) -> bool:
    return bool(_TEMPLATE_SEGMENT.match(segment))


def _path_matches(resolved: str, declared_path: str) -> bool:
    """Compare a resolved test path against a declared manifest path.

    A `{name}` segment on the DECLARED side is one wildcard segment. The test
    side is never a wildcard, and a test path still holding a hole is refused
    outright, so "I could not resolve this" can never be reported as "the test
    exercises this route".
    """
    if _contains_hole(resolved):
        return False
    test_segments = [segment for segment in resolved.split("/") if segment]
    declared_segments = [segment for segment in declared_path.split("/") if segment]
    if len(test_segments) != len(declared_segments):
        return False
    return all(
        _is_template_segment(declared) or test == declared
        for test, declared in zip(test_segments, declared_segments)
    )


def _string_values(node: ast.AST) -> set[str] | None:
    """Literal strings a node evaluates to, or None when it is not literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: set[str] = set()
        for element in node.elts:
            if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
                return None
            values.add(element.value)
        return values or None
    return None


def _hole(name: str) -> str:
    """A named, unfillable hole, written as a single sentinel character.

    The NAME is carried in a side table so expansion can substitute that name's
    own values and no others. An earlier version spelled the hole as text around
    the name, which was wrong in a way that silently corrupted routes: the hole
    text was longer than the value it stood for, so replacing it ate the '/'
    that followed and turned ".../{port}/v1/instances" into "...v1/instances".
    A one-character sentinel cannot swallow a separator, and it cannot equal a
    real route segment, so a composition that never resolves stays visibly
    unresolved instead of becoming a different, plausible-looking path.
    """
    return _HOLE_CHAR + name + _HOLE_END


# A hole is written as CHAR + name + END, using private-use codepoints that
# cannot occur in a real route. A kept (unfillable) hole collapses to the single
# KEEP character, so the path keeps its exact character positions and the '/'
# after a hole can never be swallowed by substituting for it.
_HOLE_CHAR = "\ue000"
_HOLE_END = "\ue001"
_HOLE_KEEP = "\ue002"


def _contains_hole(text: str) -> bool:
    """Whether a composed path still holds an unresolved piece.

    Both sentinels count. A kept hole is just as unresolvable, and a check that
    recognised only one spelling would let the other through as if it were a
    real route segment.
    """
    return _is_hole(text)


def _is_hole(text: str) -> bool:
    return _HOLE_CHAR in text or _HOLE_KEEP in text


def _composed(
    node: ast.AST, env: dict[str, set[str]], literals: dict[str, Any] | None = None
) -> str | None:
    """The string an expression evaluates to, with unresolved names as holes.

    This is the join a literal grep cannot perform: grepping the source of
    `f'/v1/provider/{action}'` finds two halves and never the path, and grepping
    for the finished path finds nothing at all.

    `env` maps a name to the values it is known to hold. A name absent from env
    becomes a hole rather than being dropped, so a partially-understood
    composition stays visibly incomplete instead of silently becoming a
    different, shorter path.

    `literals` carries the provable-literal structures from _provable_literals
    and is what lets a SUBSCRIPT be read instead of skipped. It is a separate
    channel from `env` on purpose: a value reached through a literal provable in
    this file is evidence, while a value sitting in the name environment came
    from call-site binding, and conflating them would let one vouch for the other.
    A subscript with no provable literal returns None, exactly as before, so the
    caller's hole handling -- and therefore every row that was already being
    classified -- is untouched.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append(_composed(value.value, env, literals) or _hole("<expr>"))
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _composed(node.left, env, literals)
        right = _composed(node.right, env, literals)
        if left is None or right is None:
            return None
        return left + right
    if isinstance(node, ast.Name):
        return _hole(node.id)
    if isinstance(node, ast.Subscript) and literals:
        # The only NEW way a subscript becomes text. It returns a concrete value
        # or None, never a partially-guessed one, so a live-response subscript
        # keeps the same behaviour it had before this branch existed.
        return _subscript_string(node, literals)
    return None


def _strip_origin(path: str) -> str:
    """Drop a composed `scheme://host:port` origin so only the path remains.

    `f"{base}{path}"` is the dominant shape in these tests and `base` is
    usually a variable, so the origin is unresolvable by construction. Cutting
    everything before the first route root is what makes a variable-composed URL
    comparable at all, and it is safe because a URL path always begins at that
    root.
    """
    for marker in ("/v1/", "/session", "/health"):
        index = path.find(marker)
        if index > 0:
            return path[index:]
    return path


def _module_tables(tree: ast.Module) -> dict[str, set[str]]:
    """Module-level names bound to a literal table of strings.

    This is the LOOP HANDLING the variable-composed files need. A test writing
        SECURED_POST_ROUTES = (("/v1/a", "code"), ...)
        for path, _denial in SECURED_POST_ROUTES:
            _post(port, path, ...)
    composes its paths from a table, and every route that table names IS a
    route the test exercises. Without this expansion such rows would be
    ambiguous, and ambiguity is reported as `unresolved`, never as a defect.
    """
    tables: dict[str, set[str]] = {}
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        value = statement.value
        if value is None:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            values = _string_values(value)
            if values:
                tables[target.id] = values
                continue
            if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
                rows: set[str] = set()
                for element in value.elts:
                    head = _string_values(element)
                    if head:
                        rows |= head
                if rows:
                    tables[target.id] = rows
    return tables


def _iterated_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call) and node.args:
        return _iterated_name(node.args[0])
    return ""


def _loop_env(tree: ast.Module, tables: dict[str, set[str]]) -> dict[str, set[str]]:
    """Names a `for` loop binds from a module-level literal table.

    Keyed per name, so two loops over two different tables in one file cannot
    contaminate each other's environment.
    """
    env: dict[str, set[str]] = {}
    for child in ast.walk(tree):
        if not isinstance(child, ast.For) or child.target is None:
            continue
        values = tables.get(_iterated_name(child.iter))
        if not values:
            continue
        target = child.target
        names = (
            [target]
            if isinstance(target, ast.Name)
            else [element for element in getattr(target, "elts", []) if isinstance(element, ast.Name)]
        )
        for name in names:
            env.setdefault(name.id, set()).update(values)
    return env


def _callee_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    return getattr(func, "attr", "")


def _functions(tree: ast.Module) -> dict[str, list[ast.FunctionDef]]:
    """Function definitions by name, plus the module-level loop environment.

    Name-keyed, so it is scope-blind: a shadowed name merges two definitions.
    That over-approximates -- it can admit a path the file never really requests
    -- and it can never drop one, so it cannot turn a genuinely unsupported row
    into a supported one. That asymmetry is the safe direction: the failure mode
    is a missed defect, not an invented one.
    """
    functions: dict[str, list[ast.FunctionDef]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, []).append(node)
    return functions


def _parameters(node: ast.FunctionDef) -> list[str]:
    """Every parameter name, positional then keyword-only.

    Keyword-only parameters are included: scripts/test_activity_receipts_service.py
    declares `def request(path, *, cookie=None, csrf=None, body=None)`, and the
    whole question there is whether `body` was supplied, because the sink reads
    `method="POST" if body is not None else "GET"`. Leaving the kwonly names out
    made every one of those verbs undecidable.
    """
    return [argument.arg for argument in node.args.posonlyargs + node.args.args]


def _keyword_only(node: ast.FunctionDef) -> list[str]:
    return [argument.arg for argument in node.args.kwonlyargs]


# Marker for "this parameter was not supplied and its default is None". Kept
# distinct from any string a test could pass, so `_single` can tell an absent
# body from a supplied one when it decides a conditional verb.
_NULL = "\x01null\x01"


def _is_null_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _call_arguments(
    site: ast.Call, function: ast.FunctionDef, literals: dict[str, Any] | None = None
) -> dict[str, set[str]] | None:
    """Bind a function's parameters from one call site's arguments.

    Returns None only when the binding itself is untrustworthy: more arguments
    than parameters (`*args`), or a `**kwargs` spread whose positions cannot be
    known. A single NON-LITERAL argument does not abort the binding -- that was
    a real bug: `request(connection, headers, "credential", body)` passes two
    non-literals before the literal that carries the path, and rejecting the
    whole call lost the evidence and reported a correct live test as
    unsupported. A parameter whose argument is not a literal is simply left
    unbound, and an unbound name becomes a hole, which the matcher refuses.

    An unsupplied parameter takes its declared default, so
    `def request(path, *, body=None)` called without `body` binds body to a
    null marker and a `method="POST" if body is not None else "GET"` sink
    resolves to GET. That default binding is the whole reason
    get-instance-activity resolves at all.
    """
    parameters = _parameters(function)
    if len(site.args) > len(parameters):
        return None
    bound: dict[str, set[str]] = {}
    for index, argument in enumerate(site.args):
        values = _string_values(argument)
        if values is not None:
            bound[parameters[index]] = values
        elif _is_null_literal(argument):
            bound[parameters[index]] = {_NULL}
        else:
            # A subscript ARGUMENT -- `request(path, prepared["result"]["run"]
            # ["runId"])` -- binds only through a provable literal. A live
            # response subscript stays unbound, which leaves a hole, which the
            # matcher refuses: the conservative refusal is the default here too.
            proven = _subscript_string(argument, literals) if literals else None
            if proven is not None:
                bound[parameters[index]] = {proven}
    for keyword in site.keywords:
        if keyword.arg is None:
            return None
        values = _string_values(keyword.value)
        if values is not None:
            bound[keyword.arg] = values
        elif _is_null_literal(keyword.value):
            bound[keyword.arg] = {_NULL}
        else:
            proven = _subscript_string(keyword.value, literals) if literals else None
            if proven is not None:
                bound[keyword.arg] = {proven}
    for parameter in _keyword_only(function):
        if parameter in bound:
            continue
        default = _default_of(function, parameter)
        if default is None:
            continue
        values = _string_values(default)
        if values is not None:
            bound[parameter] = values
        elif _is_null_literal(default):
            bound[parameter] = {_NULL}
    return bound


def _default_of(function: ast.FunctionDef, parameter: str) -> ast.AST | None:
    """The declared default expression for a parameter, when it has one."""
    positional = function.args.posonlyargs + function.args.args
    for index, argument in enumerate(positional):
        if argument.arg == parameter:
            offset = len(positional) - len(function.args.defaults)
            if index >= offset:
                return function.args.defaults[index - offset]
    for argument, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
        if argument.arg == parameter:
            return default
    return None


def _is_request_sink(
    call: ast.Call,
    functions: dict[str, list[ast.FunctionDef]],
    seen: frozenset[str] = frozenset(),
) -> bool:
    """Whether a call reaches the network.

    True for a transport primitive, and for any call to a function defined in
    this file that ITSELF contains such a call. Transitive through the call
    graph, which is what lets `post_lifecycle(...)` be recognised as a request
    even though it never names a transport.

    `seen` breaks cycles. Recursion is real in these files -- a request helper
    calls another helper, and at least one file has a helper reachable from
    itself -- and without the guard this raised RecursionError, which the
    caller's broad `except` then converted into "unanalysable", silently
    emptying the measurement for that file. A bounded walk that cannot
    loop is required, not defensive.
    """
    name = _callee_name(call)
    # An ATTRIBUTE call named `request`/`get`/`post` is the http.client or
    # requests style, not a call of a local helper that happens to share the
    # name. Treating it as a local function was a real bug: in
    # scripts/test_provider_setup.py the helper is `def request(...)` and the
    # transport is `connection.request(...)`, so the sink was matched against
    # the helper's own definition, found no transport inside it, and the row was
    # then reported unsupported -- a false accusation against a correct test.
    if isinstance(call.func, ast.Attribute):
        return name in _TRANSPORT_NAMES
    if name in _TRANSPORT_NAMES and name not in functions:
        return True
    if name not in functions or name in seen:
        return False
    nested = seen | {name}
    return any(
        _is_request_sink(inner, functions, nested)
        for definition in functions[name]
        for inner in ast.walk(definition)
        if isinstance(inner, ast.Call)
    )


def _sink_verb(call: ast.Call, env: dict[str, set[str]], assignments: dict[str, ast.AST]) -> set[str]:
    """The verbs a request call can issue, resolved through `env`.

    A conditional IS resolved when the name it tests on is bound. That is the
    whole point of carrying an environment: `method="POST" if body is not None
    else "GET"` is decided by whether the call site passed a body, and
    `method = 'GET' if action == 'status' else 'POST'` is decided by which
    action the call site passed. Reading only the sink -- what a grep or a
    naive parse does -- leaves both undecided and the row unresolved.

    `assignments` resolves the `method = <expr>` local-then-passed shape, which
    is what scripts/test_provider_setup.py does before calling
    `connection.request(method, ...)`.
    """
    for keyword in call.keywords:
        if keyword.arg == "method":
            return _verb_of(keyword.value, env, assignments)
    name = _callee_name(call)
    if name == "request" and call.args:
        return _verb_of(call.args[0], env, assignments)
    if name in {"get", "head", "delete", "options"}:
        return {name.upper()}
    if name in {"post", "put", "patch"}:
        return {name.upper()}
    if name == "urlopen" and call.args and not any(k.arg == "method" for k in call.keywords):
        argument = call.args[0]
        # `urlopen(Request(url, method=<expr>))`: the verb lives on the inner
        # Request, not on urlopen. Reading only the outer call is what left
        # get-instance-activity's verb unresolved even though its
        # `method="POST" if body is not None else "GET"` was right there and
        # decidable from the call site.
        if isinstance(argument, ast.Call) and _callee_name(argument) == "Request":
            return _verb_of_argument(argument, env, assignments)
        if isinstance(argument, ast.Name):
            binding = assignments.get(argument.id)
            if isinstance(binding, ast.Call) and _callee_name(binding) == "Request":
                return _verb_of_argument(binding, env, assignments)
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            return {"GET"}
        if isinstance(argument, ast.JoinedStr) and not any(
            isinstance(value, ast.FormattedValue) for value in argument.values
        ):
            return {"GET"}
    return set()


def _verb_of_argument(
    request: ast.Call, env: dict[str, set[str]], assignments: dict[str, ast.AST]
) -> set[str]:
    """The verb on a `Request(...)` call's `method=` argument."""
    for keyword in request.keywords:
        if keyword.arg == "method":
            return _verb_of(keyword.value, env, assignments)
    return set()


def _verb_of(node: ast.AST, env: dict[str, set[str]], assignments: dict[str, ast.AST]) -> set[str]:
    """The verbs one `method` expression can issue, given the call environment."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        verb = node.value.upper()
        return {verb} if verb in _HTTP_VERBS else set()
    if isinstance(node, ast.IfExp):
        decided = _decide(node.test, env)
        if decided is True:
            return _verb_of(node.body, env, assignments)
        if decided is False:
            return _verb_of(node.orelse, env, assignments)
        return set()
    if isinstance(node, ast.Name):
        values = env.get(node.id)
        if values and len(values) == 1:
            only = next(iter(values))
            if only.upper() in _HTTP_VERBS:
                return {only.upper()}
        bound = assignments.get(node.id)
        if bound is not None:
            return _verb_of(bound, env, assignments)
        return set()
    if isinstance(node, ast.Attribute):
        return {node.attr.upper()} if node.attr.upper() in _HTTP_VERBS else set()
    return set()


def _decide(node: ast.AST, env: dict[str, set[str]]) -> bool | None:
    """Evaluate a simple conditional against bound names, or return None.

    Handles `x == 'lit'`, `x != 'lit'`, `x is not None`, `x is None` and their
    negations -- the forms these tests actually use to pick a verb. Anything
    else returns None, which leaves the verb unresolved rather than guessed.
    """
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = _decide(node.operand, env)
        return None if inner is None else not inner
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    operator = node.ops[0]
    left = _single(node.left, env)
    right = _single(node.comparators[0], env)
    if left is _UNBOUND or right is _UNBOUND:
        return None
    if isinstance(operator, ast.Is):
        return left is right or left == right
    if isinstance(operator, ast.IsNot):
        return not (left is right or left == right)
    if isinstance(operator, ast.Eq):
        return left == right
    if isinstance(operator, ast.NotEq):
        return left != right
    return None


class _Unbound:
    """Sentinel for a name this resolver could not bind to a single value."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<unbound>"


_UNBOUND = _Unbound()


def _single(node: ast.AST, env: dict[str, set[str]]) -> object:
    """One known value for a node, or _UNBOUND.

    The null marker becomes Python's None here so that `body is not None`
    evaluates the way it reads. Every other bound value is a string.
    """
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        values = env.get(node.id)
        if values and len(values) == 1:
            only = next(iter(values))
            if not _contains_hole(only):
                return None if only == _NULL else only
    return _UNBOUND


def _resolve_test_citations(path: Path) -> tuple[set[tuple[str, frozenset[str]]], bool]:
    """Resolve the requests a test file actually makes, by AST.

    Returns (pairs, analysable). `analysable` is False for a file that is not
    Python or did not parse, and every row citing such a file is then reported
    `unresolved` -- never `unsupported`. That asymmetry is the safety property
    of this whole metric: the resolver's own blindness can never be published
    as a defect in a correct test.
    """
    if path.suffix != ".py":
        return set(), False
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError, ValueError):
        return set(), False

    tables = _module_tables(tree)
    functions = _functions(tree)
    assignments = _local_assignments(tree)
    # Provenance-limited literals for subscript expansion. Computed once per file
    # and threaded read-only; see the SUBSCRIPT-BOUND PATH PARAMETERS block above
    # for why each refusal exists.
    literals = _provable_literals(tree, assignments)
    module_env: dict[str, set[str]] = dict(tables)
    module_env.update(_loop_env(tree, tables))
    pairs: set[tuple[str, frozenset[str]]] = set()

    # Every call in the file, with the environment its enclosing function
    # supplies. A helper's parameters are bound from ITS call sites, which is
    # the step that makes `post_lifecycle(..., "export", ...)` resolve.
    for enclosing, node in _sinks_in(tree, functions):
        name = _callee_name(node)
        for env in _environments_for(
            node, name, enclosing, functions, module_env, tree, assignments, literals
        ):
            paths = _paths_at(node, env, assignments, literals)
            verbs = frozenset(_sink_verb(node, env, assignments))
            for resolved in paths:
                pairs.add((resolved, verbs))
    return pairs, True


def _sinks_in(
    tree: ast.Module, functions: dict[str, list[ast.FunctionDef]]
) -> list[tuple[ast.FunctionDef | None, ast.Call]]:
    """Every request sink, paired with the function that CONTAINS it.

    The enclosing function is what must be bound, and getting this wrong was the
    last real defect: the sink `connection.request(method, f'/v1/provider/{action}')`
    sits inside `def request(connection, headers, action, body)`, so the
    parameter carrying the route is `action` of the CONTAINING helper. Binding
    the sink's own callee name instead bound nothing, the `{action}` hole never
    filled, and a correct live test was reported unsupported.
    """
    found: list[tuple[ast.FunctionDef | None, ast.Call]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_request_sink(node, functions):
            found.append((_enclosing_function(tree, node), node))
    return found


def _binding_scopes(
    tree: ast.Module, enclosing: ast.FunctionDef, name: str
) -> list[ast.AST]:
    """Scopes that may contain the calls binding `enclosing`'s parameters.

    Nearest-first: the parent function that lexically contains the helper, then
    the module. A nested helper is called by the function it is written inside,
    so that parent is where its arguments live. If nothing there calls it, the
    module is the fallback, and the same-name filter in _call_sites keeps other
    definitions' bodies out of the binding.
    """
    scopes: list[ast.AST] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node is enclosing:
            continue
        if any(inner is enclosing for inner in ast.walk(node)):
            scopes.append(node)
    scopes.sort(key=lambda scope: len(list(ast.walk(scope))))
    scopes.append(tree)
    return scopes


def _enclosing_function(tree: ast.Module, target: ast.Call) -> ast.FunctionDef | None:
    """The innermost function definition containing `target`, if any."""
    best: ast.FunctionDef | None = None
    best_size = -1
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        contained = [inner for inner in ast.walk(node) if inner is target]
        if not contained:
            continue
        size = len(list(ast.walk(node)))
        if best_size == -1 or size < best_size:
            best = node
            best_size = size
    return best


def _environments_for(
    node: ast.Call,
    name: str,
    enclosing: ast.FunctionDef | None,
    functions: dict[str, list[ast.FunctionDef]],
    module_env: dict[str, set[str]],
    tree: ast.Module,
    assignments: dict[str, ast.AST],
    literals: dict[str, Any] | None = None,
) -> list[dict[str, set[str]]]:
    """Environments under which one sink call may issue a request.

    For a call to a helper defined in the file, one environment per call site
    that binds the helper's arguments. For everything else, the module
    environment. A helper with no bindable call site yields the module
    environment unchanged, which leaves its composed path holed and therefore
    unresolved -- the honest outcome.
    """
    if isinstance(node.func, ast.Attribute) and name not in functions:
        # http.client style: the callee is a connection, not a local helper, so
        # there is no parameter to bind from call sites. The local environment
        # plus the file's own assignments is all there is, and a path that needs
        # more than that keeps its hole and lands in `unresolved`.
        merged = dict(module_env)
        merged.update(_resolved_assignments(assignments, module_env, literals))
        return [merged]
    # Otherwise fall through. An Attribute call whose name IS a local function
    # (`connection.request(...)` next to `def request(...)`) must still bind
    # from call sites: returning early there is what left
    # /v1/provider/{action} unfilled and reported a correct live test as
    # unsupported.

    # Call sites are searched inside the scope that actually CALLS the helper.
    # That scope is the sink's enclosing function's PARENT when the enclosing
    # function is itself the helper: in scripts/test_provider_setup.py the sink
    # `connection.request(method, f'/v1/provider/{action}')` sits inside
    # `def request(connection, headers, action, body)`, and the calls that bind
    # `action` live in the enclosing TEST function.
    #
    # Getting this scope wrong twice produced false accusations against correct
    # tests, and both are worth recording. A module-wide search bound the sink
    # to the `def request(method, path, body, headers)` bodies elsewhere in the
    # file -- four functions share that name -- shifting every argument by one.
    # Scoping to the sink's own function found no call sites at all, because
    # the helper does not call itself. The rule that holds in both cases: the
    # evidence for a helper is the code that CALLS it.
    environments: list[dict[str, set[str]]] = []
    if enclosing is not None:
        # The name to look up is the ENCLOSING FUNCTION's name, not the sink's
        # callee. The sink here is `Request(...)` inside
        # `def post_lifecycle(cookie, csrf, operation, ...)`, and the evidence
        # that `operation` is "export" or "clear" lives at the call sites of
        # `post_lifecycle`. Searching for "Request" instead finds nothing,
        # leaving `/v1/instances/.../conversation/{operation}` unfilled -- a
        # correct, live test reported unsupported.
        for scope in _binding_scopes(tree, enclosing, enclosing.name):
            scope_ids = {id(inner) for inner in ast.walk(scope)}
            inside = {id(inner) for inner in ast.walk(enclosing)}
            for site in _call_sites(scope, enclosing.name, enclosing):
                if id(site) in inside or id(site) not in scope_ids:
                    continue
                bound = _call_arguments(site, enclosing, literals)
                if bound is None:
                    continue
                merged = dict(module_env)
                merged.update(_resolved_assignments(assignments, module_env, literals))
                merged.update(bound)
                environments.append(merged)
    if not environments:
        merged = dict(module_env)
        merged.update(_resolved_assignments(assignments, module_env, literals))
        environments.append(merged)
    return environments


def _resolved_assignments(
    assignments: dict[str, ast.AST],
    env: dict[str, set[str]],
    literals: dict[str, Any] | None = None,
) -> dict[str, set[str]]:
    """Local assignments reduced to the strings they can hold.

    Kept SEPARATE from the call-site binding on purpose: a name assigned in the
    file and a parameter bound at a call site are different kinds of fact, and
    merging raw AST nodes into the string environment is what made the
    resolver raise TypeError on the first f-string it saw. Only names whose
    assignment is a literal are reduced; the rest stay absent, so a composed
    path that depends on them keeps its hole.

    The provable-literal structures are consulted LAST and only through
    _subscript_string, so a name whose own RHS is a literal keeps being reduced
    by the original rule. That ordering is what keeps this change from moving any
    row that was already classified: a provable value reaches a path only by way
    of a subscript, which is the case that previously produced no value at all.
    """
    reduced: dict[str, set[str]] = {}
    for name, value in assignments.items():
        literal = _string_values(value)
        if literal:
            reduced[name] = literal
            continue
        composed = _composed(value, env, literals)
        if composed is not None and not _contains_hole(composed):
            reduced[name] = {composed}
    return reduced


def _call_sites(
    tree: ast.Module, name: str, function: ast.FunctionDef | None = None
) -> list[ast.Call]:
    """Bare-name call sites of `name` in the module.

    Walked from the module root so a call in a sibling test function is found.
    That is the normal shape: a helper is defined once and called from several
    tests, and EACH call site carries different path evidence, which is
    precisely what binds `post_lifecycle(..., "export", ...)`.

    When `function` is given, only sites that could reach THAT definition are
    returned. This is not a refinement for its own sake: four different
    functions named `request` exist in scripts/test_provider_setup.py with
    different signatures, and binding all their call sites to one signature
    shifted every parameter by one -- `action` picked up the site''s `method`
    argument, so the composed `/v1/provider/{action}` resolved to nothing and a
    correct test was reported unsupported. A name collision must not silently
    redistribute arguments.
    """
    if function is None:
        return [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == name
        ]
    arity = len(_parameters(function))
    has_varargs = bool(function.args.vararg or function.args.kwarg)
    # A call sitting INSIDE another function that shares this name belongs to
    # that other function's body, not to this signature. Without this filter
    # the four `request` definitions in scripts/test_provider_setup.py still
    # cross-contaminated: sites from the `def request(method, path, body,
    # headers)` bodies were bound to the `def request(connection, headers,
    # action, body)` signature, shifting every argument by one and resolving
    # `{action}` to a verb. Same-name functions are common in a long test file;
    # they must not redistribute each other's arguments.
    shadowed: set[int] = set()
    for other in ast.walk(tree):
        if (
            isinstance(other, (ast.FunctionDef, ast.AsyncFunctionDef))
            and other.name == name
            and other is not function
        ):
            shadowed.update(id(inner) for inner in ast.walk(other))
    sites: list[ast.Call] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name):
            continue
        if id(node) in shadowed:
            continue
        if has_varargs:
            sites.append(node)
            continue
        # A call is a candidate for this definition when its argument count
        # cannot belong to a different signature. A count that fits neither is
        # skipped rather than bound wrongly.
        if len(node.args) <= arity and all(keyword.arg is not None for keyword in node.keywords):
            sites.append(node)
    return sites


def _paths_at(
    call: ast.Call,
    env: dict[str, set[str]],
    assignments: dict[str, ast.AST],
    literals: dict[str, Any] | None = None,
) -> set[str]:
    """Every path one sink call may issue under one environment.

    Covers the transport shape (path as the first argument), the http.client
    shape (`connection.request(verb, path, ...)`), and the helper shape (the
    path is whatever the bound environment says the argument is).
    """
    name = _callee_name(call)
    candidates: list[ast.AST] = []
    if name == "request" and len(call.args) >= 2:
        candidates.append(call.args[1])
    elif name == "Request" and call.args:
        candidates.append(call.args[0])
    elif name == "urlopen" and call.args:
        argument = call.args[0]
        if isinstance(argument, ast.Name):
            # `with urlopen(request)` where `request = Request(...)` above:
            # follow the local binding to the Request's own URL argument.
            binding = assignments.get(argument.id)
            if isinstance(binding, ast.Call) and _callee_name(binding) == "Request" and binding.args:
                candidates.append(binding.args[0])
        else:
            candidates.append(argument)
    elif call.args:
        candidates.append(call.args[0])

    paths: set[str] = set()
    for candidate in candidates:
        composed = _composed(candidate, env, literals)
        if composed is None:
            continue
        for variant in _expand(composed, env):
            paths.add(_strip_origin(variant))
    return paths


def _expand(composed: str, env: dict[str, set[str]]) -> set[str]:
    """Expand a composed path, substituting each hole with ITS OWN values.

    Holes are filled INDEPENDENTLY, not all-or-nothing. A path that composes a
    runtime port and a call-site route has two holes and only one of them is
    knowable; an earlier version returned the whole composition unchanged as
    soon as one hole was unfillable, so
    `f"...:{port}/v1/instances/.../{operation}"` never resolved `operation` and
    a correct live test was reported unsupported.

    Unfilled holes keep their sentinel, and _path_matches refuses any string
    holding one -- so a partial expansion is safe: it can confirm a route it
    fully determines and can never confirm one it does not.
    """
    if _HOLE_CHAR not in composed:
        return {composed}
    start = composed.index(_HOLE_CHAR)
    end = composed.find(_HOLE_END, start)
    if end == -1:
        return {composed.replace(_HOLE_CHAR, _HOLE_KEEP)}
    name = composed[start + 1 : end]
    usable = {value for value in env.get(name, set()) if value and not _is_hole(value)}
    if not usable:
        # Leave this piece unresolved but keep the surrounding text intact, so
        # the OTHER holes in the same path can still be filled. Replacing the
        # whole hole token with a sentinel also preserves the following '/',
        # which a text-level substitution of the hole's own contents once ate.
        return _expand(composed[:start] + _HOLE_KEEP + composed[end + 1 :], env)
    expanded: set[str] = set()
    for value in usable:
        expanded |= _expand(composed[:start] + value + composed[end + 1 :], env)
    return expanded


def _local_assignments(tree: ast.Module) -> dict[str, ast.AST]:
    """Local name -> last assigned value node.

    Needed for the `request = Request(...)` then `urlopen(request)` shape. A
    name assigned more than once keeps the last binding, which is the reading a
    reader would take; where that is wrong the path stays unresolved or is
    mis-resolved, never silently dropped.
    """
    assigned: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                assigned[node.target.id] = node.value
    return assigned


# ---------------------------------------------------------------------------
# SUBSCRIPT-BOUND PATH PARAMETERS
#
# A path parameter bound to a subscript -- `run_id = prepared["result"]["run"]
# ["runId"]` -- used to leave the whole composed path unresolvable, so a row the
# cited test really does exercise was reported `unsupported`, a confident false
# accusation. The defect is real and it is gated on a PATH PARAMETER, which is
# why it blocks a whole /v1/runs/{runId} cluster at once.
#
# THE RULE, WHICH IS A REFUSAL AND NOT AN EXPANSION. A subscript may be filled
# only when its value is PROVABLY a literal written in that same test: a dict,
# list or tuple literal, or a `json.loads` of a string constant, with EVERY
# value inside it written out in the source too. Anything else -- a live
# response, a helper call, a name from another module, a value that merely looks
# like a literal -- yields None, the segment keeps its hole, and the row lands in
# `unresolved`. Never a guess, never a same-named symbol from elsewhere, never a
# prefix match. This resolver already shipped a bug that filled anonymous holes
# from an unrelated module table and INVENTED routes; a metric that fabricates
# evidence is worse than no metric, because it converts an honest unknown into a
# false assurance. On this corpus the honest answer is that almost none of these
# ids are provable: they are server-generated, and the test never writes them
# down. `unresolved` is the correct landing for those, not `unsupported` and
# emphatically not `supported`.
# ---------------------------------------------------------------------------

# Sentinel for "this structure is not a pure literal". A bare object() would do,
# but a named one reads unambiguously at every use site.
_NOT_LITERAL = object()

# Depth cap for the literal walk. These fixtures are shallow, and an unbounded
# recursive descent over parsed source is not a risk worth taking for a metric.
_LITERAL_DEPTH = 12


def _target_names(target: ast.AST) -> list[str]:
    """Every plain name a binding target introduces."""
    if isinstance(target, ast.Name):
        return [target.id]
    return [
        element.id
        for element in getattr(target, "elts", [])
        if isinstance(element, ast.Name)
    ]


def _bound_names(tree: ast.Module) -> dict[str, int]:
    """How many times each name is bound, by any construct that rebinds.

    Assignments, augmented assignments, `for` targets and comprehension targets
    all count. A name bound more than once is REFUSED by _provable_literals:
    `_local_assignments` keeps the last binding, which is the right reading for
    the `request = Request(...)` shape and the wrong one for a literal, because
    the last binding is not necessarily the value in force where the path is
    composed. Refusing the name leaves the choice unmade rather than made for the
    test.
    """
    counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.AST] = list(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            targets = [node.target]
        elif isinstance(node, ast.comprehension):
            targets = [node.target]
        else:
            continue
        for target in targets:
            for name in _target_names(target):
                counts[name] = counts.get(name, 0) + 1
    return counts


def _parameter_names(tree: ast.Module) -> set[str]:
    """Every parameter name declared anywhere in the file."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        arguments = node.args
        candidates = [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        ]
        for argument in candidates:
            if argument is not None:
                names.add(argument.arg)
    return names


def _literal_value(node: ast.AST, depth: int = 0) -> Any:
    """A pure-literal structure as plain Python, or `_NOT_LITERAL`.

    Every leaf must be a source-level constant. A single Call, Name or Attribute
    ANYWHERE inside refuses the WHOLE structure rather than half of it, which is
    what keeps `service = {"origin": origin, "port": port}` out: it looks like a
    literal and is not one, and resolving the string key would fabricate a
    segment the test never wrote down. `json.loads("<literal>")` is the one call
    accepted, because the whole document is in the source as a string.
    """
    if depth > _LITERAL_DEPTH:
        return _NOT_LITERAL
    if isinstance(node, ast.Constant) and isinstance(
        node.value, (str, int, float, bool, type(None))
    ):
        return node.value
    if isinstance(node, ast.Dict):
        resolved_map: dict[str, Any] = {}
        for key, value in zip(node.keys, node.values):
            if key is None:
                return _NOT_LITERAL  # a `**spread` key has no literal name
            if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                return _NOT_LITERAL
            resolved = _literal_value(value, depth + 1)
            if resolved is _NOT_LITERAL:
                return _NOT_LITERAL
            resolved_map[key.value] = resolved
        return resolved_map
    if isinstance(node, (ast.List, ast.Tuple)):
        resolved_items: list[Any] = []
        for element in node.elts:
            resolved = _literal_value(element, depth + 1)
            if resolved is _NOT_LITERAL:
                return _NOT_LITERAL
            resolved_items.append(resolved)
        return resolved_items if isinstance(node, ast.List) else tuple(resolved_items)
    if (
        isinstance(node, ast.Call)
        and not node.keywords
        and node.args
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "json"
        and node.func.attr == "loads"
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        try:
            return json.loads(node.args[0].value)
        except ValueError:
            return _NOT_LITERAL
    return _NOT_LITERAL


def _provable_literals(tree: ast.Module, assignments: dict[str, ast.AST]) -> dict[str, Any]:
    """Local names whose value is a pure literal, provable from this file alone.

    Three refusals, each closing a way this resolver has already lied:

      * a name bound more than once, because the last binding is a choice the
        resolver would be making on the test's behalf;
      * a name that is a parameter of any function, because a same-named literal
        is exactly how a hole gets filled from an unrelated scope -- the bug this
        metric already shipped, which invented /v1/provider/costTelemetry;
      * any structure containing a Call, which is what a live response looks
        like, and which is the ordinary case for these run/grant/route ids.

    What survives is a value written out in the source, so filling a path segment
    from it is reading the test rather than guessing at it. Only dict/list/tuple
    tops are kept: a plain string local is already handled by _string_values, and
    reusing that path keeps this change from altering any row that was already
    being resolved.
    """
    counts = _bound_names(tree)
    parameters = _parameter_names(tree)
    literals: dict[str, Any] = {}
    for name, value in assignments.items():
        if name in parameters or counts.get(name, 0) != 1:
            continue
        resolved = _literal_value(value)
        if resolved is _NOT_LITERAL or not isinstance(resolved, (dict, list, tuple)):
            continue
        literals[name] = resolved
    return literals


def _subscript_string(node: ast.AST, literals: dict[str, Any]) -> str | None:
    """The literal string a subscript expression provably yields, or None.

    Walks `base[key][key2]` back to a name bound to a provable literal and then
    forward one real key at a time. Every step must land on a key that is
    actually present in a structure that came out of the source text; a step that
    cannot is None. A dict key is a string, a sequence index is a non-negative
    int, and nothing else is accepted, so a computed or dynamic key refuses
    instead of guessing. There is no fallback of any kind.
    """
    if not isinstance(node, ast.Subscript) or not literals:
        return None
    base: ast.AST = node.value
    while isinstance(base, ast.Subscript):
        base = base.value
    if not isinstance(base, ast.Name):
        return None
    current: Any = literals.get(base.id, _NOT_LITERAL)
    if current is _NOT_LITERAL:
        return None
    keys: list[Any] = []
    step: ast.AST = node
    while isinstance(step, ast.Subscript):
        key = step.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, (str, int)) and not isinstance(
            key.value, bool
        ):
            keys.append(key.value)
        else:
            return None
        step = step.value
    for key in reversed(keys):
        if isinstance(current, dict) and isinstance(key, str) and key in current:
            current = current[key]
            continue
        if (
            isinstance(current, (list, tuple))
            and isinstance(key, int)
            and not isinstance(key, bool)
            and 0 <= key < len(current)
        ):
            current = current[key]
            continue
        return None
    return current if isinstance(current, str) else None


def _hole_path_matches(resolved: str, declared_path: str) -> bool:
    """Whether a path the resolver could only PARTLY resolve has this shape.

    A declared `{name}` wildcard and an unfilled hole are the same kind of
    statement -- one segment whose value was not determined -- so they compare
    under one segment-wise rule, and the rule is the one _path_matches already
    uses: equal segment count, wildcard on either side standing for exactly one
    segment, and no hole wide enough to swallow a separator.

    The difference is the ANSWER, and it is the whole point. A path that matches
    only this way is reported `unresolved`: the route is demonstrably in the cited
    file, and the segment's value is not provable from it. It is never
    `supported` -- a hole can confirm nothing, by construction -- and never
    `unsupported`, because calling a test that exercises the route a defect is
    the false accusation this whole change exists to remove.
    """
    if not _is_hole(resolved):
        return False
    test_segments = [segment for segment in resolved.split("/") if segment]
    declared_segments = [segment for segment in declared_path.split("/") if segment]
    if len(test_segments) != len(declared_segments):
        return False
    return all(
        _is_hole(test) or _is_template_segment(declared) or test == declared
        for test, declared in zip(test_segments, declared_segments)
    )


def _citation_measurement(items: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Partition manifest rows by whether the cited test exercises them.

    A row declaring both `path` and `method` -- the apiOperations -- becomes
    one of:

      supported    the cited file was analysed AND a resolved request in it
                   matches this row's path with a resolved verb
      unresolved   anything uncertain: the citation is not Python, it did not
                   parse, a path stayed composed, or the verb was conditional.
                   A path match with an unresolved verb is ALSO unresolved: the
                   route is present but the method was not confirmed.
      unsupported  the file was analysed and NO resolved request matches. Only
                   reachable for a file this resolver actually read end to end.

    Rows declaring no path+method pair (uiRoutes, userControls, capabilities,
    legacyAliases) are not counted anywhere: the question does not apply to
    them, and calling them unsupported would be inventing a claim.
    """
    supported: list[str] = []
    unsupported: list[str] = []
    unresolved: list[str] = []
    cache: dict[str, tuple[set[tuple[str, frozenset[str]]], bool]] = {}

    for item in items:
        identifier = str(item.get("id", ""))
        declared_path = item.get("path")
        declared_method = item.get("method")
        if not isinstance(declared_path, str) or not isinstance(declared_method, str):
            continue
        relative = str(item.get("test", ""))
        if relative not in cache:
            try:
                cache[relative] = _resolve_test_citations(ROOT / relative)
            except Exception:  # noqa: BLE001 - a measurement must never break validation
                cache[relative] = (set(), False)
        pairs, analysable = cache[relative]
        if not analysable:
            unresolved.append(identifier)
            continue
        wanted = declared_method.upper()
        path_hits = [verbs for path, verbs in pairs if _path_matches(path, declared_path)]
        if not path_hits:
            # No fully-resolved request matches. Before calling that a defect,
            # ask whether the file composes this route SHAPE with the segment
            # still unfilled. If it does, the route is in the file and only the
            # value is unprovable, which is an unknown -- not an accusation, and
            # never a confirmation. A hole can never produce `supported` here,
            # because this branch is only reached when no resolved path matched.
            if any(_hole_path_matches(path, declared_path) for path, _ in pairs):
                unresolved.append(identifier)
            else:
                unsupported.append(identifier)
        elif any(wanted in verbs for verbs in path_hits):
            supported.append(identifier)
        else:
            # The route appears but the verb was conditional or absent, so this
            # is an unknown, not a defect and not a confirmation.
            unresolved.append(identifier)
    return {
        "supported": supported,
        "unsupported": unsupported,
        "unresolved": unresolved,
    }

# ── EXPRESSION CENSUS ────────────────────────────────────────────────────────
# This block answers a DIFFERENT question from every counter above, and the
# difference is the point. `_check_preservation_item` reads each row's literal
# against the PRODUCT file and only checks the cited test RESOLVES; the whole
# DECLARED/undeclared partition is about whether a row names a data-testid
# identity. None of that says whether the row's pinned BEHAVIOUR is expressed
# anywhere in the test population. This census is the first signal this gate has
# for that question, and it is REPORTED, never refused, and never called
# coverage. It classifies each preservation row as `expressed_in_a_test` (a
# behaviour handle derived from the row's literal is referenced in some test) or
# `expressed_nowhere` (no such handle is referenced anywhere). The five-row
# `expressed_nowhere` set is the honest "behaviour really unexercised" group; the
# `expressed_in_a_test` rows are recognised as exercised-by-expression so they
# are no longer lumped with the absent ones (a recall increase that does not
# change any existing figure). See evidence/.../failure-sensitivity-and-expression-census-*.md.

TEST_FILE_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("apps/web", ("*.test.ts", "*.test.tsx", "*.spec.ts", "*.spec.tsx")),
    ("scripts", ("test_*.py",)),
)

_IDENTITY_HANDLE = re.compile(
    r'(?:data-testid|testId|aria-label|label|title|description|name)\s*[=:]\s*'
    r'''(?:"([^"]+)"|'([^']+)'|`([^`]+)`)'''
)
_BACKTICK_HANDLE = re.compile(r"`([^`]*)`")
_METHOD_HANDLE = re.compile(r"\b(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(")
_HANDLER_HANDLE = re.compile(r"on[A-Za-z]+\s*=\s*\{\s*([A-Za-z_$][\w$.]*)")
_CODE_PUNCTUATION = re.compile(r"[(){}`=>:]")


def _strip_comments(text: str) -> str:
    """Drop line and block comments so a handle is not 'expressed' by a comment.

    A comment naming a control is the reason the naive substring census reports
    `aria-label="Workbench status"` as exercised: the only occurrence in the
    whole test population is a comment. Comments are removed first.
    """
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"(?m)^\s*#.*$", " ", text)
    text = re.sub(r"(?m)^\s*//.*$", " ", text)
    text = re.sub(r"\s//[^\n'\"`]*$", " ", text, flags=re.M)
    return text


def _test_population() -> dict[str, str]:
    """Repo-relative, comment-stripped contents of every test file, by pinned glob."""
    population: dict[str, str] = {}
    for base, patterns in TEST_FILE_PATTERNS:
        for pattern in patterns:
            for path in sorted((ROOT / base).rglob(pattern)):
                if not path.is_file() or path.is_symlink():
                    continue
                relative = path.relative_to(ROOT).as_posix()
                population[relative] = _strip_comments(
                    path.read_text(encoding="utf-8", errors="replace")
                )
    return population


def _behaviour_handles(literal: str) -> list[str]:
    """Behaviour handles a test could plausibly reference for this literal.

    A source-syntax literal (`aria-label="Open navigation"`, an f-string route, a
    client method) cannot match a behaviour-level assertion, so the whole
    expression is never searched; a handle is derived instead: a named identity
    value, a route prefix before `${`, a method/handler name, or -- for a bare
    natural-language string with no code punctuation -- the WHOLE string. A bare
    string is never word-split, because splitting prose is what let the word
    `inspect` inside row 8's sentence collide with unrelated tests.
    """
    found: list[str] = []
    for match in _IDENTITY_HANDLE.finditer(literal):
        found.append(next(group for group in match.groups() if group is not None))
    for match in _BACKTICK_HANDLE.finditer(literal):
        found.append(match.group(1).split("${")[0])
    if not found:
        if _CODE_PUNCTUATION.search(literal):
            match = _METHOD_HANDLE.search(literal) or _HANDLER_HANDLE.search(literal)
            if match:
                found.append(match.group(1).split(".")[-1])
        else:
            found.append(literal)
    handles: list[str] = []
    for handle in found:
        handle = handle.strip()
        for candidate in (handle, handle.rstrip("….!?").strip()):
            if candidate and candidate not in handles:
                handles.append(candidate)
    return handles


def _expressed_in_a_test(literal: str, population: dict[str, str]) -> tuple[bool, str | None]:
    """(is the behaviour expressed in any test, first matching file)."""
    for handle in _behaviour_handles(literal):
        pattern = re.compile(r"(?<![\w])" + re.escape(handle) + r"(?![\w])", re.IGNORECASE)
        for name, content in population.items():
            if pattern.search(content):
                return True, name
    return False, None


def _expression_census(
    evidence_items: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Preservation rows split by whether the pinned behaviour is expressed in a test.

    Returns (expressed, expressed_nowhere). `expressed` is a recall increase: a
    row whose behaviour a test touches through a role-and-name query, a route
    fragment or a method call is recognised as exercised, even though its exact
    manifest literal is absent. `expressed_nowhere` is the honest unexercised
    group. This is NOT a coverage claim and NOT regression verification: a
    mutation of a protected row's behaviour (measured) can still leave the
    expression signal true, so `expressed` must never be read as "a test fails if
    this breaks". Neither list feeds any existing figure; the gate's counts,
    refusals and return value are unchanged by this function.
    """
    population = _test_population()
    expressed: list[dict[str, str]] = []
    expressed_nowhere: list[dict[str, str]] = []
    for item in evidence_items:
        row = {
            "id": str(item.get("id", "")),
            "file": str(item["evidence"]["file"]),
            "contains": str(item["evidence"]["contains"]),
        }
        found, where = _expressed_in_a_test(row["contains"], population)
        if found:
            row["expressedIn"] = where or ""
            expressed.append(row)
        else:
            expressed_nowhere.append(row)
    return expressed, expressed_nowhere


def validate() -> dict[str, int]:
    manifest_path = ROOT / "config" / "functionality-preservation.v1.yaml"
    manifest = _merge_preservation_extensions(_load_yaml(manifest_path))
    schema = json.loads((ROOT / "schemas" / "functionality-preservation.v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(manifest)

    all_items = [*manifest["uiRoutes"], *manifest["userControls"], *manifest["apiOperations"], *manifest["capabilities"], *manifest["legacyAliases"]]
    identifiers = [item["id"] for item in all_items]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("functionality-preservation ids must be globally unique")
    for item in all_items:
        _check_preservation_item(item)

    _validate_router_surface(manifest)

    declared_paths = [item["path"] for item in manifest["apiOperations"]]
    service_path = ROOT / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "service_process.py"
    uncovered_service = sorted(item for item in _api_literals(service_path) if not _path_covers(item, declared_paths))
    if uncovered_service:
        raise ValueError(f"service APIs lack preservation coverage: {uncovered_service}")

    dynamic = _load_yaml(ROOT / "config" / "frontend-dynamic-preservation.v1.yaml")
    dynamic_schema = json.loads((ROOT / "schemas" / "frontend-dynamic-preservation.v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(dynamic_schema).validate(dynamic)
    dynamic_items = [*dynamic.get("controls", []), *dynamic.get("operations", []), *dynamic.get("behaviors", [])]
    dynamic_ids = [item.get("id") for item in dynamic_items if isinstance(item, dict)]
    if len(dynamic_items) != len(dynamic_ids) or any(not isinstance(item, str) or not item for item in dynamic_ids) or len(dynamic_ids) != len(set(dynamic_ids)):
        raise ValueError("dynamic frontend preservation identifiers must be unique non-empty strings")
    for item in dynamic_items:
        evidence = item.get("evidence")
        if not isinstance(evidence, dict) or set(evidence) != {"file", "contains"}:
            raise ValueError(f"dynamic frontend evidence is invalid for {item.get('id')}")
        content = _safe_repo_file(str(evidence["file"])).read_text(encoding="utf-8")
        if str(evidence["contains"]) not in content:
            raise ValueError(f"dynamic frontend evidence is stale for {item['id']}")

    # The typed client may only call manifest-covered endpoints. The governed
    # file workspace path builder is generic, so coverage is enforced at the
    # operation level: every file-workspace operation invoked by the client
    # must be a declared dynamic preservation operation.
    file_workspace_prefix = "/v1/instances/{instanceId}/file-workspace/"
    coverage = set(declared_paths)
    uncovered_frontend = sorted(
        item
        for item in _frontend_api_templates()
        if item not in coverage and not item.startswith(file_workspace_prefix)
    )
    if uncovered_frontend:
        raise ValueError(f"frontend API use lacks preservation coverage: {uncovered_frontend}")
    declared_operations = {item["operation"] for item in dynamic.get("operations", [])}
    http_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "apps" / "web" / "src" / "client" / "http").glob("*.ts"))
    )
    invoked_operations = set(re.findall(r"(?:getOperation|postOperation)\(\s*instanceId,\s*'(\w+)'", http_source))
    undeclared_operations = sorted(invoked_operations - declared_operations)
    if undeclared_operations:
        raise ValueError(f"frontend file-workspace operations lack preservation coverage: {undeclared_operations}")
    # The current readFile contract returns its exact path, content hash, Git
    # base SHA, read-only state, and encoding in one atomic response. That
    # supersedes a second readFileMetadata round trip without dropping the
    # preserved metadata outcome. Keep this equivalence explicit and narrow:
    # the operation is only covered while readFile is really invoked and the
    # typed response still validates a metadata object.
    equivalent_operations: set[str] = set()
    if "readFile" in invoked_operations and "metadata: z.object({" in http_source:
        equivalent_operations.add("readFileMetadata")
    dynamic_gap_ids = {
        item["id"]
        for item in dynamic_items
        if item["evidence"]["file"] == "docs/design/FRONTEND_FEATURE_MATRIX.md"
    }
    dynamic_gap_ids.update(
        item["id"]
        for item in dynamic.get("operations", [])
        if item["operation"] not in invoked_operations
        and item["operation"] not in equivalent_operations
    )
    # A LABEL CENSUS, NOT A COVERAGE MEASUREMENT, and the key name says so.
    # This counts manifest rows whose SELF-DECLARED status is the string "gap",
    # so it cannot see a control that exists in apps/web/src and has no manifest
    # entry at all. It was previously emitted as `surfaceGaps`, and a zero under
    # that name reads downstream as "no coverage gaps", which is a false
    # assurance: the word "container" went undeclared across all four manifests
    # while twelve operator controls already existed, and this counter was 0
    # throughout. The real coverage census is `undeclaredControls` below; which
    # population it enumerates is bounded at
    # evidence/one-line-release-001/owner-decision-brief-control-population-boundary-20260927.md.
    declared_gap_ids = {
        item["id"]
        for item in [*manifest["uiRoutes"], *manifest["userControls"], *manifest["capabilities"]]
        if item["status"] == "gap"
    }

    # THE COVERAGE CENSUS, and the check that closes the blind spot the two
    # label censuses above admit to. It enumerates control identities from the
    # shipped frontend source, not from any manifest, because a census drawn
    # from the manifest cannot see a control the manifest never mentions. Every
    # one of the undeclared controls is named with its file and the literal an
    # operator must add, because a refusal that cannot say what is missing is
    # not actionable, and because the manifest is owned by a separate lane: this
    # check is deliberately NOT satisfiable by editing the validator.
    shipped = _shipped_frontend_sources()
    undeclared = _undeclared_controls(
        shipped,
        [*all_items, *dynamic_items],
    )
    # The SAME population, partitioned rather than filtered. This computes the
    # shape of `undeclared` for reporting only: it does not remove an entry, does
    # not change what counts as undeclared, and does not feed back into the
    # figure below. The captured copy is what main() reports, so the two cannot
    # drift apart.
    global _CENSUS
    _CENSUS = {
        "sources": shipped,
        "undeclared": undeclared,
        "shapes": _control_shape_classes(shipped, undeclared),
        "declared": _uncredited_declared_controls(manifest["userControls"]),
        "declaredDynamic": _uncredited_declared_controls(dynamic_items),
        "expression": _expression_census(all_items),
    }
    # ENFORCEMENT IS DEFERRED, AND THE REASON IS A DECISION NOBODY HAS MADE YET, not a
    # softener. The figure is reported rather than refused because the POPULATION is
    # still undecided: `_is_shipped_frontend_source` is a single unversioned predicate
    # with no independent pin on its size, and a mutator that narrows it drops this
    # count from 511 to 55 with nothing else noticing. Refusing on a population whose
    # boundary has not been chosen would make this gate's verdict depend on an unmade
    # decision, in either direction. The owner brief that records the boundary as
    # undecided and unpolled is the authority for that, so the honest state today is a
    # real, visible, honestly-caveated number rather than a green tick or a red gate.
    # When the boundary is chosen, this block becomes a refusal that names each
    # undeclared control, and the name/literal pair is already computed above.

    # The citation measurement runs AFTER every existing check, and its result
    # is stored for main() to print. Position is deliberate: if it were earlier
    # it would run against a manifest state the later checks have not accepted
    # yet. It raises nothing and returns nothing into the figure set, so a bug
    # in it can only produce a wrong REPORT, never a wrong verdict.
    global _CITATIONS
    _CITATIONS = _citation_measurement(manifest["apiOperations"])

    registry = ExperienceRegistry(ROOT)
    policy = load_experience_policy(ROOT / "config" / "application-experience-policy.yaml")
    descriptors = registry.list()
    experience_schema = json.loads((ROOT / "schemas" / "application-experience.v1.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(experience_schema)
    for descriptor in descriptors:
        validator.validate(descriptor)
        resolved = registry.resolve(
            descriptor["applicationId"],
            instance_grants=policy.grants_for(descriptor["applicationId"]),
            operator_permits=policy.operator_permits,
            runtime_capabilities=policy.runtime_capabilities,
            actor_permissions=policy.permissions_for("local_user"),
        )
        if resolved is None or resolved["descriptorIdentity"]["descriptorDigest"] != resolved["installProjection"]["descriptorDigest"]:
            raise ValueError("experience resolution lacks a stable descriptor binding")
        if resolved["installProjection"]["grantsCapabilities"] is not False:
            raise ValueError("experience install projection attempted to grant capabilities")

    return {
        "descriptors": len(descriptors),
        "routes": len(manifest["uiRoutes"]),
        "controls": len(manifest["userControls"]),
        "apis": len(manifest["apiOperations"]),
        "capabilities": len(manifest["capabilities"]),
        "aliases": len(manifest["legacyAliases"]),
        "dynamicControls": len(dynamic["controls"]),
        "dynamicOperations": len(dynamic["operations"]),
        "dynamicBehaviors": len(dynamic["behaviors"]),
        "declaredGapRows": len(declared_gap_ids),
        # MEASURED, and it is the only one of these figures that is a coverage
        # measurement rather than a count of self-declared labels. It is the
        # length of the set difference between control identities found in
        # shipped apps/web/src source and control identities some manifest entry
        # pins in that same file.
        #
        # CORRECTION, same kind as the `25 of the 77` note above: this comment
        # used to claim "It is 0 here only because the check above refuses
        # otherwise, so a reader who sees 0 is reading a value that could not
        # have been printed otherwise." That sentence describes an ENFORCED
        # refusal. The refusal is DEFERRED, one comment block above, on purpose,
        # so no such guard exists, the value is 511 and not 0, and a reader who
        # sees 511 is reading a plainly reported measurement with nothing
        # refusing it. The note is corrected because it no longer describes the
        # code; the behaviour is untouched, and stays non-refusing.
        #
        # The figure is a POPULATION SIZE, not a verdict. It says how many
        # undeclared control identities the shipped source contains, and it does
        # not say whether the population should include all of them, which is the
        # owner decision recorded at
        # evidence/one-line-release-001/owner-decision-brief-control-population-boundary-20260927.md.
        # The shape breakdown main() prints alongside it describes what the 511
        # are made of; it does not reduce them.
        "undeclaredControls": len(undeclared),
        "dynamicGaps": len(dynamic_gap_ids),
    }


def _report_shapes(census: dict[str, Any], total: int) -> None:
    """Print the shape of the census alongside the census figure.

    Reporting rather than filtering is the whole point: the owner has not
    chosen the population boundary, so this describes all of the population
    instead of keeping the part that looks actionable. The partition is proven
    to be exhaustive by a test, and the `sum=` field is printed so the claim is
    checkable from the output alone rather than only from the test suite.
    """
    shapes = census["shapes"]
    counted = sum(len(values) for values in shapes.values())
    print(
        "SHAPES undeclaredControls="
        + str(total)
        + " breakdown="
        + ",".join(f"{name}:{len(shapes[name])}" for name in CONTROL_SHAPE_CLASSES)
        + f" sum={counted}"
        + f" exhaustive={counted == total}"
    )
    # The classes that are clearly NOT operator actions are listed in full,
    # because they are the ones an owner choosing a boundary needs to see by
    # name. container_or_layout is the large remainder and is sampled, with the
    # sample size stated so a reader never mistakes it for the whole class.
    for name in ("skeleton_placeholder", "non_element_reference", "component_host_unresolved"):
        values = shapes[name]
        if not values:
            continue
        print(f"SHAPES_DETAIL class={name} count={len(values)} identities=" + " ".join(values))
    containers = shapes["container_or_layout"]
    sample = min(12, len(containers))
    print(
        f"SHAPES_DETAIL class=container_or_layout count={len(containers)} "
        f"sample={sample} identities=" + " ".join(containers[:sample])
    )
    credited, uncredited = census["declared"]
    print(
        f"DECLARED userControls={len(credited) + len(uncredited)} "
        f"creditingADataTestid={len(credited)} creditingNone={len(uncredited)}"
    )
    print(
        "DECLARED_DETAIL creditingNone="
        + str(len(uncredited))
        + " entries="
        + " ".join(f"{row['id']}@{row['file']}" for row in uncredited)
    )
    dyn_credited, dyn_uncredited = census["declaredDynamic"]
    print(
        f"DECLARED dynamicEntries={len(dyn_credited) + len(dyn_uncredited)} "
        f"creditingADataTestid={len(dyn_credited)} creditingNone={len(dyn_uncredited)}"
    )
    # A separate question from every line above, and a recall increase that
    # changes none of them: is the row's pinned BEHAVIOUR expressed anywhere in
    # the test population, rather than only in the product file? The
    # `expressedNowhere` rows are the honest "behaviour really unexercised" set.
    # Neither half is coverage and neither is regression verification.
    expressed, expressed_nowhere = census["expression"]
    print(
        f"EXPRESSION rows={len(expressed) + len(expressed_nowhere)} "
        f"expressedInATest={len(expressed)} expressedNowhere={len(expressed_nowhere)}"
    )
    print(
        "EXPRESSION_DETAIL expressedNowhere="
        + str(len(expressed_nowhere))
        + " entries="
        + " ".join(row["id"] for row in expressed_nowhere)
    )


def _report_citations(measurement: dict[str, list[str]]) -> None:
    """Print the citation measurement. Reporting only; refuses nothing.

    The same shape as the SHAPES line: one summary line, then the entries in
    the two buckets a reader can act on, then the ceiling. The counts are of
    manifest ROWS, not of tests, and a row is one claim.
    """
    supported = measurement["supported"]
    unsupported = measurement["unsupported"]
    unresolved = measurement["unresolved"]
    total = len(supported) + len(unsupported) + len(unresolved)
    print(
        f"CITATIONS rows={total} supported={len(supported)} "
        f"unsupported={len(unsupported)} unresolved={len(unresolved)}"
    )
    print("CITATIONS_DETAIL unsupported=" + str(len(unsupported)) + " entries=" + " ".join(unsupported))
    print("CITATIONS_DETAIL unresolved=" + str(len(unresolved)) + " entries=" + " ".join(unresolved))
    print(
        "WHAT THE CITATIONS LINE DOES NOT ESTABLISH, AND WHAT IT IS NOT. It is a "
        "REPORT, not a gate: it refuses nothing, it changes no existing check, no "
        "published figure and no exit code, and a bug in it can only produce a wrong "
        "report, never a wrong verdict. It measures whether the cited test file "
        "CONTAINS a request to the declared route with the declared verb, and "
        "nothing about whether that request is asserted, isolated, or would fail if "
        "the route broke. A 'supported' row means the route is reachable in that "
        "file, NOT that the test is good. The 'unsupported' count is a LOWER BOUND "
        "on bad citations, not an upper bound: the resolver reads Python by AST, so "
        "a TypeScript citation (apps/web/tests/live-core.spec.ts and the two "
        "apps/web client specs) is always 'unresolved' and a defect behind one of "
        "those is invisible here. Resolution is per-name and per-scope, so a "
        "composition this walk cannot follow -- a path built from a computed "
        "expression, a dispatch table, or a value returned by another module -- "
        "leaves a hole and lands in 'unresolved' rather than 'unsupported'; that is "
        "deliberate, because the resolver's own blindness must never be published "
        "as a defect in a correct test, and an honest unknown is the only safe "
        "answer here. The three counts are of manifest ROWS, one per claim, and "
        "rows that declare no path+method pair (uiRoutes, userControls, "
        "capabilities, legacyAliases) are counted in none of them, so the three "
        "buckets do not sum to the whole manifest and must not be read as a "
        "coverage percentage over it."
    )


def main() -> int:
    counts = validate()
    print("PASS " + " ".join(f"{key}={value}" for key, value in counts.items()))
    _report_shapes(_CENSUS, counts["undeclaredControls"])
    _report_citations(_CITATIONS)
    # The gap counters are LABEL CENSUSES, not coverage measurements, and the
    # note below says so where a reader will actually see it. `undeclaredControls`
    # is the one coverage figure here. This note changes no count, no check and no
    # return value; it only stops the output from over-claiming.
    print(
        "NOTE declaredGapRows and dynamicGaps remain LABEL CENSUSES over self-declared "
        "status fields, NOT coverage: a control present in apps/web/src and absent from "
        "the manifest is invisible to both, which is how the word container went "
        "undeclared while twelve operator controls were rendered, with both counters "
        "reading 0. undeclaredControls is now the real coverage figure: it is the count "
        "of control identities found in shipped apps/web/src source that no "
        "functionality-preservation or dynamic-preservation entry declares in that same "
        "file, and each name/literal pair an operator would have to declare is already "
        "computed above. The REFUSAL IS NOT ENFORCED YET and that is deliberate: the "
        "population boundary is undecided (see the ENFORCEMENT IS DEFERRED comment at the "
        "computation), so this figure is REPORTED rather than refused, and a green run must "
        "not be read as a clean inventory. It does not establish that the "
        "population it enumerates is the population the owner wants inventoried; that "
        "boundary is undecided and recorded at "
        "evidence/one-line-release-001/owner-decision-brief-control-population-boundary-20260927.md, "
        "and it remains UNDECIDED AND UNTOUCHED by the SHAPES lines above, which partition "
        "the same population and reduce nothing. "
        # The ceiling, stated as plainly as the claims above. The SHAPES line
        # tells the owner what the 511 are made of; it does NOT tell them the
        # census is right, and these are the things it cannot establish.
        "WHAT THE SHAPES LINE DOES NOT ESTABLISH: the classes come from a LEXICAL SCAN of "
        "shipped source, not a JSX parse, so a wrong tag resolution moves an identity between "
        "classes without changing the total; container_or_layout is a sampled list, not the "
        "whole class; component_host_unresolved means the scan could not see through a "
        "third-party component (react-router Link, Radix primitives) and those identities may "
        "well be interactive, so interactive is a LOWER BOUND; and non_element_reference "
        "counts data-testid literals found in a querySelector string or a doc comment, which "
        "is why one control named drawer contributes three identities on this census. "
        "The DECLARED line does not mean the uncredited rows are wrong: _check_preservation_item "
        "still proves each is fresh evidence, but an entry anchored on prose, an aria-label or a "
        "client method names no data-testid and therefore discharges no identity, so declared "
        "rows and undeclared identities are NOT two halves of one quantity and must not be "
        "summed into a coverage percentage. A passing 0 on undeclaredControls would mean no "
        "shipped control LACKS a declaration, not that every user-facing control is one. "
        # The ceiling of the EXPRESSION line, stated where a reader will see it.
        # It is a recall increase over a literal search, NOT coverage and NOT
        # regression verification: a measured mutation of a protected row's
        # behaviour can leave this signal true, and a bare-prose row is only
        # searched whole, never word-split, precisely so a coincidence in a
        # comment cannot read as coverage.
        "The EXPRESSION line answers only whether a row's pinned behaviour is "
        "referenced by SOME test, via a derived handle; it does NOT run that test "
        "against a mutated product, so 'expressedInATest' is not regression "
        "verification and must not be summed with undeclaredControls or with the "
        "DECLARED counts. 'expressedNowhere' is a count of rows whose DERIVED "
        "HANDLE was not found by a reference search, NOT a count of untested "
        "behaviours: it is expected to be large for route-shaped apiOperations "
        "whose tests construct the route at run time, and a non-zero value here "
        "does not by itself impeach any row."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
