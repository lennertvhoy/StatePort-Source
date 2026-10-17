"""The actor permission policy and the handlers that check it must agree.

A permission a handler requires but no role holds makes that route unreachable
for everyone; a role that holds a platform permission it should not is a silent
privilege widening.  Both are caught here from the shipped sources, so a new
handler or a new grant cannot drift without a reviewed edit to this file.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
for source in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source))

from stateport_application_experience import load_experience_policy  # noqa: E402

POLICY = load_experience_policy(ROOT / "config" / "application-experience-policy.yaml")
SOURCES = sorted((ROOT / "packages").glob("*/src/**/*.py"))

# Checked by a handler, granted to no role: the route fails closed for every
# actor.  No web UI surface calls either route.  Granting one is an owner
# decision about export/purge of local state, not a drive-by edit.
UNGRANTED_ON_PURPOSE = frozenset({"platform.privacy.export", "platform.privacy.purge"})

# Granted by the policy but never checked by any handler: the grant is inert
# today.  Listed so a typo in a new grant cannot hide among them.
INERT_GRANTS = frozenset({
    "application.use", "advanced.inspect", "application.file.read", "application.file.write",
    "platform.authority.inspect",
})

_CHECKED = (
    re.compile(r"require_actor_permission\(\s*\"([a-z][a-z0-9._-]+)\"\s*\)"),
    re.compile(r"\"([a-z][a-z0-9._-]+)\"\s+(?:not\s+)?in\s+(?:self\.experience_policy\.permissions_for\([^)]*\)|actor_permissions\b|permissions\b)"),
)


# The file-workspace broker has its own ``file.read``/``file.write`` actor
# namespace; only the experience-policy namespaces are compared here.
_POLICY_NAMESPACES = ("application.", "platform.", "advanced.")


def _checked_permissions() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for path in SOURCES:
        text = path.read_text(encoding="utf-8")
        for pattern in _CHECKED:
            for match in pattern.finditer(text):
                if not match.group(1).startswith(_POLICY_NAMESPACES):
                    continue
                found.setdefault(match.group(1), []).append(path.name)
    return found


def _granted() -> frozenset[str]:
    return frozenset().union(*POLICY.actor_permissions.values())


def test_scanner_finds_the_known_handler_checks():
    checked = _checked_permissions()
    assert {"application.terminal.use", "application.cto.use", "platform.authority.mutate",
            "application.provider.manage", "application.provider.credential",
            "application.install.fixture"} <= set(checked)


def test_every_permission_a_handler_checks_is_granted_to_some_role():
    unreachable = sorted(set(_checked_permissions()) - _granted() - UNGRANTED_ON_PURPOSE)
    assert unreachable == [], f"checked by a handler but granted to no role: {unreachable}"


def test_the_ungranted_allowlist_is_not_stale():
    checked = set(_checked_permissions())
    assert UNGRANTED_ON_PURPOSE <= checked
    assert not UNGRANTED_ON_PURPOSE & _granted()


def test_every_grant_is_checked_by_a_handler_or_listed_as_inert():
    unchecked = sorted(_granted() - set(_checked_permissions()) - INERT_GRANTS)
    assert unchecked == [], f"granted but checked nowhere (typo or dead grant): {unchecked}"
    assert not INERT_GRANTS & set(_checked_permissions()), "an inert-listed grant is now checked; drop it from the list"


def test_local_user_never_holds_platform_administration():
    local = POLICY.permissions_for("local_user")
    operator = POLICY.permissions_for("platform_operator")
    assert not {item for item in local if item.startswith("platform.")}
    assert local <= operator, "local_user must never exceed platform_operator"


def test_local_user_holds_what_its_single_owner_surface_offers():
    local = POLICY.permissions_for("local_user")
    assert {"application.terminal.use", "application.cto.use", "application.install.fixture",
            "application.provider.manage", "application.provider.credential"} <= local
