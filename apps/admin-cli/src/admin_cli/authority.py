"""CLI adapter for typed standing authority and action receipts."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Mapping

from governed_runner.authority import (
    AUTHORITY_MODES,
    AuthorityError,
    AuthorityManager,
    grant_template,
)


def _load_mapping(path: str) -> Mapping[str, Any]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ValueError("grant file is missing or unsafe")
    text = source.read_text(encoding="utf-8")
    try:
        if source.suffix.lower() == ".json":
            value = json.loads(text)
        else:
            import yaml

            value = yaml.safe_load(text)
    except (ImportError, OSError, UnicodeError, ValueError) as exc:
        raise ValueError("grant file could not be parsed") from exc
    if not isinstance(value, Mapping):
        raise ValueError("grant file must contain an object")
    return value


def _custom_policies(items: list[str]) -> dict[str, str]:
    policies: dict[str, str] = {}
    for item in items:
        action, separator, mode = item.partition("=")
        if not separator or not action or mode not in AUTHORITY_MODES or action in policies:
            raise ValueError("custom policies must be unique ACTION=MODE values")
        policies[action] = mode
    return policies


def _manager(args: Any) -> AuthorityManager:
    return AuthorityManager(
        Path(args.repository),
        state_root=Path(args.authority_state_root) if args.authority_state_root else None,
        policy_path=Path(args.authority_policy) if args.authority_policy else None,
    )


def _grant_from_args(manager: AuthorityManager, args: Any, *, one_time: bool = False) -> dict[str, Any]:
    action_allow = list(args.allow)
    if one_time:
        action_allow.append(args.action)
    return grant_template(
        manager,
        grant_id=args.grant_id,
        profile=args.profile,
        actor_id=args.actor_id,
        role=args.role,
        branch_pattern=args.branch_pattern,
        slice_id=args.slice_id,
        application_id=args.application_id,
        run_id=args.run_id,
        paths=args.path or ["."],
        allow=action_allow,
        require_approval=args.require_approval,
        forbid=args.forbid,
        owner_directive_id=args.owner_directive_id,
        expires_when="one_action" if one_time else args.expires_when,
        expires_at=None if one_time else args.expires_at,
        parent_grant_id=args.parent_grant_id,
        can_delegate=args.can_delegate,
        kind="one_time" if one_time else args.kind,
        custom_policies=_custom_policies(args.custom_policy),
        max_actions=1 if one_time else args.max_actions,
        max_duration_seconds=args.max_duration_seconds,
        max_cost_usd=args.max_cost_usd,
        network=args.network,
        allowed_domains=args.allowed_domain,
        providers=args.provider,
        secret_capabilities=args.secret_capability,
        deployment_sources=(
            [
                {"repositoryIdentity": identity, "projectPath": project_path}
                for identity, project_path in args.deployment_source
            ]
            if args.deployment_source
            else None
        ),
    )


def authority_cmd(args: Any) -> int:
    """Run one authority command and emit a typed JSON result."""

    try:
        manager = _manager(args)
        command = args.authority_command
        if command == "inspect":
            result = manager.inspect()
        elif command == "grant":
            grant = _grant_from_args(manager, args)
            result = manager.activate_grant(grant, owner_actor_id=args.owner_actor_id)
        elif command == "activate":
            result = manager.activate_grant(
                _load_mapping(args.grant_file),
                owner_actor_id=args.owner_actor_id,
            )
        elif command == "allow-once":
            grant = _grant_from_args(manager, args, one_time=True)
            result = manager.activate_grant(grant, owner_actor_id=args.owner_actor_id)
        elif command == "evaluate":
            result = manager.evaluate(
                args.action,
                actor_id=args.actor_id,
                grant_id=args.grant_id,
                branch=args.branch,
                slice_id=args.slice_id,
                application_id=args.application_id,
                run_id=args.run_id,
                paths=args.path,
                estimated_cost_usd=args.estimated_cost_usd,
                estimated_duration_seconds=args.estimated_duration_seconds,
                domains=args.domain,
                provider=args.provider,
                secret_capabilities=args.secret_capability,
                assurances=args.assurance,
            )
        elif command == "revoke":
            result = manager.revoke_grant(
                args.grant_id,
                actor_id=args.owner_actor_id,
                owner_directive_id=args.owner_directive_id,
                reason=args.reason,
            )
        elif command in {"pause", "resume"}:
            result = manager.set_paused(
                paused=command == "pause",
                actor_id=args.owner_actor_id,
                owner_directive_id=args.owner_directive_id,
                reason=args.reason,
            )
        elif command == "receipt":
            result = manager.get_receipt(args.receipt_id)
        elif command == "show-grant":
            result = manager.get_grant(args.grant_id)
        else:  # pragma: no cover - argparse owns this boundary
            raise ValueError(f"unsupported authority command: {command}")
    except (OSError, ValueError, AuthorityError) as exc:
        code = exc.code if isinstance(exc, AuthorityError) else "invalid_contract"
        payload: dict[str, Any] = {"ok": False, "code": code, "detail": str(exc)}
        receipt = getattr(exc, "receipt", None)
        if isinstance(receipt, Mapping):
            payload["receipt"] = dict(receipt)
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
