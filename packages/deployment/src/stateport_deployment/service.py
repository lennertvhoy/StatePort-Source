"""StatePort deployment planner and lifecycle controller."""

from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping

from governed_runner.authority import AuthorityError, AuthorityManager

from .authority import validate_authority_decision, validate_authority_receipt
from .contracts import (
    ARCHITECTURE,
    DEPLOYMENT_SCHEMA,
    PLAN_SCHEMA,
    TARGET_ADAPTER,
    deployment_creation_changes,
    deployment_update_changes,
    plan_digest,
    validate_deployment_spec,
    validate_plan,
)
from .errors import AdapterError, DeploymentRefusal
from .inspection import (
    COMPOSE_FILES,
    CONTAINERFILES,
    DESCRIPTORS,
    assisted_runtime_contract,
    authority_source_identity,
    inspect_project,
    parse_compose_contract,
    parse_containerfile_contract,
    read_exact_source_file,
    resolve_assisted_profile,
    validate_project_declared_builds,
)
from .podman import RootlessPodmanAdapter
from .store import DeploymentStore
from .util import (
    COMMIT,
    DIGEST,
    default_state_root,
    digest_bytes,
    digest_value,
    relative_posix,
    safe_id,
    strict_mapping_document,
    timestamp,
)


PLAN_TTL_SECONDS = 3600
PYTHON_BASE = "docker.io/library/python@sha256:afe189875f1d2f9b45e287834fb9f2c273a5d59d354ae4050ab9affbf0a6ba06"
NODE_BASE = "docker.io/library/node@sha256:76789712cd1ae89a1225eac9077010d68987a423588042dac30446f502f1858c"


def _expected_material_reference(
    plan: Mapping[str, Any], service: Mapping[str, Any]
) -> str:
    if service["build"]["mode"] == "image":
        reference = service["image"]["reference"]
        if not isinstance(reference, str):
            raise DeploymentRefusal(
                "invalid_contract", "image service lacks an exact material reference"
            )
        return reference
    if service["build"]["generated"]:
        containerfile_text = plan["overlay"].get(
            service["build"]["containerfile"]
        )
        if not isinstance(containerfile_text, str):
            raise DeploymentRefusal(
                "overlay_missing",
                "generated Containerfile is absent from the exact plan overlay",
            )
    else:
        relative = relative_posix(
            service["build"]["containerfile"]
            if service["build"]["context"] == "."
            else (
                f"{service['build']['context']}/"
                f"{service['build']['containerfile']}"
            ),
            "exact source Containerfile",
            allow_dot=False,
        )
        try:
            containerfile_text = read_exact_source_file(
                plan["spec"]["source"],
                plan["sourceInventory"],
                relative,
            ).decode("utf-8")
        except UnicodeError as exc:
            raise DeploymentRefusal(
                "containerfile_unsupported",
                "exact source Containerfile is not UTF-8",
            ) from exc
    return str(
        parse_containerfile_contract(
            containerfile_text, require_runtime=False
        )["baseImage"]
    )


def _load_mapping(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise DeploymentRefusal("descriptor_invalid", f"could not parse {path.name}") from exc
    return strict_mapping_document(
        text,
        format_name="json" if path.suffix == ".json" else "yaml",
        label=path.name,
    )


def _load_exact_mapping(
    inspection: Mapping[str, Any], relative: str
) -> dict[str, Any]:
    raw = read_exact_source_file(
        inspection["source"], inspection["source"]["inventory"], relative
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise DeploymentRefusal(
            "descriptor_invalid", f"could not parse exact tracked {relative}"
        ) from exc
    return strict_mapping_document(
        text,
        format_name="json" if Path(relative).suffix == ".json" else "yaml",
        label=f"exact tracked {relative}",
    )


def _service_defaults() -> dict[str, Any]:
    return {
        "image": {"reference": None, "acceptedDigest": None},
        "resources": {"memoryLimit": "256m", "cpuLimit": 1.0, "pidsLimit": 128},
        "storage": [],
        "secrets": [],
        "environment": {"STATEPORT_DEPLOYMENT_MODE": "alpha"},
        "networks": ["internal"],
    }


def _runtime(command: list[str]) -> dict[str, Any]:
    return {
        "command": command,
        "workdir": "/app",
        "user": {"mode": "nonroot", "uid": 10001, "gid": 10001},
        "readOnlyRoot": True,
    }


def _port(port: int = 8080) -> dict[str, Any]:
    return {"name": "http", "containerPort": port, "hostAddress": "127.0.0.1", "hostPort": 0}


def _ignore_file() -> str:
    return """.git\n.env\n.env.*\nsecrets\nprivate\n__pycache__\n*.pyc\nnode_modules\ndist\nbuild\n"""


def _static_ignore_file() -> str:
    return """.git\n.env\n.env.*\nsecrets\nprivate\n__pycache__\n*.pyc\nnode_modules\n"""


def _assisted_spec(inspection: Mapping[str, Any], deployment_id: str, target: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    project = Path(inspection["project"])
    overlay: dict[str, str] = {}
    defaults = _service_defaults()
    tracked_paths = {item["path"] for item in inspection["source"]["inventory"]}
    resolution = resolve_assisted_profile(
        inspection["source"], inspection["source"]["inventory"]
    )
    profile = resolution["profile"]
    if profile is None:
        raise DeploymentRefusal(
            "assisted_profile_unsupported",
            "project does not resolve to one exact supported assisted profile",
            details={"blockers": resolution["blockers"]},
        )
    runtime_contract = assisted_runtime_contract(resolution["candidates"][0])
    command_json = json.dumps(
        runtime_contract["command"], separators=(",", ":")
    )
    if profile == "python":
        containerfile = """FROM %s
WORKDIR /app
COPY --chown=10001:10001 . /app
USER 10001:10001
CMD %s
""" % (PYTHON_BASE, command_json)
        overlay.update({"web.Containerfile": containerfile, "web.containerignore": _ignore_file()})
        service = {
            "id": "web",
            "sourcePath": ".",
            "build": {"mode": "source", "context": ".", "containerfile": "web.Containerfile", "generated": True},
            **deepcopy(defaults),
            "runtime": _runtime(runtime_contract["command"]),
            "ports": [_port()],
            "health": deepcopy(runtime_contract["health"]),
        }
        application = project.name
    elif profile == "node":
        containerfile = """FROM %s
WORKDIR /app
COPY --chown=10001:10001 . /app
USER 10001:10001
CMD %s
""" % (NODE_BASE, command_json)
        overlay.update({"web.Containerfile": containerfile, "web.containerignore": _ignore_file()})
        service = {
            "id": "web",
            "sourcePath": ".",
            "build": {"mode": "source", "context": ".", "containerfile": "web.Containerfile", "generated": True},
            **deepcopy(defaults),
            "runtime": _runtime(runtime_contract["command"]),
            "ports": [_port()],
            "health": deepcopy(runtime_contract["health"]),
        }
        application = project.name
    elif profile == "static":
        static_root = resolution["staticRoot"]
        if not isinstance(static_root, str):
            raise DeploymentRefusal(
                "assisted_profile_unsupported",
                "static profile lacks an exact tracked root",
            )
        static_root = relative_posix(static_root, "static root")
        if runtime_contract["sourcePath"] != static_root:
            raise DeploymentRefusal(
                "source_identity_mismatch",
                "static inspection and planning roots differ",
            )
        expected_index = "index.html" if static_root == "." else f"{static_root}/index.html"
        if expected_index not in tracked_paths:
            raise DeploymentRefusal(
                "source_identity_mismatch", "static root is not present in the exact tracked source"
            )
        containerfile = """FROM %s
WORKDIR /app
COPY --chown=10001:10001 . /app/
USER 10001:10001
CMD %s
""" % (PYTHON_BASE, command_json)
        overlay.update({"web.Containerfile": containerfile, "web.containerignore": _static_ignore_file()})
        service = {
            "id": "web",
            "sourcePath": static_root,
            "build": {"mode": "source", "context": static_root, "containerfile": "web.Containerfile", "generated": True},
            **deepcopy(defaults),
            "runtime": _runtime(runtime_contract["command"]),
            "ports": [_port()],
            "health": deepcopy(runtime_contract["health"]),
        }
        application = project.name
    else:
        raise DeploymentRefusal(
            "assisted_profile_unsupported",
            "project requires an exact StatePort descriptor or supported dependency-free Python, Node, or static profile",
        )
    spec = {
        "schema": DEPLOYMENT_SCHEMA,
        "metadata": {"deploymentId": deployment_id, "applicationId": deployment_id, "name": application},
        "source": {key: inspection["source"][key] for key in ("repositoryIdentity", "repositoryRoot", "projectPath", "commit", "treeDigest", "dirty", "dirtyDigest", "dirtyPolicy", "descriptorDigest")},
        "target": {"adapter": TARGET_ADAPTER, "targetId": "local", "architecture": ARCHITECTURE, "identityDigest": target["identityDigest"]},
        "services": [service],
        "networks": [{"id": "internal", "public": False}],
        "authority": {
            "grantId": None,
            "requireApproval": ["first_apply"],
            "automaticWithReceipt": ["health_check", "restart", "log_collection", "observe", "remove_runtime_preserve_data"],
        },
        "policy": {"ordinaryRemovePreservesData": True, "rollbackOnFailedHealth": True},
    }
    return validate_deployment_spec(spec), overlay


def _materialize_descriptor(
    descriptor: Mapping[str, Any],
    inspection: Mapping[str, Any],
    deployment_id: str,
    target: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    candidate = deepcopy(dict(descriptor))
    if candidate.get("schema") != DEPLOYMENT_SCHEMA:
        raise DeploymentRefusal("unsupported_schema", "StatePort deployment descriptor schema is unsupported")
    candidate["metadata"]["deploymentId"] = deployment_id
    candidate["source"] = {
        key: inspection["source"][key]
        for key in (
            "repositoryIdentity",
            "repositoryRoot",
            "projectPath",
            "commit",
            "treeDigest",
            "dirty",
            "dirtyDigest",
            "dirtyPolicy",
            "descriptorDigest",
        )
    }
    candidate["target"] = {
        "adapter": TARGET_ADAPTER,
        "targetId": "local",
        "architecture": ARCHITECTURE,
        "identityDigest": target["identityDigest"],
    }
    normalized = validate_deployment_spec(candidate)
    validate_project_declared_builds(
        normalized,
        inspection["source"],
        inspection["source"]["inventory"],
    )
    return normalized, {}


def _containerfile_spec(
    inspection: Mapping[str, Any],
    deployment_id: str,
    target: Mapping[str, Any],
    containerfile: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    try:
        text = read_exact_source_file(
            inspection["source"],
            inspection["source"]["inventory"],
            containerfile,
        ).decode("utf-8")
    except UnicodeError as exc:
        raise DeploymentRefusal(
            "containerfile_unsupported", "Containerfile must be UTF-8 text"
        ) from exc
    contract = parse_containerfile_contract(text)
    ports = [
        {
            "name": "http" if index == 1 else f"port-{index}",
            "containerPort": port,
            "hostAddress": "127.0.0.1",
            "hostPort": 0,
        }
        for index, port in enumerate(contract["ports"], 1)
    ]
    spec = {
        "schema": DEPLOYMENT_SCHEMA,
        "metadata": {
            "deploymentId": deployment_id,
            "applicationId": deployment_id,
            "name": Path(inspection["project"]).name,
        },
        "source": {
            key: inspection["source"][key]
            for key in (
                "repositoryIdentity",
                "repositoryRoot",
                "projectPath",
                "commit",
                "treeDigest",
                "dirty",
                "dirtyDigest",
                "dirtyPolicy",
                "descriptorDigest",
            )
        },
        "target": {
            "adapter": TARGET_ADAPTER,
            "targetId": "local",
            "architecture": ARCHITECTURE,
            "identityDigest": target["identityDigest"],
        },
        "services": [
            {
                "id": "app",
                "sourcePath": ".",
                "build": {
                    "mode": "source",
                    "context": ".",
                    "containerfile": containerfile,
                    "generated": False,
                },
                "image": {"reference": None, "acceptedDigest": None},
                "runtime": {
                    "command": contract["command"],
                    "workdir": contract["workdir"],
                    "user": {
                        "mode": "nonroot",
                        "uid": contract["uid"],
                        "gid": contract["gid"],
                    },
                    "readOnlyRoot": True,
                },
                "ports": ports,
                "health": contract["health"],
                "resources": {
                    "memoryLimit": "256m",
                    "cpuLimit": 1.0,
                    "pidsLimit": 128,
                },
                "storage": [],
                "secrets": [],
                "environment": {"STATEPORT_DEPLOYMENT_MODE": "alpha"},
                "networks": ["internal"],
            }
        ],
        "networks": [{"id": "internal", "public": False}],
        "authority": {
            "grantId": None,
            "requireApproval": ["first_apply"],
            "automaticWithReceipt": [
                "health_check",
                "restart",
                "log_collection",
                "observe",
                "remove_runtime_preserve_data",
            ],
        },
        "policy": {
            "ordinaryRemovePreservesData": True,
            "rollbackOnFailedHealth": True,
        },
    }
    return validate_deployment_spec(spec), {}


def _compose_spec(
    compose: Mapping[str, Any],
    inspection: Mapping[str, Any],
    deployment_id: str,
    target: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Materialize a declared Compose contract through the shared strict parser."""
    normalized = parse_compose_contract(
        compose,
        source=inspection["source"],
        inventory=inspection["source"]["inventory"],
    )
    spec = {
        "schema": DEPLOYMENT_SCHEMA,
        "metadata": {
            "deploymentId": deployment_id,
            "applicationId": deployment_id,
            "name": normalized["name"],
        },
        "source": {
            key: inspection["source"][key]
            for key in (
                "repositoryIdentity",
                "repositoryRoot",
                "projectPath",
                "commit",
                "treeDigest",
                "dirty",
                "dirtyDigest",
                "dirtyPolicy",
                "descriptorDigest",
            )
        },
        "target": {
            "adapter": TARGET_ADAPTER,
            "targetId": "local",
            "architecture": ARCHITECTURE,
            "identityDigest": target["identityDigest"],
        },
        "services": normalized["services"],
        "networks": normalized["networks"],
        "authority": {
            "grantId": None,
            "requireApproval": ["first_apply"],
            "automaticWithReceipt": [
                "health_check",
                "restart",
                "log_collection",
                "observe",
                "remove_runtime_preserve_data",
            ],
        },
        "policy": {
            "ordinaryRemovePreservesData": True,
            "rollbackOnFailedHealth": True,
        },
    }
    return validate_deployment_spec(spec), {}


class DeploymentService:
    def __init__(
        self,
        *,
        state_root: Path | str | None = None,
        adapter: RootlessPodmanAdapter | None = None,
        authority_manager: AuthorityManager | None = None,
        actor: str = "local-owner",
    ) -> None:
        self._state_root = state_root
        self._store: DeploymentStore | None = None
        self._adapter = adapter
        self._authority_manager = authority_manager
        self.actor = safe_id(actor, "actor id")

    def _verify_authority(
        self,
        decision: Mapping[str, Any] | None,
        *,
        action: str,
        deployment_id: str,
        run_id: str | None = None,
        planning_grant_id: str | None = None,
        source_identity: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._authority_manager is None:
            raise DeploymentRefusal(
                "authority_required",
                "deployment operations require the canonical authority manager",
            )
        if not isinstance(decision, Mapping):
            raise DeploymentRefusal(
                "authority_required", "a canonical reserved authority decision is required"
            )
        reference = validate_authority_decision(
            decision,
            action=action,
            actor=self.actor,
            deployment_id=deployment_id,
            grant_id=planning_grant_id,
            run_id=run_id,
            source_identity=source_identity,
        )
        try:
            reservation = self._authority_manager.claim_reserved_decision(decision)
        except AuthorityError as exc:
            raise DeploymentRefusal(
                "authority_invalid",
                "authority decision is not canonical, reserved, live, and unclaimed",
                details={"authorityCode": exc.code},
            ) from exc
        claim = reservation["claim"]
        return {
            **reference,
            "reservationId": reservation["reservationId"],
            "reservationDigest": reservation["reservationDigest"],
            "claimId": claim["claimId"],
            "claimDigest": claim["claimDigest"],
        }

    @property
    def store(self) -> DeploymentStore:
        """Create the private state store only for a stateful operation."""
        if self._store is None:
            self._store = DeploymentStore(self._state_root)
        return self._store

    @property
    def adapter(self) -> RootlessPodmanAdapter:
        """Probe adapter availability only when planning or operating runtime."""
        if self._adapter is None:
            raise DeploymentRefusal(
                "deployment_adapter_required",
                "deployment runtime effects require an explicitly configured adapter",
            )
        return self._adapter

    def _adapter_operation(
        self,
        operation_id: str,
        authority_reference: Mapping[str, Any],
    ) -> Any:
        binder = getattr(self.adapter, "bind_operation", None)
        if callable(binder):
            return binder(operation_id, authority_reference)
        return nullcontext()

    def inspect(self, project: Path | str) -> dict[str, Any]:
        return inspect_project(project)

    def assert_state_root_separate(
        self, inspection: Mapping[str, Any]
    ) -> None:
        """Require deployment evidence to be disjoint from all control roots."""

        selected = (
            Path(self._state_root)
            if self._state_root is not None
            else default_state_root()
        )
        try:
            state_root = selected.resolve(strict=False)
            source_repository_root = Path(
                inspection["source"]["repositoryRoot"]
            ).resolve(strict=True)
        except OSError as exc:
            raise DeploymentRefusal(
                "repository_identity_unknown",
                "deployment state separation could not resolve source identity",
            ) from exc

        def registered_worktrees(repository_root: Path) -> list[Path]:
            try:
                completed = subprocess.run(
                    (
                        "git",
                        "--no-replace-objects",
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-C",
                        str(repository_root),
                        "worktree",
                        "list",
                        "--porcelain",
                        "-z",
                    ),
                    check=True,
                    capture_output=True,
                    timeout=30,
                    shell=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise DeploymentRefusal(
                    "repository_identity_unknown",
                    "deployment state separation could not verify registered worktrees",
                ) from exc
            worktrees: list[Path] = []
            for field in completed.stdout.split(b"\0"):
                if not field.startswith(b"worktree "):
                    continue
                try:
                    worktrees.append(
                        Path(field[len(b"worktree ") :].decode()).resolve(
                            strict=True
                        )
                    )
                except (OSError, UnicodeError) as exc:
                    raise DeploymentRefusal(
                        "repository_identity_unknown",
                        "a registered worktree could not be identified safely",
                    ) from exc
            if not worktrees or repository_root not in worktrees:
                raise DeploymentRefusal(
                    "repository_identity_unknown",
                    "repository did not report its exact registered worktree",
                )
            return worktrees

        boundaries = registered_worktrees(source_repository_root)
        if self._authority_manager is not None:
            control_checkout = self._authority_manager.checkout.resolve(strict=True)
            boundaries.extend(registered_worktrees(control_checkout))
            boundaries.append(self._authority_manager.state_root.resolve(strict=True))
        boundaries = sorted(set(boundaries), key=lambda value: value.as_posix())
        overlapping = next(
            (
                boundary
                for boundary in boundaries
                if state_root == boundary
                or state_root.is_relative_to(boundary)
                or boundary.is_relative_to(state_root)
            ),
            None,
        )
        if overlapping is not None:
            raise DeploymentRefusal(
                "unsafe_state_root",
                "deployment state must remain disjoint from source, control, and authority state",
                details={
                    "stateRoot": str(state_root),
                    "overlappingBoundary": str(overlapping),
                },
            )

    def _build_apply_plan(
        self,
        inspection: Mapping[str, Any],
        deployment_id: str,
        *,
        grant_id: str,
    ) -> dict[str, Any]:
        deployment_id = safe_id(deployment_id, "deployment id")
        grant_id = safe_id(grant_id, "grant id")
        if inspection["dirty"]:
            raise DeploymentRefusal("dirty_source", "deployment planning requires a clean exact Git source")
        if inspection["unsafeConstructs"]:
            raise DeploymentRefusal("unsafe_project", "project contains unsafe deployment constructs", details={"unsafeConstructs": inspection["unsafeConstructs"]})
        if not inspection["deterministicAssistedPlanningSupported"]:
            raise DeploymentRefusal("unsupported_project", "project cannot produce a deterministic deployment proposal", details={"unknowns": inspection["unknowns"]})
        target = self.adapter.probe()
        tracked_paths = {item["path"] for item in inspection["source"]["inventory"]}
        descriptor_name = next((name for name in DESCRIPTORS if name in tracked_paths), None)
        compose_name = next((name for name in COMPOSE_FILES if name in tracked_paths), None)
        containerfile_name = next(
            (name for name in CONTAINERFILES if name in tracked_paths), None
        )
        if descriptor_name is not None:
            spec, overlay = _materialize_descriptor(_load_exact_mapping(inspection, descriptor_name), inspection, deployment_id, target)
        elif compose_name is not None:
            spec, overlay = _compose_spec(_load_exact_mapping(inspection, compose_name), inspection, deployment_id, target)
        elif containerfile_name is not None:
            spec, overlay = _containerfile_spec(
                inspection,
                deployment_id,
                target,
                containerfile_name,
            )
        else:
            spec, overlay = _assisted_spec(inspection, deployment_id, target)
        unsupported_storage = sorted(
            {
                storage["persistence"]
                for service in spec["services"]
                for storage in service["storage"]
                if storage["persistence"]
                in {"backup_required", "externally_managed"}
            }
        )
        if unsupported_storage:
            raise DeploymentRefusal(
                "unsupported_storage_policy",
                "Slice A supports only ephemeral and retained managed storage",
                details={"unsupportedPersistence": unsupported_storage},
            )
        # Project content may request capabilities, but never grants itself
        # authority. The operator-supplied canonical grant always wins.
        spec["authority"]["grantId"] = grant_id
        non_loopback = any(port["hostAddress"] not in {"127.0.0.1", "::1"} for service in spec["services"] for port in service["ports"])
        secrets = any(service["secrets"] for service in spec["services"])
        required = list(spec["authority"]["requireApproval"])
        required.extend(["first_apply"])
        if non_loopback:
            required.append("non_loopback_port")
        if secrets:
            required.append("secret_binding")
        spec["authority"]["requireApproval"] = list(dict.fromkeys(required))
        spec = validate_deployment_spec(spec)
        created = datetime.now(timezone.utc).replace(microsecond=0)
        seed = {
            "operation": "apply",
            "spec": spec,
            "sourceInventory": inspection["source"]["inventory"],
            "createdAt": timestamp(created),
            "expiresAt": timestamp(created + timedelta(seconds=PLAN_TTL_SECONDS)),
            "overlay": overlay,
        }
        plan_id = "plan_" + digest_value(seed)[7:31]
        evidence_path = str(self.store.plan_path(deployment_id, plan_id))
        plan: dict[str, Any] = {
            "schema": PLAN_SCHEMA,
            "planId": plan_id,
            "planDigest": None,
            "operation": "apply",
            "predecessorRevision": None,
            "createdAt": seed["createdAt"],
            "expiresAt": seed["expiresAt"],
            "spec": spec,
            "sourceInventory": inspection["source"]["inventory"],
            "changes": deployment_creation_changes(spec),
            "risks": (["non_loopback_port"] if non_loopback else []) + (["secret_binding_unavailable_in_slice_a"] if secrets else []),
            "destructiveEffects": [],
            "dataRetentionEffects": [
                {
                    "storageId": storage_id,
                    "persistence": persistence,
                    "ordinaryRemove": (
                        "removed" if persistence == "ephemeral" else "retained"
                    ),
                }
                for storage_id, persistence in sorted(
                    {
                        storage["id"]: storage["persistence"]
                        for service in spec["services"]
                        for storage in service["storage"]
                    }.items()
                )
            ],
            "authorityDecision": {"status": "awaiting_approval", "required": spec["authority"]["requireApproval"], "reason": "first deployment and every material risk bind to this exact plan digest"},
            "overlay": overlay,
            "evidencePath": evidence_path,
        }
        plan["planDigest"] = plan_digest(plan)
        return validate_plan(plan, now=created)

    def plan(
        self,
        project: Path | str,
        *,
        deployment_id: str,
        grant_id: str,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        inspection = inspect_project(project)
        source_identity = authority_source_identity(inspection)
        # This check is deliberately before the authority claim and before
        # DeploymentStore construction, so a refusal creates no source residue.
        self.assert_state_root_separate(inspection)
        authority_reference = self._verify_authority(
            authority_decision,
            action="plan_deployment",
            deployment_id=deployment_id,
            planning_grant_id=grant_id,
            source_identity=source_identity,
        )
        plan = self._build_apply_plan(
            inspection, deployment_id, grant_id=grant_id
        )
        try:
            state = self.store.load_state(deployment_id)
        except DeploymentRefusal as exc:
            if exc.code != "deployment_not_found":
                raise
            state = None
        if state is None:
            self.store.create_from_plan(
                plan,
                actor=self.actor,
                authority_reference=authority_reference,
            )
        else:
            self.store.add_plan(
                plan,
                actor=self.actor,
                authority_reference=authority_reference,
            )
        return plan

    def plan_update(
        self,
        project: Path | str,
        *,
        deployment_id: str,
        grant_id: str,
        authority_decision: Mapping[str, Any] | None,
        rollback_of: str | None = None,
    ) -> dict[str, Any]:
        """Plan an exact update (or rollback) of the accepted revision.

        The update plan supersedes the currently accepted revision and binds
        the same digest-bound approval contract as a first apply.  A rollback
        plan restores the exact specification of the revision named by
        ``rollback_of``; the store verifies both properties exactly.
        """

        inspection = inspect_project(project)
        source_identity = authority_source_identity(inspection)
        self.assert_state_root_separate(inspection)
        authority_reference = self._verify_authority(
            authority_decision,
            action="plan_deployment",
            deployment_id=deployment_id,
            planning_grant_id=grant_id,
            source_identity=source_identity,
        )
        state = self.store.load_state(deployment_id)
        if state["lifecycleState"] not in {"healthy", "degraded"}:
            raise DeploymentRefusal(
                "invalid_transition",
                "an update requires a healthy or degraded accepted revision",
            )
        accepted = state.get("acceptedRevision")
        if not isinstance(accepted, str):
            raise DeploymentRefusal(
                "invalid_transition", "deployment has no accepted revision to update"
            )
        plan = self._build_apply_plan(inspection, deployment_id, grant_id=grant_id)
        operation = "rollback" if rollback_of is not None else "update"
        if rollback_of is not None and rollback_of == accepted:
            raise DeploymentRefusal(
                "invalid_contract", "a rollback must restore a different revision"
            )
        prior_plan = self.store.load_plan(
            deployment_id, accepted, require_unexpired=False
        )
        created = datetime.now(timezone.utc).replace(microsecond=0)
        seed = {
            "operation": operation,
            "spec": plan["spec"],
            "sourceInventory": plan["sourceInventory"],
            "supersedes": accepted,
            "rollbackOf": rollback_of,
            "createdAt": plan["createdAt"],
            "expiresAt": plan["expiresAt"],
            "overlay": plan["overlay"],
        }
        plan_id = "plan_" + digest_value(seed)[7:31]
        plan.update(
            planId=plan_id,
            operation=operation,
            predecessorRevision=accepted,
            supersedes=accepted,
            rollbackOf=rollback_of,
            revisionId=None,
            changes=deployment_update_changes(prior_plan["spec"], plan["spec"]),
            authorityDecision={
                "status": "awaiting_approval",
                "required": plan["spec"]["authority"]["requireApproval"],
                "reason": (
                    "rollback restores an exact earlier revision and binds to this plan digest"
                    if operation == "rollback"
                    else "update replaces the accepted revision and every material risk binds to this exact plan digest"
                ),
            },
            evidencePath=str(self.store.plan_path(deployment_id, plan_id)),
        )
        plan["planDigest"] = plan_digest(plan)
        plan["revisionId"] = plan["planDigest"]
        validated = validate_plan(plan, now=created)
        self.store.add_plan(
            validated,
            actor=self.actor,
            authority_reference=authority_reference,
        )
        return validated

    @staticmethod
    def _retained_storage_ids(spec: Mapping[str, Any]) -> list[str]:
        return sorted(
            {
                item["id"]
                for service in spec["services"]
                for item in service["storage"]
                if item["persistence"] == "retained"
            }
        )

    def plan_backup(
        self,
        deployment_id: str,
        *,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        state = self.store.load_state(deployment_id)
        if state["lifecycleState"] not in {"healthy", "degraded"}:
            raise DeploymentRefusal(
                "invalid_transition", "a backup requires an accepted deployment"
            )
        accepted = state.get("acceptedRevision")
        if not isinstance(accepted, str):
            raise DeploymentRefusal(
                "invalid_transition", "deployment has no accepted revision to back up"
            )
        prior = self.store.load_plan(
            deployment_id, accepted, require_unexpired=False
        )
        storage_ids = self._retained_storage_ids(prior["spec"])
        if not storage_ids or set(state["storageIdentities"]) != set(storage_ids):
            raise DeploymentRefusal(
                "backup_unavailable",
                "backup requires exact retained deployment storage identities",
            )
        authority_reference = self._verify_authority(
            authority_decision,
            action="plan_deployment",
            deployment_id=deployment_id,
            run_id=accepted,
        )
        created = datetime.now(timezone.utc).replace(microsecond=0)
        backup_id = "backup_" + digest_value(
            {
                "deploymentId": deployment_id,
                "acceptedRevision": accepted,
                "stateRevision": state["revision"],
                "createdAt": timestamp(created),
            }
        )[7:31]
        seed = {
            "operation": "backup_data",
            "backupId": backup_id,
            "predecessorRevision": accepted,
            "createdAt": timestamp(created),
            "expiresAt": timestamp(created + timedelta(seconds=PLAN_TTL_SECONDS)),
        }
        plan_id = "plan_" + digest_value(seed)[7:31]
        plan: dict[str, Any] = {
            "schema": PLAN_SCHEMA,
            "planId": plan_id,
            "planDigest": None,
            "operation": "backup_data",
            "predecessorRevision": accepted,
            "backupId": backup_id,
            "createdAt": seed["createdAt"],
            "expiresAt": seed["expiresAt"],
            "spec": prior["spec"],
            "sourceInventory": prior["sourceInventory"],
            "changes": [
                {
                    "kind": "storage",
                    "action": "backup",
                    "id": storage_id,
                    "backupId": backup_id,
                }
                for storage_id in storage_ids
            ],
            "risks": ["service_pause"],
            "destructiveEffects": [],
            "dataRetentionEffects": [
                {
                    "backupId": backup_id,
                    "from": "present",
                    "to": "snapshot_available",
                }
            ],
            "authorityDecision": {
                "status": "awaiting_approval",
                "required": ["data_backup"],
                "reason": (
                    "backup briefly pauses the exact accepted runtime and creates "
                    "a retained snapshot"
                ),
            },
            "overlay": prior["overlay"],
            "evidencePath": str(self.store.plan_path(deployment_id, plan_id)),
        }
        plan["planDigest"] = plan_digest(plan)
        validated = validate_plan(plan, now=created)
        self.store.add_plan(
            validated,
            actor=self.actor,
            authority_reference=authority_reference,
        )
        return validated

    def plan_restore(
        self,
        deployment_id: str,
        *,
        backup_id: str,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        backup_id = safe_id(backup_id, "backup id")
        state = self.store.load_state(deployment_id)
        if state["lifecycleState"] not in {"healthy", "degraded"}:
            raise DeploymentRefusal(
                "invalid_transition", "a restore requires an accepted deployment"
            )
        accepted = state.get("acceptedRevision")
        if not isinstance(accepted, str):
            raise DeploymentRefusal(
                "invalid_transition", "deployment has no accepted revision to restore"
            )
        backup = state["dataBackups"].get(backup_id)
        if not isinstance(backup, Mapping) or backup.get("status") != "available":
            raise DeploymentRefusal(
                "backup_not_found", "an available exact deployment backup is required"
            )
        prior = self.store.load_plan(
            deployment_id, accepted, require_unexpired=False
        )
        storage_ids = self._retained_storage_ids(prior["spec"])
        if set(backup["storage"]) != set(storage_ids):
            raise DeploymentRefusal(
                "backup_identity_mismatch",
                "backup storage does not match the accepted deployment",
            )
        authority_reference = self._verify_authority(
            authority_decision,
            action="plan_deployment",
            deployment_id=deployment_id,
            run_id=accepted,
        )
        created = datetime.now(timezone.utc).replace(microsecond=0)
        seed = {
            "operation": "restore_data",
            "backupId": backup_id,
            "backupDigest": backup["backupDigest"],
            "predecessorRevision": accepted,
            "createdAt": timestamp(created),
            "expiresAt": timestamp(created + timedelta(seconds=PLAN_TTL_SECONDS)),
        }
        plan_id = "plan_" + digest_value(seed)[7:31]
        plan: dict[str, Any] = {
            "schema": PLAN_SCHEMA,
            "planId": plan_id,
            "planDigest": None,
            "operation": "restore_data",
            "predecessorRevision": accepted,
            "backupId": backup_id,
            "backupDigest": backup["backupDigest"],
            "createdAt": seed["createdAt"],
            "expiresAt": seed["expiresAt"],
            "spec": prior["spec"],
            "sourceInventory": prior["sourceInventory"],
            "changes": [
                {
                    "kind": "storage",
                    "action": "restore",
                    "id": storage_id,
                    "backupId": backup_id,
                }
                for storage_id in storage_ids
            ],
            "risks": ["service_pause", "data_replacement"],
            "destructiveEffects": [
                {"kind": "volume", "name": name, "irreversible": True}
                for name in sorted(state["storageIdentities"].values())
            ],
            "dataRetentionEffects": [
                {
                    "backupId": backup_id,
                    "from": "present",
                    "to": "restored_from_snapshot",
                }
            ],
            "authorityDecision": {
                "status": "awaiting_approval",
                "required": ["data_restore"],
                "reason": (
                    "restore replaces current retained data with the exact reviewed "
                    "snapshot and consumes its temporary runtime volume after verification"
                ),
            },
            "overlay": prior["overlay"],
            "evidencePath": str(self.store.plan_path(deployment_id, plan_id)),
        }
        plan["planDigest"] = plan_digest(plan)
        validated = validate_plan(plan, now=created)
        self.store.add_plan(
            validated,
            actor=self.actor,
            authority_reference=authority_reference,
        )
        return validated

    @staticmethod
    def _verified_data_backup_record(
        *,
        operation: str,
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        result: Mapping[str, Any],
        accepted_revision: str,
        expected_storage: Mapping[str, str],
    ) -> dict[str, Any]:
        def canonical_timestamp(value: object, label: str) -> str:
            if not isinstance(value, str):
                raise AdapterError(
                    f"{label}_verification_failed",
                    f"deployment {label} timestamp is missing",
                )
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise AdapterError(
                    f"{label}_verification_failed",
                    f"deployment {label} timestamp is invalid",
                ) from exc
            if (
                parsed.tzinfo is None
                or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
                or parsed.microsecond
                or value != parsed.isoformat().replace("+00:00", "Z")
            ):
                raise AdapterError(
                    f"{label}_verification_failed",
                    f"deployment {label} timestamp is invalid",
                )
            return value

        if operation == "backup_data":
            storage = result.get("storage")
            created_at = canonical_timestamp(result.get("createdAt"), "backup")
            if (
                result.get("backupId") != plan["backupId"]
                or result.get("sourceRevision") != accepted_revision
                or not isinstance(storage, Mapping)
                or set(storage) != set(expected_storage)
            ):
                raise AdapterError(
                    "backup_verification_failed",
                    "deployment backup result is incomplete",
                )
            backup_identity = {
                "backupId": plan["backupId"],
                "sourceRevision": accepted_revision,
                "createdAt": created_at,
                "storage": deepcopy(dict(storage)),
            }
            for storage_id, item in storage.items():
                if (
                    not isinstance(storage_id, str)
                    or not isinstance(item, Mapping)
                    or set(item)
                    != {"artifactId", "contentDigest", "fileCount", "bytes"}
                    or item.get("artifactId")
                    != f"{plan['backupId']}/{storage_id}.tar"
                    or DIGEST.fullmatch(str(item.get("contentDigest"))) is None
                    or isinstance(item.get("fileCount"), bool)
                    or not isinstance(item.get("fileCount"), int)
                    or item["fileCount"] < 0
                    or isinstance(item.get("bytes"), bool)
                    or not isinstance(item.get("bytes"), int)
                    or item["bytes"] < 0
                ):
                    raise AdapterError(
                        "backup_verification_failed",
                        "deployment backup storage evidence is invalid",
                    )
            return {
                **backup_identity,
                "backupDigest": digest_value(backup_identity),
                "status": "available",
                "restoredAt": None,
            }

        prior = state["dataBackups"].get(plan["backupId"])
        restored_at = canonical_timestamp(result.get("restoredAt"), "restore")
        if (
            not isinstance(prior, Mapping)
            or result.get("backupId") != plan["backupId"]
            or result.get("backupDigest") != plan["backupDigest"]
            or result.get("backupConsumed") is not True
        ):
            raise AdapterError(
                "restore_verification_failed",
                "deployment restore result is incomplete",
            )
        restored = deepcopy(dict(prior))
        restored["status"] = "restored_consumed"
        restored["restoredAt"] = restored_at
        return restored

    def apply_data_plan(
        self,
        deployment_id: str,
        *,
        accept_plan_digest: str,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        with self.store.operation_lock(deployment_id):
            state = self.store.load_state(deployment_id)
            if state["lifecycleState"] != "awaiting_approval":
                raise DeploymentRefusal(
                    "invalid_transition", "deployment is not awaiting a data-plan approval"
                )
            plan = self.store.load_plan(deployment_id, accept_plan_digest)
            operation = plan["operation"]
            if operation not in {"backup_data", "restore_data"}:
                raise DeploymentRefusal(
                    "approval_mismatch", "approval must bind an exact backup or restore plan"
                )
            accepted = state.get("acceptedRevision")
            if (
                not isinstance(accepted, str)
                or plan["predecessorRevision"] != accepted
                or state.get("desiredRevision") != accept_plan_digest
            ):
                raise DeploymentRefusal(
                    "stale_plan", "data plan no longer matches the accepted revision"
                )
            accepted_plan = self.store.load_plan(
                deployment_id, accepted, require_unexpired=False
            )
            action = (
                "backup_deployment_data"
                if operation == "backup_data"
                else "restore_deployment_data"
            )
            authority_reference = self._verify_authority(
                authority_decision,
                action=action,
                deployment_id=deployment_id,
                run_id=accept_plan_digest,
            )
            self._assert_source_current(plan)
            target = self.adapter.probe()
            if target["identityDigest"] != plan["spec"]["target"]["identityDigest"]:
                raise DeploymentRefusal(
                    "target_identity_changed", "target identity changed after planning"
                )
            expected_storage = {
                storage_id: state["storageIdentities"][storage_id]
                for storage_id in self._retained_storage_ids(plan["spec"])
            }
            _reserved, approval_receipts, operation_id = (
                self.store.approve_and_reserve(
                    deployment_id,
                    plan,
                    actor=self.actor,
                    authority_reference=authority_reference,
                )
            )
            try:
                with self._adapter_operation(operation_id, authority_reference):
                    if operation == "backup_data":
                        result = self.adapter.backup_data(
                            plan["spec"],
                            backup_id=plan["backupId"],
                            plan_digest=plan["planDigest"],
                            expected_volumes=expected_storage,
                            expected_revision=accepted,
                            expected_images=state["imageDigests"],
                            infrastructure=state.get("infrastructureIdentity"),
                        )
                    else:
                        backup = state["dataBackups"].get(plan["backupId"])
                        if (
                            not isinstance(backup, Mapping)
                            or backup.get("status") != "available"
                            or backup.get("backupDigest") != plan["backupDigest"]
                        ):
                            raise DeploymentRefusal(
                                "stale_plan", "restore backup changed after planning"
                            )
                        result = self.adapter.restore_data(
                            plan["spec"],
                            backup=backup,
                            plan_digest=plan["planDigest"],
                            expected_volumes=expected_storage,
                            expected_revision=accepted,
                            expected_images=state["imageDigests"],
                            infrastructure=state.get("infrastructureIdentity"),
                        )
                if (
                    not isinstance(result, Mapping)
                    or not isinstance(result.get("observation"), Mapping)
                    or not isinstance(result.get("health"), Mapping)
                ):
                    raise AdapterError(
                        f"{operation.removesuffix('_data')}_verification_failed",
                        "deployment data operation result is incomplete",
                    )
                self._validate_observation(
                    accepted_plan, result["observation"], state["imageDigests"]
                )
                backup_record = self._verified_data_backup_record(
                    operation=operation,
                    plan=plan,
                    state=state,
                    result=result,
                    accepted_revision=accepted,
                    expected_storage=expected_storage,
                )
            except (AdapterError, DeploymentRefusal) as exc:
                failure_code = exc.code

                def failed(current: dict[str, Any]) -> None:
                    transition = deepcopy(current["currentTransition"])
                    transition.update(phase="failed", failureCode=failure_code)
                    current["currentTransition"] = transition
                    current["driftStatus"] = "unknown"

                self.store.transition(
                    deployment_id,
                    "reconciliation_required",
                    event=f"{operation}_failed",
                    actor=self.actor,
                    data={
                        "operationId": operation_id,
                        "planDigest": accept_plan_digest,
                        "failureCode": failure_code,
                        "details": dict(getattr(exc, "details", {})),
                        "authorityDecision": authority_reference,
                    },
                    mutation=failed,
                    expected_operation_id=operation_id,
                    authority_outcome={
                        "status": "failed",
                        "code": failure_code,
                        "summary": "Deployment data operation failed and requires observed reconciliation",
                        "resource": {
                            "planDigest": accept_plan_digest,
                            "backupId": plan["backupId"],
                            "failureDetailsDigest": digest_value(
                                getattr(exc, "details", {})
                            ),
                        },
                    },
                )
                raise

            def staged(current: dict[str, Any]) -> None:
                transition = deepcopy(current["currentTransition"])
                transition["phase"] = "verifying"
                current["currentTransition"] = transition
                current["lastSuccessfulObservation"] = deepcopy(
                    result["observation"]
                )
                current["observedRevision"] = result["observation"][
                    "observedRevision"
                ]
                current["serviceHealth"] = deepcopy(result["health"])
                current["driftStatus"] = result["observation"]["status"]

            self.store.transition(
                deployment_id,
                "verifying",
                event=f"{operation}_runtime_verified",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "planDigest": accept_plan_digest,
                    "backupId": plan["backupId"],
                },
                mutation=staged,
                expected_operation_id=operation_id,
            )

            def completed(current: dict[str, Any]) -> None:
                current["currentTransition"] = None
                current["desiredRevision"] = accepted
                current["approvedPlanDigest"] = accepted
                current["dataBackups"][plan["backupId"]] = deepcopy(backup_record)
                current["driftStatus"] = result["observation"]["status"]

            final_state, receipt = self.store.transition(
                deployment_id,
                "healthy",
                event=(
                    "deployment_data_backed_up"
                    if operation == "backup_data"
                    else "deployment_data_restored"
                ),
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "planDigest": accept_plan_digest,
                    "backup": backup_record,
                    "runtime": result,
                    "authorityDecision": authority_reference,
                },
                mutation=completed,
                expected_operation_id=operation_id,
                authority_outcome={
                    "status": "succeeded",
                    "code": None,
                    "summary": (
                        "Deployment retained data was backed up and runtime health was verified"
                        if operation == "backup_data"
                        else "Deployment retained data was restored and runtime health was verified"
                    ),
                    "resource": {
                        "planDigest": accept_plan_digest,
                        "backup": backup_record,
                        "runtimeDigest": digest_value(result),
                    },
                },
            )
            return {
                "state": final_state,
                "runtime": result,
                "backup": backup_record,
                "approvalReceipts": approval_receipts,
                "receipt": receipt,
            }

    def _plan_for_state(self, state: Mapping[str, Any]) -> dict[str, Any]:
        digest = state.get("approvedPlanDigest") or state.get("desiredRevision") or state.get("acceptedRevision")
        if not isinstance(digest, str):
            raise DeploymentRefusal("plan_not_found", "deployment has no exact bound plan")
        return self.store.load_plan(state["deploymentId"], digest, require_unexpired=False)

    def reject_plan(
        self,
        deployment_id: str,
        *,
        plan_digest: str,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Reject one pending revision/data plan without touching accepted runtime."""

        with self.store.operation_lock(deployment_id):
            state = self.store.load_state(deployment_id)
            if (
                state["lifecycleState"] != "awaiting_approval"
                or state.get("desiredRevision") != plan_digest
                or state.get("currentTransition") is not None
            ):
                raise DeploymentRefusal(
                    "stale_plan", "deployment is not awaiting this exact proposal"
                )
            plan = self.store.load_plan(
                deployment_id, plan_digest, require_unexpired=False
            )
            predecessor = state.get("acceptedRevision")
            if (
                plan["operation"]
                not in {"update", "rollback", "backup_data", "restore_data"}
                or not isinstance(predecessor, str)
                or plan.get("predecessorRevision") != predecessor
            ):
                raise DeploymentRefusal(
                    "invalid_transition",
                    "only a pending plan for an accepted revision can be rejected",
                )
            authority_reference = self._verify_authority(
                authority_decision,
                action="plan_deployment",
                deployment_id=deployment_id,
                run_id=plan_digest,
            )
            predecessor_plan = self.store.load_plan(
                deployment_id, predecessor, require_unexpired=False
            )

            def rejected(current: dict[str, Any]) -> None:
                current["desiredRevision"] = predecessor
                current["approvedPlanDigest"] = predecessor
                current["sourceIdentity"] = deepcopy(
                    predecessor_plan["spec"]["source"]
                )
                current["targetIdentity"] = deepcopy(
                    predecessor_plan["spec"]["target"]
                )
                current["secretBindingIdentifiers"] = sorted(
                    {
                        secret["binding"]
                        for service in predecessor_plan["spec"]["services"]
                        for secret in service["secrets"]
                    }
                )
                current["currentTransition"] = None
                current["driftStatus"] = "in_sync"

            updated, receipt = self.store.transition(
                deployment_id,
                "healthy",
                event="proposal_rejected",
                actor=self.actor,
                data={
                    "planDigest": plan_digest,
                    "acceptedRevision": predecessor,
                    "runtimeMutation": False,
                    "authorityDecision": authority_reference,
                },
                mutation=rejected,
                authority_outcome={
                    "status": "succeeded",
                    "code": None,
                    "summary": (
                        "Exact deployment proposal was rejected without changing "
                        "the accepted runtime"
                    ),
                    "resource": {
                        "rejectedPlanDigest": plan_digest,
                        "acceptedRevision": predecessor,
                        "runtimeMutation": False,
                    },
                },
            )
            return {"state": updated, "receipt": receipt}

    def authority_run_id(self, deployment_id: str) -> str:
        """Return the exact currently governed plan digest after recovery."""

        state = self.store.load_state(deployment_id)
        return self._plan_for_state(state)["planDigest"]

    def peek_authority_run_id(self, deployment_id: str, action: str) -> str:
        """Resolve an exact action scope without creating or recovering state."""

        readonly_store = DeploymentStore(self._state_root, create=False)
        return readonly_store.peek_authority_run_id(deployment_id, action)

    def _assert_source_current(self, plan: Mapping[str, Any]) -> None:
        source = plan["spec"]["source"]
        root = Path(source["repositoryRoot"])
        project = root if source["projectPath"] == "." else root / source["projectPath"]
        current = inspect_project(project)["source"]
        current_spec = {
            key: current[key]
            for key in (
                "repositoryIdentity",
                "repositoryRoot",
                "projectPath",
                "commit",
                "treeDigest",
                "dirty",
                "dirtyDigest",
                "dirtyPolicy",
                "descriptorDigest",
            )
        }
        if current_spec != source or current["inventory"] != plan["sourceInventory"]:
            raise DeploymentRefusal("stale_plan", "source identity changed after plan approval")

    def apply(
        self,
        deployment_id: str,
        *,
        accept_plan_digest: str,
        authority_decision: Mapping[str, Any] | None,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        with self.store.operation_lock(deployment_id):
            return self._apply_locked(
                deployment_id,
                accept_plan_digest=accept_plan_digest,
                authority_decision=authority_decision,
                failpoint=failpoint,
            )

    @staticmethod
    def _validate_apply_result(plan: Mapping[str, Any], result: Mapping[str, Any]) -> None:
        expected_services = {service["id"] for service in plan["spec"]["services"]}
        expected_networks = {
            network["id"] for network in plan["spec"]["networks"]
        }
        expected_storage = {
            storage["id"]: storage["persistence"]
            for service in plan["spec"]["services"]
            for storage in service["storage"]
            if storage["persistence"] != "externally_managed"
        }
        images = result.get("images")
        image_materials = result.get("imageMaterials")
        expected_materials = {
            service["id"]: _expected_material_reference(plan, service)
            for service in plan["spec"]["services"]
        }
        build_modes = {
            service["id"]: service["build"]["mode"]
            for service in plan["spec"]["services"]
        }
        health = result.get("health")
        observation = result.get("observation")
        if (
            result.get("adapter") != TARGET_ADAPTER
            or not isinstance(result.get("target"), Mapping)
            or result["target"].get("identityDigest")
            != plan["spec"]["target"]["identityDigest"]
        ):
            raise AdapterError(
                "runtime_identity_mismatch",
                "adapter result does not bind the approved target",
            )
        if (
            not isinstance(images, Mapping)
            or set(images) != expected_services
            or any(
                not isinstance(value, str) or DIGEST.fullmatch(value) is None
                for value in images.values()
            )
        ):
            raise AdapterError("runtime_identity_mismatch", "runtime image identities are incomplete")
        if (
            not isinstance(image_materials, Mapping)
            or set(image_materials) != expected_services
            or any(
                not isinstance(item, Mapping)
                or set(item)
                != {"reference", "manifestDigest", "imageDigest", "platform"}
                or item.get("platform") != "linux/amd64"
                or item.get("reference") != expected_materials[service_id]
                or item.get("reference").rsplit("@", 1)[-1]
                != item.get("manifestDigest")
                or DIGEST.fullmatch(str(item.get("manifestDigest"))) is None
                or DIGEST.fullmatch(str(item.get("imageDigest"))) is None
                or (
                    build_modes[service_id] == "image"
                    and item.get("imageDigest") != images.get(service_id)
                )
                for service_id, item in image_materials.items()
            )
        ):
            raise AdapterError(
                "runtime_identity_mismatch",
                "adapter image material evidence is incomplete",
            )
        result_networks = result.get("networks")
        result_volumes = result.get("volumes")
        result_services = result.get("services")
        if (
            not isinstance(result_networks, Mapping)
            or set(result_networks) != expected_networks
            or any(not isinstance(value, str) or not value for value in result_networks.values())
            or not isinstance(result_volumes, Mapping)
            or set(result_volumes) != set(expected_storage)
            or any(not isinstance(value, str) or not value for value in result_volumes.values())
            or not isinstance(result_services, Mapping)
            or set(result_services) != expected_services
        ):
            raise AdapterError(
                "runtime_identity_mismatch",
                "adapter resource identities are incomplete",
            )
        if not isinstance(health, Mapping) or set(health) != expected_services or any(
            not isinstance(item, Mapping) or item.get("status") != "healthy"
            for item in health.values()
        ):
            raise AdapterError("health_verification_failed", "runtime health evidence is incomplete")
        if (
            not isinstance(observation, Mapping)
            or observation.get("targetIdentity") != plan["spec"]["target"]["identityDigest"]
            or observation.get("observedRevision") != plan["planDigest"]
            or observation.get("status") != "in_sync"
            or observation.get("drift")
        ):
            raise AdapterError(
                "runtime_identity_mismatch",
                "observed runtime does not match the approved plan",
                details={"observation": deepcopy(dict(observation)) if isinstance(observation, Mapping) else observation},
            )
        observed_services = observation.get("services")
        if not isinstance(observed_services, Mapping) or set(observed_services) != expected_services:
            raise AdapterError("runtime_identity_mismatch", "observed service set is incomplete")
        for service_id, item in observed_services.items():
            if (
                not isinstance(item, Mapping)
                or item.get("present") is not True
                or item.get("running") is not True
                or item.get("revision") != plan["planDigest"]
                or item.get("sourceCommit") != plan["spec"]["source"]["commit"]
                or item.get("imageDigest") != images[service_id]
            ):
                raise AdapterError("runtime_identity_mismatch", f"observed service identity differs: {service_id}")
            result_service = result_services.get(service_id)
            if (
                not isinstance(result_service, Mapping)
                or result_service.get("name") != item.get("name")
                or result_service.get("containerId") != item.get("containerId")
                or result_service.get("imageDigest") != images[service_id]
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"adapter service result differs: {service_id}",
                )
        observed_networks = observation.get("networks")
        if not isinstance(observed_networks, Mapping) or set(
            observed_networks
        ) != expected_networks:
            raise AdapterError(
                "runtime_identity_mismatch",
                "observed network identities are incomplete",
            )
        for network_id, item in observed_networks.items():
            if (
                not isinstance(item, Mapping)
                or item.get("present") is not True
                or item.get("internal") is not True
                or item.get("name") != result_networks[network_id]
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"observed network identity differs: {network_id}",
                )
        observed_volumes = observation.get("volumes")
        if not isinstance(observed_volumes, Mapping) or set(
            observed_volumes
        ) != set(expected_storage):
            raise AdapterError(
                "runtime_identity_mismatch",
                "observed storage identities are incomplete",
            )
        for storage_id, item in observed_volumes.items():
            if (
                not isinstance(item, Mapping)
                or item.get("present") is not True
                or item.get("name") != result_volumes[storage_id]
                or item.get("persistence") != expected_storage[storage_id]
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"observed storage identity differs: {storage_id}",
                )

    def _apply_locked(
        self,
        deployment_id: str,
        *,
        accept_plan_digest: str,
        authority_decision: Mapping[str, Any] | None,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        state = self.store.load_state(deployment_id)
        if state["lifecycleState"] != "awaiting_approval":
            raise DeploymentRefusal("invalid_transition", "deployment is not awaiting an exact apply approval")
        plan = self.store.load_plan(deployment_id, accept_plan_digest)
        authority_reference = self._verify_authority(
            authority_decision,
            action="apply_deployment",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
        )
        if plan["operation"] != "apply" or plan["planDigest"] != accept_plan_digest:
            raise DeploymentRefusal("approval_mismatch", "approval must bind the exact apply plan digest")
        self._assert_source_current(plan)
        target = self.adapter.probe()
        if target["identityDigest"] != plan["spec"]["target"]["identityDigest"]:
            raise DeploymentRefusal("target_identity_changed", "target identity changed after planning")
        _reserved, approval_receipts, operation_id = self.store.approve_and_reserve(
            deployment_id,
            plan,
            actor=self.actor,
            authority_reference=authority_reference,
        )
        context_root = self.store.new_build_context_path(deployment_id, operation_id)
        effects_started = False
        context_receipt: dict[str, Any] | None = None
        context_cleanup: dict[str, Any] | None = None
        try:
            context_receipt = self.adapter.materialize_context(plan, context_root)
            overlay_root = self.store.verify_overlay(
                deployment_id, plan["planId"], plan["overlay"]
            )
            effects_started = True
            with self._adapter_operation(operation_id, authority_reference):
                result = self.adapter.apply(
                    plan,
                    context_root=context_root,
                    overlay_root=overlay_root,
                    failpoint=failpoint,
                )
            self._validate_apply_result(plan, result)
            context_cleanup = self.store.cleanup_build_context(
                deployment_id,
                operation_id,
                expected_digest=context_receipt["contextDigest"],
            )
        except (AdapterError, DeploymentRefusal) as exc:
            details = dict(getattr(exc, "details", {}))
            failure_code = getattr(exc, "code", "apply_failed")
            if context_cleanup is None:
                try:
                    context_cleanup = self.store.cleanup_build_context(
                        deployment_id,
                        operation_id,
                        expected_digest=(
                            context_receipt["contextDigest"]
                            if context_receipt is not None
                            else None
                        ),
                    )
                except DeploymentRefusal as cleanup_exc:
                    details["buildContextCleanup"] = {
                        "status": "uncertain",
                        "failureCode": cleanup_exc.code,
                        "details": dict(cleanup_exc.details),
                    }
                else:
                    details["buildContextCleanup"] = context_cleanup
            cleanup = details.get("cleanup")
            uncertain = effects_started and (
                not isinstance(cleanup, Mapping) or bool(cleanup.get("uncertain"))
            )
            uncertain = uncertain or (
                isinstance(details.get("buildContextCleanup"), Mapping)
                and details["buildContextCleanup"].get("status") == "uncertain"
            )
            retained_storage = (
                dict(cleanup.get("retainedStorageIdentities", {}))
                if isinstance(cleanup, Mapping)
                and cleanup.get("verified") is True
                and isinstance(cleanup.get("retainedStorageIdentities"), Mapping)
                else {}
            )

            def failed(current: dict[str, Any]) -> None:
                if uncertain:
                    transition = deepcopy(current["currentTransition"])
                    transition.update(
                        phase="failed",
                        failureCode=failure_code,
                        details=details,
                    )
                    current["currentTransition"] = transition
                else:
                    current["currentTransition"] = None
                    current["storageIdentities"] = retained_storage
                    current["imageDigests"] = {}
                    current["observedRevision"] = None
                    current["serviceHealth"] = {
                        service["id"]: {"status": "absent"}
                        for service in plan["spec"]["services"]
                    }
                    current["infrastructureIdentity"] = (
                        self._infrastructure_from_plan(plan, only_storage=set(retained_storage))
                        if retained_storage
                        else None
                    )
                    current["removalState"] = "runtime_absent"
                    current["retainedDataState"] = (
                        "retained_after_failed_apply"
                        if retained_storage
                        else "not_created"
                    )
                current["driftStatus"] = "unknown" if uncertain else "runtime_absent_data_may_be_retained"

            target_state = "reconciliation_required" if uncertain else "failed"
            self.store.transition(
                deployment_id,
                target_state,
                event="apply_failed",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "planDigest": accept_plan_digest,
                    "failureCode": getattr(exc, "code", "apply_failed"),
                    "details": details,
                    "authorityDecision": authority_reference,
                },
                mutation=failed,
                expected_operation_id=operation_id,
                authority_outcome={
                    "status": "failed",
                    "code": getattr(exc, "code", "apply_failed"),
                    "summary": "Exact deployment apply failed and its durable runtime disposition was recorded",
                    "resource": {
                        "planDigest": accept_plan_digest,
                        "runtimeEffectUncertain": uncertain,
                        "retainedStorageIdentities": retained_storage,
                        "failureDetailsDigest": digest_value(details),
                    },
                },
            )
            raise

        def staged(current: dict[str, Any]) -> None:
            current["imageDigests"] = dict(result["images"])
            current["serviceHealth"] = deepcopy(result["health"])
            current["storageIdentities"] = dict(result["volumes"])
            current["observedRevision"] = result["observation"]["observedRevision"]
            current["lastSuccessfulObservation"] = deepcopy(result["observation"])
            current["driftStatus"] = result["observation"]["status"]
            current["infrastructureIdentity"] = self._infrastructure_from_plan(plan)
            current["removalState"] = "runtime_present"
            current["retainedDataState"] = "present" if result["volumes"] else "not_applicable"
            transition = deepcopy(current["currentTransition"])
            transition.update(
                phase="verifying",
                contextDigest=context_receipt["contextDigest"],
                contextCleanup=deepcopy(context_cleanup),
            )
            current["currentTransition"] = transition

        self.store.transition(deployment_id, "verifying", event="runtime_started", actor=self.actor, data={"operationId": operation_id, "planDigest": accept_plan_digest, "context": context_receipt, "contextCleanup": context_cleanup, "images": result["images"]}, mutation=staged, expected_operation_id=operation_id)

        def accepted(current: dict[str, Any]) -> None:
            current["acceptedRevision"] = accept_plan_digest
            current["desiredRevision"] = accept_plan_digest
            current["observedRevision"] = result["observation"]["observedRevision"]
            current["approvedPlanDigest"] = accept_plan_digest
            current["currentTransition"] = None
            current["driftStatus"] = result["observation"]["status"]

        final_state, receipt = self.store.transition(
            deployment_id,
            "healthy",
            event="revision_accepted",
            actor=self.actor,
            data={
                "operationId": operation_id,
                "planDigest": accept_plan_digest,
                "health": result["health"],
                "observation": result["observation"],
                "authorityDecision": authority_reference,
            },
            mutation=accepted,
            expected_operation_id=operation_id,
            authority_outcome={
                "status": "succeeded",
                "code": None,
                "summary": "Exact deployment revision was directly observed healthy and accepted",
                "resource": {
                    "planDigest": accept_plan_digest,
                    "runtime": deepcopy(result),
                    "runtimeDigest": digest_value(result),
                    "contextDigest": context_receipt["contextDigest"],
                    "contextCleanup": deepcopy(context_cleanup),
                },
            },
        )
        return {"state": final_state, "receipt": receipt, "approvalReceipts": approval_receipts, "runtime": result, "context": context_receipt, "contextCleanup": context_cleanup}

    @staticmethod
    def _infrastructure_from_plan(
        plan: Mapping[str, Any], *, only_storage: set[str] | None = None
    ) -> dict[str, Any]:
        """Return the exact creating-revision identity of a plan's shared infrastructure."""

        commit = plan["spec"]["source"]["commit"]
        revision = plan["planDigest"]
        return {
            "networks": (
                {}
                if only_storage is not None
                else {
                    network["id"]: {"revision": revision, "sourceCommit": commit}
                    for network in plan["spec"]["networks"]
                }
            ),
            "volumes": {
                item["id"]: {"revision": revision, "sourceCommit": commit}
                for service in plan["spec"]["services"]
                for item in service["storage"]
                if item["persistence"] != "externally_managed"
                and (only_storage is None or item["id"] in only_storage)
            },
        }

    @staticmethod
    def _infrastructure_from_observation(
        observation: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Derive creating-revision infrastructure identity from observed labels."""

        def collect(items: object) -> dict[str, Any]:
            if not isinstance(items, Mapping):
                return {}
            return {
                resource_id: {
                    "revision": item.get("planDigest"),
                    "sourceCommit": item.get("sourceCommit"),
                }
                for resource_id, item in items.items()
                if isinstance(item, Mapping)
                and item.get("present") is True
                and isinstance(item.get("planDigest"), str)
                and DIGEST.fullmatch(item["planDigest"]) is not None
                and isinstance(item.get("sourceCommit"), str)
                and COMMIT.fullmatch(item["sourceCommit"]) is not None
            }

        return {
            "networks": collect(observation.get("networks")),
            "volumes": collect(observation.get("volumes")),
        }

    @staticmethod
    def _validated_update_infrastructure(
        value: object, plan: Mapping[str, Any]
    ) -> dict[str, Any]:
        expected = {
            "networks": {network["id"] for network in plan["spec"]["networks"]},
            "volumes": {
                item["id"]
                for service in plan["spec"]["services"]
                for item in service["storage"]
                if item["persistence"] != "externally_managed"
            },
        }
        if not isinstance(value, Mapping) or set(value) != {"networks", "volumes"}:
            raise AdapterError(
                "runtime_identity_mismatch",
                "adapter infrastructure evidence is incomplete",
            )
        result: dict[str, Any] = {}
        for kind in ("networks", "volumes"):
            entries = value[kind]
            if (
                not isinstance(entries, Mapping)
                or set(entries) != expected[kind]
                or any(
                    not isinstance(entry, Mapping)
                    or set(entry) != {"revision", "sourceCommit"}
                    or DIGEST.fullmatch(str(entry.get("revision"))) is None
                    or COMMIT.fullmatch(str(entry.get("sourceCommit"))) is None
                    for entry in entries.values()
                )
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"adapter infrastructure evidence is incomplete: {kind}",
                )
            result[kind] = deepcopy(dict(entries))
        return result

    @staticmethod
    def _preflight_update(
        plan: Mapping[str, Any], predecessor_plan: Mapping[str, Any]
    ) -> None:
        """Refuse updates whose topology change requires the remove/purge flow."""

        def storage_shape(spec: Mapping[str, Any]) -> dict[str, tuple[str, str]]:
            return {
                item["id"]: (item["mountPath"], item["persistence"])
                for service in spec["services"]
                for item in service["storage"]
                if item["persistence"] != "externally_managed"
            }

        prior_storage = storage_shape(predecessor_plan["spec"])
        new_storage = storage_shape(plan["spec"])
        removed_storage = sorted(set(prior_storage) - set(new_storage))
        changed_storage = sorted(
            storage_id
            for storage_id in set(prior_storage) & set(new_storage)
            if prior_storage[storage_id] != new_storage[storage_id]
        )
        prior_networks = {network["id"] for network in predecessor_plan["spec"]["networks"]}
        new_networks = {network["id"] for network in plan["spec"]["networks"]}
        removed_networks = sorted(prior_networks - new_networks)
        if removed_storage or changed_storage or removed_networks:
            raise DeploymentRefusal(
                "update_topology_changed",
                "an update may not remove or reshape networks or storage; use the separately approved remove and purge flow",
            )

    def apply_update(
        self,
        deployment_id: str,
        *,
        accept_plan_digest: str,
        authority_decision: Mapping[str, Any] | None,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        with self.store.operation_lock(deployment_id):
            return self._apply_update_locked(
                deployment_id,
                accept_plan_digest=accept_plan_digest,
                authority_decision=authority_decision,
                failpoint=failpoint,
            )

    def _apply_update_locked(
        self,
        deployment_id: str,
        *,
        accept_plan_digest: str,
        authority_decision: Mapping[str, Any] | None,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        state = self.store.load_state(deployment_id)
        if state["lifecycleState"] != "awaiting_approval":
            raise DeploymentRefusal("invalid_transition", "deployment is not awaiting an exact update approval")
        plan = self.store.load_plan(deployment_id, accept_plan_digest)
        authority_reference = self._verify_authority(
            authority_decision,
            action="apply_deployment",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
        )
        if plan["operation"] not in {"update", "rollback"} or plan["planDigest"] != accept_plan_digest:
            raise DeploymentRefusal("approval_mismatch", "approval must bind the exact update plan digest")
        if (
            state.get("desiredRevision") != plan["planDigest"]
            or state.get("acceptedRevision") != plan["predecessorRevision"]
        ):
            raise DeploymentRefusal("stale_plan", "update plan no longer matches the accepted revision")
        self._assert_source_current(plan)
        target = self.adapter.probe()
        if target["identityDigest"] != plan["spec"]["target"]["identityDigest"]:
            raise DeploymentRefusal("target_identity_changed", "target identity changed after planning")
        predecessor_digest = plan["predecessorRevision"]
        predecessor_plan = self.store.load_plan(
            deployment_id, predecessor_digest, require_unexpired=False
        )
        self._preflight_update(plan, predecessor_plan)
        _reserved, approval_receipts, operation_id = self.store.approve_and_reserve(
            deployment_id,
            plan,
            actor=self.actor,
            authority_reference=authority_reference,
        )
        context_root = self.store.new_build_context_path(deployment_id, operation_id)
        context_receipt: dict[str, Any] | None = None
        context_cleanup: dict[str, Any] | None = None
        try:
            context_receipt = self.adapter.materialize_context(plan, context_root)
            overlay_root = self.store.verify_overlay(
                deployment_id, plan["planId"], plan["overlay"]
            )
            with self._adapter_operation(operation_id, authority_reference):
                result = self.adapter.apply_update(
                    plan,
                    predecessor_plan=predecessor_plan,
                    predecessor_images=state["imageDigests"],
                    infrastructure=state.get("infrastructureIdentity"),
                    context_root=context_root,
                    overlay_root=overlay_root,
                    failpoint=failpoint,
                )
            self._validate_apply_result(plan, result)
            infrastructure = self._validated_update_infrastructure(
                result.get("infrastructure"), plan
            )
            context_cleanup = self.store.cleanup_build_context(
                deployment_id,
                operation_id,
                expected_digest=context_receipt["contextDigest"],
            )
        except (AdapterError, DeploymentRefusal) as exc:
            self._record_update_failure(
                deployment_id,
                plan,
                predecessor_plan=predecessor_plan,
                operation_id=operation_id,
                authority_reference=authority_reference,
                exc=exc,
                context_receipt=context_receipt,
                context_cleanup=context_cleanup,
            )
            raise

        def staged(current: dict[str, Any]) -> None:
            current["imageDigests"] = dict(result["images"])
            current["serviceHealth"] = deepcopy(result["health"])
            current["storageIdentities"] = dict(result["volumes"])
            current["observedRevision"] = result["observation"]["observedRevision"]
            current["lastSuccessfulObservation"] = deepcopy(result["observation"])
            current["driftStatus"] = result["observation"]["status"]
            current["infrastructureIdentity"] = deepcopy(infrastructure)
            current["removalState"] = "runtime_present"
            current["retainedDataState"] = "present" if result["volumes"] else "not_applicable"
            transition = deepcopy(current["currentTransition"])
            transition.update(
                phase="verifying",
                contextDigest=context_receipt["contextDigest"],
                contextCleanup=deepcopy(context_cleanup),
            )
            current["currentTransition"] = transition

        self.store.transition(
            deployment_id,
            "verifying",
            event=f"{plan['operation']}_runtime_started",
            actor=self.actor,
            data={"operationId": operation_id, "planDigest": accept_plan_digest, "context": context_receipt, "contextCleanup": context_cleanup, "images": result["images"]},
            mutation=staged,
            expected_operation_id=operation_id,
        )

        def accepted(current: dict[str, Any]) -> None:
            current["acceptedRevision"] = accept_plan_digest
            current["desiredRevision"] = accept_plan_digest
            current["observedRevision"] = result["observation"]["observedRevision"]
            current["approvedPlanDigest"] = accept_plan_digest
            current["rollbackPredecessor"] = predecessor_digest
            current["currentTransition"] = None
            current["driftStatus"] = result["observation"]["status"]

        final_state, receipt = self.store.transition(
            deployment_id,
            "healthy",
            event="revision_accepted",
            actor=self.actor,
            data={
                "operationId": operation_id,
                "planDigest": accept_plan_digest,
                "supersedes": predecessor_digest,
                "health": result["health"],
                "observation": result["observation"],
                "prunedImages": list(result.get("prunedImages", [])),
                "authorityDecision": authority_reference,
            },
            mutation=accepted,
            expected_operation_id=operation_id,
            authority_outcome={
                "status": "succeeded",
                "code": None,
                "summary": "Exact deployment update was health-gated, directly observed healthy, and accepted",
                "resource": {
                    "planDigest": accept_plan_digest,
                    "supersedes": predecessor_digest,
                    "runtime": deepcopy(result),
                    "runtimeDigest": digest_value(result),
                    "contextDigest": context_receipt["contextDigest"],
                    "contextCleanup": deepcopy(context_cleanup),
                },
            },
        )
        return {"state": final_state, "receipt": receipt, "approvalReceipts": approval_receipts, "runtime": result, "context": context_receipt, "contextCleanup": context_cleanup}

    def _record_update_failure(
        self,
        deployment_id: str,
        plan: Mapping[str, Any],
        *,
        predecessor_plan: Mapping[str, Any],
        operation_id: str,
        authority_reference: Mapping[str, Any],
        exc: AdapterError | DeploymentRefusal,
        context_receipt: Mapping[str, Any] | None,
        context_cleanup: Mapping[str, Any] | None,
    ) -> None:
        """Record an update failure exactly, with automatic predecessor restoration.

        The mandatory ``rollbackOnFailedHealth`` policy authorizes the
        automatic rollback with receipts.  When the adapter proves the
        accepted runtime was never stopped or was restored exactly, the
        deployment returns to its still-accepted predecessor revision through
        the rollback lifecycle; anything uncertain becomes
        ``reconciliation_required`` and is resolved only by direct
        observation.
        """

        details = dict(getattr(exc, "details", {}))
        failure_code = getattr(exc, "code", "update_failed")
        if context_cleanup is None:
            try:
                context_cleanup = self.store.cleanup_build_context(
                    deployment_id,
                    operation_id,
                    expected_digest=(
                        context_receipt["contextDigest"]
                        if isinstance(context_receipt, Mapping)
                        else None
                    ),
                )
            except DeploymentRefusal as cleanup_exc:
                details["buildContextCleanup"] = {
                    "status": "uncertain",
                    "failureCode": cleanup_exc.code,
                    "details": dict(cleanup_exc.details),
                }
            else:
                details["buildContextCleanup"] = context_cleanup
        rollback = details.get("rollback")
        rollback = dict(rollback) if isinstance(rollback, Mapping) else {
            "status": "not_required",
            "revision": predecessor_plan["planDigest"],
            "reason": "update failed before the runtime adapter ran",
        }
        residue = details.get("residue")
        residue_uncertain = isinstance(residue, Mapping) and bool(residue.get("uncertain"))
        context_uncertain = (
            isinstance(details.get("buildContextCleanup"), Mapping)
            and details["buildContextCleanup"].get("status") == "uncertain"
        )
        restored = rollback.get("status") in {"restored", "not_required"} and not (
            residue_uncertain or context_uncertain
        )
        if restored:
            # Prove the accepted predecessor runtime directly before the
            # deployment is allowed back into its healthy accepted state.
            current_state = self.store.load_state(deployment_id)
            try:
                with self._adapter_operation(operation_id, authority_reference):
                    observation = self.adapter.observe(
                        predecessor_plan["spec"],
                        expected_revision=predecessor_plan["planDigest"],
                        expected_images=current_state.get("imageDigests", {}),
                        verify_health=True,
                        infrastructure=current_state.get(
                            "infrastructureIdentity"
                        ),
                    )
                self._validate_observation(
                    predecessor_plan,
                    observation,
                    current_state.get("imageDigests", {}),
                )
            except (AdapterError, DeploymentRefusal) as observe_exc:
                restored = False
                details["restorationObservation"] = {
                    "failureCode": getattr(observe_exc, "code", "runtime_observation_failed"),
                    "details": dict(getattr(observe_exc, "details", {})),
                }
        base_data: dict[str, Any] = {
            "operationId": operation_id,
            "planDigest": plan["planDigest"],
            "failureCode": failure_code,
            "details": details,
            "authorityDecision": authority_reference,
        }

        def interrupted(current: dict[str, Any]) -> None:
            transition = deepcopy(current["currentTransition"])
            transition.update(phase="failed", failureCode=failure_code, details=details)
            current["currentTransition"] = transition
            current["driftStatus"] = "unknown"

        if not restored:
            self.store.transition(
                deployment_id,
                "reconciliation_required",
                event=f"{plan['operation']}_failed",
                actor=self.actor,
                data=base_data,
                mutation=interrupted,
                expected_operation_id=operation_id,
                authority_outcome={
                    "status": "failed",
                    "code": failure_code,
                    "summary": "Exact deployment update failed with an uncertain runtime and requires observed-state reconciliation",
                    "resource": {
                        "planDigest": plan["planDigest"],
                        "rollback": deepcopy(rollback),
                        "failureDetailsDigest": digest_value(details),
                    },
                },
            )
            return

        self.store.transition(
            deployment_id,
            "rollback_required",
            event=f"{plan['operation']}_failed",
            actor=self.actor,
            data={**base_data, "rollback": deepcopy(rollback)},
            mutation=interrupted,
            expected_operation_id=operation_id,
            authority_outcome={
                "status": "failed",
                "code": failure_code,
                "summary": "Exact deployment update failed and its mandatory automatic rollback restored the accepted revision",
                "resource": {
                    "planDigest": plan["planDigest"],
                    "rollback": deepcopy(rollback),
                    "failureDetailsDigest": digest_value(details),
                },
            },
        )
        self.store.transition(
            deployment_id,
            "rolling_back",
            event="automatic_rollback_started",
            actor=self.actor,
            data={
                "operationId": operation_id,
                "planDigest": plan["planDigest"],
                "restoredRevision": predecessor_plan["planDigest"],
            },
            mutation=lambda _state: None,
            expected_operation_id=operation_id,
        )

        def restored_mutation(current: dict[str, Any]) -> None:
            current["currentTransition"] = None
            current["desiredRevision"] = predecessor_plan["planDigest"]
            current["approvedPlanDigest"] = predecessor_plan["planDigest"]
            current["observedRevision"] = observation["observedRevision"]
            current["serviceHealth"] = deepcopy(observation["health"])
            current["lastSuccessfulObservation"] = deepcopy(observation)
            current["driftStatus"] = observation["status"]
            current["rollbackPredecessor"] = plan["planDigest"]
            current["removalState"] = "runtime_present"

        self.store.transition(
            deployment_id,
            "healthy",
            event="automatic_rollback_completed",
            actor=self.actor,
            data={
                "operationId": operation_id,
                "planDigest": plan["planDigest"],
                "restoredRevision": predecessor_plan["planDigest"],
                "observation": observation,
                "authorityDecision": authority_reference,
            },
            mutation=restored_mutation,
            expected_operation_id=operation_id,
        )

    @staticmethod
    def _require_automatic(plan: Mapping[str, Any], action: str) -> None:
        if action not in plan["spec"]["authority"]["automaticWithReceipt"]:
            raise DeploymentRefusal(
                "authority_required", f"deployment policy does not authorize automatic {action}"
            )

    @staticmethod
    def _validate_observation(
        plan: Mapping[str, Any],
        observation: Mapping[str, Any],
        images: Mapping[str, str],
    ) -> None:
        expected_services = {service["id"] for service in plan["spec"]["services"]}
        if (
            observation.get("targetIdentity") != plan["spec"]["target"]["identityDigest"]
            or observation.get("observedRevision") != plan["planDigest"]
            or observation.get("status") != "in_sync"
            or observation.get("drift")
        ):
            raise AdapterError("runtime_identity_mismatch", "runtime observation differs from accepted state")
        services = observation.get("services")
        health = observation.get("health")
        if not isinstance(services, Mapping) or set(services) != expected_services:
            raise AdapterError("runtime_identity_mismatch", "runtime service set differs from accepted state")
        if not isinstance(health, Mapping) or (
            set(health) != expected_services
            or any(not isinstance(item, Mapping) or item.get("status") != "healthy" for item in health.values())
        ):
            raise AdapterError("health_verification_failed", "one or more services are unhealthy")
        observed_images = observation.get("images")
        expected_source_images = {
            service["id"]
            for service in plan["spec"]["services"]
            if service["build"]["mode"] == "source"
        }
        if not isinstance(observed_images, Mapping) or set(
            observed_images
        ) != expected_source_images:
            raise AdapterError(
                "runtime_identity_mismatch",
                "runtime image evidence is incomplete",
            )
        for service_id, item in services.items():
            if (
                not isinstance(item, Mapping)
                or item.get("present") is not True
                or item.get("running") is not True
                or item.get("revision") != plan["planDigest"]
                or item.get("sourceCommit") != plan["spec"]["source"]["commit"]
                or item.get("imageDigest") != images.get(service_id)
            ):
                raise AdapterError("runtime_identity_mismatch", f"runtime service differs: {service_id}")

    @staticmethod
    def _expected_absent_drift(
        state: Mapping[str, Any],
        plan: Mapping[str, Any],
        observation: Mapping[str, Any],
        *,
        interrupted_operation: str | None,
    ) -> list[str]:
        """Classify expected absence without discarding runtime identity drift."""

        services = observation.get("services")
        networks = observation.get("networks")
        volumes = observation.get("volumes")
        images = observation.get("images")
        unexpected = observation.get("unexpectedResources")
        if not all(
            isinstance(item, Mapping)
            for item in (services, networks, volumes, images, unexpected)
        ):
            return ["runtime_observation_incomplete"]
        runtime_revision = (
            plan.get("predecessorRevision")
            if plan.get("operation") == "purge_data"
            else plan.get("planDigest")
        )
        expects_retained = (
            interrupted_operation == "remove"
            or state.get("lifecycleState") == "removed_runtime_data_retained"
            or (
                state.get("lifecycleState") == "failed"
                and state.get("retainedDataState")
                == "retained_after_failed_apply"
            )
        )
        persistence = {
            item["id"]: item["persistence"]
            for service in plan["spec"]["services"]
            for item in service["storage"]
            if item["persistence"] != "externally_managed"
        }
        ignored = {
            *(
                f"container_missing:{service['id']}"
                for service in plan["spec"]["services"]
            ),
            *(
                f"network_missing:{network['id']}"
                for network in plan["spec"]["networks"]
            ),
            *(
                f"image_missing:{service['id']}"
                for service in plan["spec"]["services"]
                if service["build"]["mode"] == "source"
            ),
        }
        for storage_id, policy in persistence.items():
            if not (expects_retained and policy != "ephemeral"):
                ignored.add(f"volume_missing:{storage_id}")
        drift = [
            item
            for item in observation.get("drift", [])
            if isinstance(item, str) and item not in ignored
        ]
        if any(item.get("present") for item in services.values()):
            drift.append("runtime_present_after_removal")
        if any(item.get("present") for item in networks.values()):
            drift.append("network_present_after_removal")
        if any(item.get("present") for item in images.values()):
            drift.append("image_present_after_removal")
        storage_identities = state.get("storageIdentities")
        storage_identities = (
            storage_identities if isinstance(storage_identities, Mapping) else {}
        )
        infrastructure = state.get("infrastructureIdentity")
        infra_volumes = (
            infrastructure.get("volumes")
            if isinstance(infrastructure, Mapping)
            and isinstance(infrastructure.get("volumes"), Mapping)
            else {}
        )
        for storage_id, policy in persistence.items():
            item = volumes.get(storage_id)
            if not isinstance(item, Mapping):
                drift.append(f"storage_observation_missing:{storage_id}")
                continue
            should_exist = expects_retained and policy != "ephemeral"
            if bool(item.get("present")) != should_exist:
                drift.append(f"storage_removal_mismatch:{storage_id}")
                continue
            infra_entry = infra_volumes.get(storage_id)
            expected_label_revision = (
                infra_entry.get("revision")
                if isinstance(infra_entry, Mapping)
                and isinstance(infra_entry.get("revision"), str)
                else runtime_revision
            )
            expected_label_source = (
                infra_entry.get("sourceCommit")
                if isinstance(infra_entry, Mapping)
                and isinstance(infra_entry.get("sourceCommit"), str)
                else plan["spec"]["source"]["commit"]
            )
            if should_exist and (
                storage_identities.get(storage_id) != item.get("name")
                or item.get("persistence") != policy
                or item.get("planDigest") != expected_label_revision
                or item.get("revision") != expected_label_revision
                or item.get("sourceCommit") != expected_label_source
            ):
                drift.append(f"storage_identity_changed:{storage_id}")
        if any(unexpected.values()):
            drift.append("unexpected_runtime_resources")
        return sorted(set(drift))

    def _reconcile_observed_transition(
        self,
        state: Mapping[str, Any],
        plan: Mapping[str, Any],
        observation: Mapping[str, Any],
        *,
        authority_reference: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        transition = state.get("currentTransition")
        if (
            state.get("lifecycleState") != "reconciliation_required"
            or not isinstance(transition, Mapping)
        ):
            return None
        operation = transition.get("operation")
        operation_id = transition.get("operationId")
        interrupted_authority = transition.get("authorityDecision")
        if not isinstance(operation_id, str) or not isinstance(
            interrupted_authority, Mapping
        ):
            return None
        interrupted_request_id = interrupted_authority.get("requestId")
        if not isinstance(interrupted_request_id, str):
            return None
        services = observation.get("services")
        networks = observation.get("networks")
        volumes = observation.get("volumes")
        images = observation.get("images")
        unexpected = observation.get("unexpectedResources")
        if not all(
            isinstance(item, Mapping)
            for item in (services, networks, volumes, images, unexpected)
        ):
            return None
        runtime_absent = not any(
            item.get("present") for item in services.values()
        ) and not any(item.get("present") for item in networks.values())
        no_unexpected = not any(unexpected.values())

        if operation == "apply":
            def cleanup_context() -> dict[str, Any]:
                return self.store.cleanup_build_context(
                    state["deploymentId"],
                    operation_id,
                    expected_digest=(
                        transition.get("contextDigest")
                        if isinstance(transition.get("contextDigest"), str)
                        else None
                    ),
                    expected_inventory=plan["sourceInventory"],
                    allow_partial=True,
                )

            observed_images = {
                service_id: item.get("imageDigest")
                for service_id, item in services.items()
                if isinstance(item, Mapping)
                and isinstance(item.get("imageDigest"), str)
            }
            try:
                self._validate_observation(plan, observation, observed_images)
            except AdapterError:
                storage_safe = not any(
                    item.get("present") for item in volumes.values()
                )
                images_absent = not any(
                    item.get("present") for item in images.values()
                )
                if (
                    not runtime_absent
                    or not no_unexpected
                    or not storage_safe
                    or not images_absent
                ):
                    return None
                try:
                    context_cleanup = cleanup_context()
                except DeploymentRefusal:
                    return None

                def failed(current: dict[str, Any]) -> None:
                    current["currentTransition"] = None
                    current["observedRevision"] = None
                    current["imageDigests"] = {}
                    current["storageIdentities"] = {
                        storage_id: item["name"]
                        for storage_id, item in volumes.items()
                        if item.get("present")
                        and item.get("persistence") != "ephemeral"
                        and isinstance(item.get("name"), str)
                    }
                    current["serviceHealth"] = {
                        service["id"]: {"status": "absent"}
                        for service in plan["spec"]["services"]
                    }
                    current["infrastructureIdentity"] = (
                        self._infrastructure_from_plan(
                            plan, only_storage=set(current["storageIdentities"])
                        )
                        if current["storageIdentities"]
                        else None
                    )
                    current["lastSuccessfulObservation"] = deepcopy(observation)
                    current["driftStatus"] = "in_sync"
                    current["removalState"] = "runtime_absent"
                    current["retainedDataState"] = (
                        "retained_after_failed_apply"
                        if current["storageIdentities"]
                        else "not_created"
                    )

                return self.store.transition(
                    state["deploymentId"],
                    "failed",
                    event="interrupted_apply_reconciled_absent",
                    actor=self.actor,
                    data={
                        "operationId": operation_id,
                        "observation": observation,
                        "contextCleanup": context_cleanup,
                        "authorityDecision": authority_reference,
                        "reconciledAuthorityRequestId": interrupted_request_id,
                        "reconciledAuthorityOutcome": {
                            "status": "failed",
                            "code": "interrupted_apply_absent",
                            "summary": "Interrupted deployment apply was observed with no runtime effect",
                            "resource": {
                                "deploymentId": state["deploymentId"],
                                "lifecycleState": "failed",
                                "planDigest": plan["planDigest"],
                                "observedRevision": None,
                            },
                        },
                    },
                    mutation=failed,
                    expected_operation_id=operation_id,
                )

            try:
                context_cleanup = cleanup_context()
            except DeploymentRefusal:
                return None

            def accepted(current: dict[str, Any]) -> None:
                current["currentTransition"] = None
                current["acceptedRevision"] = plan["planDigest"]
                current["desiredRevision"] = plan["planDigest"]
                current["approvedPlanDigest"] = plan["planDigest"]
                current["observedRevision"] = observation["observedRevision"]
                current["imageDigests"] = observed_images
                current["serviceHealth"] = deepcopy(observation["health"])
                current["storageIdentities"] = {
                    key: value.get("name") for key, value in volumes.items()
                }
                current["lastSuccessfulObservation"] = deepcopy(observation)
                current["driftStatus"] = "in_sync"
                current["removalState"] = "runtime_present"
                current["retainedDataState"] = (
                    "present" if current["storageIdentities"] else "not_applicable"
                )

            return self.store.transition(
                state["deploymentId"],
                "healthy",
                event="interrupted_apply_reconciled_healthy",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "observation": observation,
                    "imageDigests": observed_images,
                    "contextCleanup": context_cleanup,
                    "authorityDecision": authority_reference,
                    "reconciledAuthorityRequestId": interrupted_request_id,
                    "reconciledAuthorityOutcome": {
                        "status": "succeeded",
                        "code": None,
                        "summary": "Interrupted deployment apply was observed healthy at its exact approved revision",
                        "resource": {
                            "deploymentId": state["deploymentId"],
                            "lifecycleState": "healthy",
                            "planDigest": plan["planDigest"],
                            "observedRevision": observation["observedRevision"],
                        },
                    },
                },
                mutation=accepted,
                expected_operation_id=operation_id,
            )

        if operation in {"update", "rollback"}:
            predecessor_digest = plan.get("predecessorRevision")
            if not isinstance(predecessor_digest, str):
                return None
            try:
                predecessor_plan = self.store.load_plan(
                    state["deploymentId"], predecessor_digest, require_unexpired=False
                )
            except DeploymentRefusal:
                return None
            observed_images = {
                service_id: item.get("imageDigest")
                for service_id, item in services.items()
                if isinstance(item, Mapping)
                and isinstance(item.get("imageDigest"), str)
            }
            try:
                self._validate_observation(plan, observation, observed_images)
            except AdapterError:
                pass
            else:
                def accepted(current: dict[str, Any]) -> None:
                    current["currentTransition"] = None
                    current["acceptedRevision"] = plan["planDigest"]
                    current["desiredRevision"] = plan["planDigest"]
                    current["approvedPlanDigest"] = plan["planDigest"]
                    current["observedRevision"] = observation["observedRevision"]
                    current["imageDigests"] = observed_images
                    current["serviceHealth"] = deepcopy(observation["health"])
                    current["storageIdentities"] = {
                        key: value.get("name") for key, value in volumes.items()
                    }
                    current["infrastructureIdentity"] = (
                        self._infrastructure_from_observation(observation)
                    )
                    current["rollbackPredecessor"] = predecessor_digest
                    current["lastSuccessfulObservation"] = deepcopy(observation)
                    current["driftStatus"] = "in_sync"
                    current["removalState"] = "runtime_present"
                    current["retainedDataState"] = (
                        "present" if current["storageIdentities"] else "not_applicable"
                    )

                return self.store.transition(
                    state["deploymentId"],
                    "healthy",
                    event=f"interrupted_{operation}_reconciled_healthy",
                    actor=self.actor,
                    data={
                        "operationId": operation_id,
                        "observation": observation,
                        "imageDigests": observed_images,
                        "authorityDecision": authority_reference,
                        "reconciledAuthorityRequestId": interrupted_request_id,
                        "reconciledAuthorityOutcome": {
                            "status": "succeeded",
                            "code": None,
                            "summary": "Interrupted deployment update was observed healthy at its exact approved revision",
                            "resource": {
                                "deploymentId": state["deploymentId"],
                                "lifecycleState": "healthy",
                                "planDigest": plan["planDigest"],
                                "observedRevision": observation["observedRevision"],
                            },
                        },
                    },
                    mutation=accepted,
                    expected_operation_id=operation_id,
                )
            # The swap either never completed or was already rolled back:
            # prove the accepted predecessor runtime directly before
            # returning the deployment to its still-accepted revision.
            try:
                with self._adapter_operation(
                    authority_reference["requestId"], authority_reference
                ):
                    predecessor_observation = self.adapter.observe(
                        predecessor_plan["spec"],
                        expected_revision=predecessor_digest,
                        expected_images=state.get("imageDigests", {}),
                        verify_health=True,
                        infrastructure=state.get("infrastructureIdentity"),
                    )
                self._validate_observation(
                    predecessor_plan,
                    predecessor_observation,
                    state.get("imageDigests", {}),
                )
            except AdapterError:
                return None

            def restored(current: dict[str, Any]) -> None:
                current["currentTransition"] = None
                current["desiredRevision"] = predecessor_digest
                current["approvedPlanDigest"] = predecessor_digest
                current["observedRevision"] = predecessor_observation["observedRevision"]
                current["serviceHealth"] = deepcopy(predecessor_observation["health"])
                current["lastSuccessfulObservation"] = deepcopy(predecessor_observation)
                current["driftStatus"] = "in_sync"
                current["rollbackPredecessor"] = plan["planDigest"]
                current["removalState"] = "runtime_present"

            return self.store.transition(
                state["deploymentId"],
                "healthy",
                event=f"interrupted_{operation}_reconciled_predecessor",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "observation": predecessor_observation,
                    "authorityDecision": authority_reference,
                    "reconciledAuthorityRequestId": interrupted_request_id,
                    "reconciledAuthorityOutcome": {
                        "status": "failed",
                        "code": "interrupted_update_restored",
                        "summary": "Interrupted deployment update was observed restored at its still-accepted predecessor revision",
                        "resource": {
                            "deploymentId": state["deploymentId"],
                            "lifecycleState": "healthy",
                            "planDigest": predecessor_digest,
                            "observedRevision": predecessor_observation["observedRevision"],
                        },
                    },
                },
                mutation=restored,
                expected_operation_id=operation_id,
            )

        if operation == "restart":
            try:
                self._validate_observation(
                    plan, observation, state.get("imageDigests", {})
                )
            except AdapterError:
                return None

            def restarted(current: dict[str, Any]) -> None:
                current["currentTransition"] = None
                current["observedRevision"] = observation["observedRevision"]
                current["serviceHealth"] = deepcopy(observation["health"])
                current["lastSuccessfulObservation"] = deepcopy(observation)
                current["driftStatus"] = "in_sync"

            return self.store.transition(
                state["deploymentId"],
                "healthy",
                event="interrupted_restart_reconciled",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "observation": observation,
                    "authorityDecision": authority_reference,
                    "reconciledAuthorityRequestId": interrupted_request_id,
                    "reconciledAuthorityOutcome": {
                        "status": "succeeded",
                        "code": None,
                        "summary": "Interrupted deployment restart was observed healthy at its accepted revision",
                        "resource": {
                            "deploymentId": state["deploymentId"],
                            "lifecycleState": "healthy",
                            "planDigest": plan["planDigest"],
                            "observedRevision": observation["observedRevision"],
                        },
                    },
                },
                mutation=restarted,
                expected_operation_id=operation_id,
            )

        if operation == "remove":
            removal_drift = self._expected_absent_drift(
                state,
                plan,
                observation,
                interrupted_operation="remove",
            )
            if removal_drift:
                return None

            def removed(current: dict[str, Any]) -> None:
                current["currentTransition"] = None
                current["desiredRevision"] = None
                current["observedRevision"] = None
                current["serviceHealth"] = {
                    service["id"]: {"status": "absent"}
                    for service in plan["spec"]["services"]
                }
                current["lastSuccessfulObservation"] = deepcopy(observation)
                current["removalState"] = "runtime_removed"
                current["retainedDataState"] = (
                    "retained"
                    if any(item.get("present") for item in volumes.values())
                    else "not_applicable"
                )
                current["storageIdentities"] = {
                    storage_id: item["name"]
                    for storage_id, item in volumes.items()
                    if item.get("present")
                    and item.get("persistence") != "ephemeral"
                    and isinstance(item.get("name"), str)
                }
                infrastructure = current.get("infrastructureIdentity")
                current["infrastructureIdentity"] = (
                    {
                        "networks": {},
                        "volumes": {
                            key: value
                            for key, value in infrastructure.get("volumes", {}).items()
                            if key in current["storageIdentities"]
                        },
                    }
                    if isinstance(infrastructure, Mapping) and current["storageIdentities"]
                    else None
                )
                current["driftStatus"] = "in_sync"

            return self.store.transition(
                state["deploymentId"],
                "removed_runtime_data_retained",
                event="interrupted_remove_reconciled",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "observation": observation,
                    "authorityDecision": authority_reference,
                    "reconciledAuthorityRequestId": interrupted_request_id,
                    "reconciledAuthorityOutcome": {
                        "status": "succeeded",
                        "code": None,
                        "summary": "Interrupted runtime removal was observed complete with retained-data policy preserved",
                        "resource": {
                            "deploymentId": state["deploymentId"],
                            "lifecycleState": "removed_runtime_data_retained",
                            "planDigest": plan["planDigest"],
                            "observedRevision": None,
                        },
                    },
                },
                mutation=removed,
                expected_operation_id=operation_id,
            )

        if operation == "purge_data":
            purge_drift = self._expected_absent_drift(
                state,
                plan,
                observation,
                interrupted_operation="purge_data",
            )
            if purge_drift:
                return None

            def purged(current: dict[str, Any]) -> None:
                current["currentTransition"] = None
                current["storageIdentities"] = {}
                current["infrastructureIdentity"] = None
                current["retainedDataState"] = "purged"
                current["removalState"] = "runtime_removed_data_purged"
                current["desiredRevision"] = None
                current["observedRevision"] = None
                current["lastSuccessfulObservation"] = deepcopy(observation)
                current["driftStatus"] = "in_sync"

            return self.store.transition(
                state["deploymentId"],
                "purged",
                event="interrupted_purge_reconciled",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "observation": observation,
                    "authorityDecision": authority_reference,
                    "reconciledAuthorityRequestId": interrupted_request_id,
                    "reconciledAuthorityOutcome": {
                        "status": "succeeded",
                        "code": None,
                        "summary": "Interrupted data purge was observed complete with all governed storage absent",
                        "resource": {
                            "deploymentId": state["deploymentId"],
                            "lifecycleState": "purged",
                            "planDigest": plan["planDigest"],
                            "observedRevision": None,
                        },
                    },
                },
                mutation=purged,
                expected_operation_id=operation_id,
            )
        return None

    def status(
        self,
        deployment_id: str,
        *,
        authority_decision: Mapping[str, Any] | None,
        record: bool = True,
    ) -> dict[str, Any]:
        with self.store.operation_lock(deployment_id):
            return self._status_locked(
                deployment_id,
                authority_decision=authority_decision,
                record=record,
            )

    def _status_locked(
        self,
        deployment_id: str,
        *,
        authority_decision: Mapping[str, Any] | None,
        record: bool,
    ) -> dict[str, Any]:
        state = self.store.load_state(deployment_id)
        plan = self._plan_for_state(state)
        authority_reference = self._verify_authority(
            authority_decision,
            action="observe_deployment",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
        )
        self._require_automatic(plan, "observe")
        current_transition = state.get("currentTransition")
        interrupted_operation = (
            current_transition.get("operation")
            if isinstance(current_transition, Mapping)
            else None
        )
        expected_absent = state["lifecycleState"] in {
            "removed_runtime_data_retained",
            "purged",
        } or (
            state["lifecycleState"] == "failed"
            and state.get("retainedDataState") == "retained_after_failed_apply"
            and state.get("removalState") == "runtime_absent"
        ) or interrupted_operation in {"remove", "purge_data"}
        expected_runtime_revision = (
            plan.get("predecessorRevision")
            if plan.get("operation") == "purge_data"
            else (
                current_transition.get("planDigest")
                if isinstance(current_transition, Mapping)
                and isinstance(current_transition.get("planDigest"), str)
                else (
                    state.get("acceptedRevision")
                    or state.get("approvedPlanDigest")
                    or state.get("desiredRevision")
                )
            )
        )
        # Between planning and applying an update the desired plan differs
        # from the runtime's accepted revision; observe against the plan that
        # actually governs the running revision or source labels would read
        # as false drift.
        observe_plan = plan
        if (
            isinstance(expected_runtime_revision, str)
            and expected_runtime_revision != plan["planDigest"]
        ):
            try:
                observe_plan = self.store.load_plan(
                    deployment_id, expected_runtime_revision, require_unexpired=False
                )
            except DeploymentRefusal:
                observe_plan = plan
        try:
            with self._adapter_operation(
                authority_reference["requestId"], authority_reference
            ):
                observation = self.adapter.observe(
                    observe_plan["spec"],
                    expected_revision=expected_runtime_revision,
                    expected_images=state.get("imageDigests", {}),
                    verify_health=not expected_absent,
                    infrastructure=state.get("infrastructureIdentity"),
                )
        except AdapterError as exc:
            failure_code = exc.code

            def observation_failed(current: dict[str, Any]) -> None:
                current["driftStatus"] = "unknown"
                current["serviceHealth"] = {
                    service["id"]: {"status": "unknown"}
                    for service in plan["spec"]["services"]
                }
                if current.get("currentTransition"):
                    current["currentTransition"]["phase"] = "observation_failed"
                    current["currentTransition"]["failureCode"] = failure_code

            transition = None
            if state["lifecycleState"] == "healthy":
                transition = "degraded"
            elif state.get("currentTransition") or state["lifecycleState"] in {
                "approved",
                "applying",
                "verifying",
                "failed",
                "removed_runtime_data_retained",
                "purged",
            }:
                transition = "reconciliation_required"
            updated, failure_receipt = self.store.mutate(
                deployment_id,
                event="runtime_observation_failed",
                actor=self.actor,
                data={
                    "failureCode": exc.code,
                    "details": dict(exc.details),
                    "authorityDecision": authority_reference,
                },
                mutation=observation_failed,
                transition_to=transition,
                authority_outcome={
                    "status": "failed",
                    "code": exc.code,
                    "summary": "Deployment runtime observation failed and its uncertainty was recorded",
                    "resource": {
                        "failureDetailsDigest": digest_value(exc.details),
                    },
                },
            )
            exc.details.update(
                {
                    "deploymentReceipt": failure_receipt,
                    "lifecycleState": updated["lifecycleState"],
                }
            )
            raise
        if not record:
            return {"state": state, "observation": observation}
        if expected_absent:
            drift = self._expected_absent_drift(
                state,
                plan,
                observation,
                interrupted_operation=interrupted_operation,
            )
        else:
            drift = list(observation["drift"])

        def observed(current: dict[str, Any]) -> None:
            current["lastSuccessfulObservation"] = deepcopy(observation)
            current["observedRevision"] = observation["observedRevision"]
            current["serviceHealth"] = deepcopy(
                observation.get("health")
                or {
                    key: {"status": "unknown" if value.get("running") else "absent"}
                    for key, value in observation["services"].items()
                }
            )
            current["driftStatus"] = "in_sync" if not drift else "drifted"
            if current.get("currentTransition"):
                current["currentTransition"]["phase"] = "interrupted_observed"

        transition: str | None = None
        if (
            (state.get("currentTransition") or state["lifecycleState"] in {"approved", "applying", "verifying"})
            and state["lifecycleState"] != "reconciliation_required"
        ):
            transition = "reconciliation_required"
        elif drift and state["lifecycleState"] == "healthy":
            transition = "degraded"
        # Terminal states without an in-flight operation retain their historical
        # lifecycle identity and report observed divergence through driftStatus.
        # reconciliation_required is reserved for a durable transition that can
        # name the interrupted operation and its authority decision.
        elif (
            drift
            and state.get("currentTransition")
            and state["lifecycleState"]
            in {"failed", "removed_runtime_data_retained", "purged"}
        ):
            transition = "reconciliation_required"
        elif not drift and state["lifecycleState"] == "degraded":
            transition = "healthy"
        updated, receipt = self.store.mutate(
            deployment_id,
            event="runtime_observed",
            actor=self.actor,
            data={
                "observation": observation,
                "effectiveDrift": drift,
                "authorityDecision": authority_reference,
            },
            mutation=observed,
            transition_to=transition,
            authority_outcome={
                "status": "succeeded",
                "code": None,
                "summary": "Deployment runtime was directly observed and durable drift truth was recorded",
                "resource": {
                    "observation": deepcopy(observation),
                    "observationDigest": digest_value(observation),
                    "effectiveDrift": list(drift),
                },
            },
        )
        reconciliation = self._reconcile_observed_transition(
            updated,
            plan,
            observation,
            authority_reference=authority_reference,
        )
        if reconciliation is None:
            return {"state": updated, "observation": observation, "receipt": receipt}
        reconciled_state, reconciliation_receipt = reconciliation
        return {
            "state": reconciled_state,
            "observation": observation,
            "receipt": receipt,
            "reconciliationReceipt": reconciliation_receipt,
        }

    def logs(
        self,
        deployment_id: str,
        *,
        authority_decision: Mapping[str, Any] | None,
        service_id: str | None = None,
        tail: int = 200,
    ) -> dict[str, Any]:
        with self.store.operation_lock(deployment_id):
            state = self.store.load_state(deployment_id)
            plan = self._plan_for_state(state)
            authority_reference = self._verify_authority(
                authority_decision,
                action="collect_deployment_logs",
                deployment_id=deployment_id,
                run_id=plan["planDigest"],
            )
            self._require_automatic(plan, "log_collection")
            try:
                with self._adapter_operation(
                    authority_reference["requestId"], authority_reference
                ):
                    result = self.adapter.logs(
                        plan["spec"],
                        service_id=service_id,
                        tail=tail,
                        expected_revision=state.get("acceptedRevision"),
                    )
            except AdapterError as exc:
                self.store.mutate(
                    deployment_id,
                    event="logs_collection_failed",
                    actor=self.actor,
                    data={
                        "failureCode": exc.code,
                        "details": dict(exc.details),
                        "authorityDecision": authority_reference,
                    },
                    mutation=lambda _state: None,
                    authority_outcome={
                        "status": "failed",
                        "code": exc.code,
                        "summary": "Bounded deployment log collection failed",
                        "resource": {
                            "serviceId": service_id,
                            "tail": tail,
                            "failureDetailsDigest": digest_value(exc.details),
                        },
                    },
                )
                raise
            evidence, evidence_document = self.store.prepare_evidence(
                deployment_id, kind="logs", value=result
            )
            _, receipt = self.store.mutate(
                deployment_id,
                event="logs_collected",
                actor=self.actor,
                data={
                    "services": sorted(result["logs"]),
                    "tail": tail,
                    "redacted": True,
                    "evidence": evidence,
                    "authorityDecision": authority_reference,
                },
                mutation=lambda _state: None,
                authority_outcome={
                    "status": "succeeded",
                    "code": None,
                    "summary": "Bounded redacted deployment logs were collected as immutable evidence",
                    "resource": {
                        "logEvidence": deepcopy(evidence),
                        "services": sorted(result["logs"]),
                        "serviceId": service_id,
                        "tail": tail,
                        "redacted": True,
                        "bounded": True,
                    },
                },
                evidence_documents=(evidence_document,),
            )
            return {**result, "evidence": evidence, "receipt": receipt}

    def restart(
        self,
        deployment_id: str,
        *,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        with self.store.operation_lock(deployment_id):
            return self._restart_locked(
                deployment_id, authority_decision=authority_decision
            )

    def _restart_locked(
        self,
        deployment_id: str,
        *,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        state = self.store.load_state(deployment_id)
        if state["lifecycleState"] not in {"healthy", "degraded"} or not state["acceptedRevision"]:
            raise DeploymentRefusal("invalid_transition", "only an accepted deployment can restart")
        plan = self.store.load_plan(deployment_id, state["acceptedRevision"], require_unexpired=False)
        authority_reference = self._verify_authority(
            authority_decision,
            action="restart_deployment",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
        )
        self._require_automatic(plan, "restart")
        _reserved, _reservation, operation_id = self.store.reserve_runtime_operation(
            deployment_id,
            operation="restart",
            actor=self.actor,
            allowed_states={"healthy", "degraded"},
            plan_digest=state["acceptedRevision"],
            authority_reference=authority_reference,
        )
        try:
            with self._adapter_operation(operation_id, authority_reference):
                result = self.adapter.restart(
                    plan["spec"],
                    expected_revision=state["acceptedRevision"],
                    expected_images=state["imageDigests"],
                    infrastructure=state.get("infrastructureIdentity"),
                )
            self._validate_observation(plan, result["observation"], state["imageDigests"])
        except AdapterError as exc:
            failure_code = exc.code

            def failed(current: dict[str, Any]) -> None:
                transition = deepcopy(current["currentTransition"])
                transition.update(phase="failed", failureCode=failure_code)
                current["currentTransition"] = transition
                current["driftStatus"] = "unknown"
            self.store.transition(
                deployment_id,
                "reconciliation_required",
                event="restart_failed",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "failureCode": exc.code,
                    "details": exc.details,
                    "authorityDecision": authority_reference,
                },
                mutation=failed,
                expected_operation_id=operation_id,
                authority_outcome={
                    "status": "failed",
                    "code": exc.code,
                    "summary": "Deployment restart failed and requires observed-state reconciliation",
                    "resource": {
                        "planDigest": plan["planDigest"],
                        "failureDetailsDigest": digest_value(exc.details),
                    },
                },
            )
            raise
        def finished(current: dict[str, Any]) -> None:
            current["currentTransition"] = None
            current["lastSuccessfulObservation"] = deepcopy(result["observation"])
            current["observedRevision"] = result["observation"]["observedRevision"]
            current["serviceHealth"] = deepcopy(result["health"])
            current["driftStatus"] = result["observation"]["status"]
        updated, receipt = self.store.mutate(
            deployment_id,
            event="restart_completed",
            actor=self.actor,
            data={
                "operationId": operation_id,
                "health": result["health"],
                "observation": result["observation"],
                "authorityDecision": authority_reference,
            },
            mutation=finished,
            transition_to=(
                "healthy" if state["lifecycleState"] == "degraded" else None
            ),
            expected_operation_id=operation_id,
            authority_outcome={
                "status": "succeeded",
                "code": None,
                "summary": "Accepted deployment revision restarted and was directly observed healthy",
                "resource": {
                    "planDigest": plan["planDigest"],
                    "runtime": deepcopy(result),
                    "runtimeDigest": digest_value(result),
                },
            },
        )
        return {"state": updated, "runtime": result, "receipt": receipt}

    def remove(
        self,
        deployment_id: str,
        *,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        with self.store.operation_lock(deployment_id):
            return self._remove_locked(
                deployment_id, authority_decision=authority_decision
            )

    def _remove_locked(
        self,
        deployment_id: str,
        *,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        state = self.store.load_state(deployment_id)
        accepted_revision = state.get("acceptedRevision")
        transition = state.get("currentTransition")
        interrupted_operation = (
            transition.get("operation") if isinstance(transition, Mapping) else None
        )
        interrupted_authority = (
            transition.get("authorityDecision")
            if isinstance(transition, Mapping)
            else None
        )
        interrupted_request_id = (
            interrupted_authority.get("requestId")
            if isinstance(interrupted_authority, Mapping)
            else None
        )
        interrupted_operation_id = (
            transition.get("operationId")
            if isinstance(transition, Mapping)
            else None
        )
        interrupted_revision = (
            transition.get("planDigest")
            if isinstance(transition, Mapping)
            and transition.get("operation") in {"apply", "remove"}
            else None
        )
        partial_recovery = (
            state.get("lifecycleState") == "reconciliation_required"
            and isinstance(interrupted_revision, str)
        )
        expected_revision = (
            interrupted_revision if partial_recovery else accepted_revision
        )
        if not isinstance(expected_revision, str):
            if state.get("retainedDataState") == "retained_after_failed_apply":
                raise DeploymentRefusal(
                    "retained_data_disposition_required",
                    "failed first-apply data requires a separately approved purge before retry or removal",
                )
            else:
                raise DeploymentRefusal(
                    "runtime_not_present",
                    "deployment has no accepted runtime revision to remove",
                )
        if state["lifecycleState"] not in {"healthy", "degraded", "failed", "reconciliation_required"}:
            raise DeploymentRefusal("invalid_transition", "deployment runtime is not removable from its current state")
        plan = self._plan_for_state(state)
        authority_reference = self._verify_authority(
            authority_decision,
            action="remove_deployment_runtime",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
        )
        self._require_automatic(plan, "remove_runtime_preserve_data")
        recovered_context_cleanup: dict[str, Any] | None = None
        if partial_recovery and interrupted_operation == "apply":
            if not isinstance(interrupted_operation_id, str):
                raise DeploymentRefusal(
                    "operation_identity_mismatch",
                    "interrupted apply has no exact build-context identity",
                )
            try:
                recovered_context_cleanup = self.store.cleanup_build_context(
                    deployment_id,
                    interrupted_operation_id,
                    expected_digest=(
                        transition.get("contextDigest")
                        if isinstance(transition, Mapping)
                        and isinstance(transition.get("contextDigest"), str)
                        else None
                    ),
                    expected_inventory=plan["sourceInventory"],
                    allow_partial=True,
                )
            except DeploymentRefusal as exc:
                self.store.mutate(
                    deployment_id,
                    event="interrupted_build_context_cleanup_failed",
                    actor=self.actor,
                    data={
                        "operationId": interrupted_operation_id,
                        "failureCode": exc.code,
                        "details": dict(exc.details),
                        "authorityDecision": authority_reference,
                    },
                    mutation=lambda current: current.update(driftStatus="unknown"),
                    expected_operation_id=interrupted_operation_id,
                    authority_outcome={
                        "status": "failed",
                        "code": exc.code,
                        "summary": "Interrupted apply build context could not be safely classified for cleanup",
                        "resource": {
                            "operationId": interrupted_operation_id,
                            "failureDetailsDigest": digest_value(exc.details),
                        },
                    },
                )
                raise
        _reserved, _reservation, operation_id = self.store.reserve_runtime_operation(
            deployment_id,
            operation="remove",
            actor=self.actor,
            allowed_states={"healthy", "degraded", "failed", "reconciliation_required"},
            plan_digest=plan["planDigest"],
            authority_reference=authority_reference,
            supersede_interrupted=partial_recovery,
        )
        try:
            with self._adapter_operation(operation_id, authority_reference):
                log_snapshot = self.adapter.logs(
                    plan["spec"], tail=200, expected_revision=expected_revision
                )
        except AdapterError as log_exc:
            log_snapshot = {
                "deploymentId": deployment_id,
                "status": "unavailable",
                "failureCode": log_exc.code,
                "details": dict(log_exc.details),
                "redacted": True,
                "bounded": True,
            }
        log_evidence, log_evidence_document = self.store.prepare_evidence(
            deployment_id, kind="pre_removal_logs", value=log_snapshot
        )
        self.store.mutate(
            deployment_id,
            event="pre_removal_logs_captured",
            actor=self.actor,
            data={
                "operationId": operation_id,
                "logEvidence": log_evidence,
                "authorityDecision": authority_reference,
            },
            mutation=lambda _state: None,
            expected_operation_id=operation_id,
            evidence_documents=(log_evidence_document,),
        )
        try:
            with self._adapter_operation(operation_id, authority_reference):
                result = self.adapter.remove_runtime(
                    plan["spec"],
                    expected_revision=expected_revision,
                    recovery_operation=(
                        interrupted_operation if partial_recovery else None
                    ),
                )
            retained_storage = result.get("retainedStorageIdentities")
            expected_retained_ids = {
                item["id"]
                for service_spec in plan["spec"]["services"]
                for item in service_spec["storage"]
                if item["persistence"] not in {
                    "ephemeral",
                    "externally_managed",
                }
            }
            retained_ids_exact = False
            if isinstance(retained_storage, Mapping):
                retained_ids_exact = (
                    set(retained_storage).issubset(expected_retained_ids)
                    if partial_recovery and interrupted_operation == "apply"
                    else set(retained_storage) == expected_retained_ids
                )
            if (
                result.get("verifiedRuntimeAbsent") is not True
                or result.get("ordinaryRemovalPreservedData") is not True
                or not isinstance(retained_storage, Mapping)
                or not retained_ids_exact
                or any(
                    not isinstance(name, str) or not name
                    for name in retained_storage.values()
                )
                or len(set(retained_storage.values())) != len(retained_storage)
                or set(retained_storage.values())
                != set(result.get("retainedVolumes", []))
                or result.get("recoveryOperation")
                != (interrupted_operation if partial_recovery else None)
            ):
                raise AdapterError("removal_verification_failed", "runtime removal was not directly verified")
        except (AdapterError, DeploymentRefusal) as exc:
            details = dict(getattr(exc, "details", {}))
            failure_code = getattr(exc, "code", "remove_failed")

            def failed(current: dict[str, Any]) -> None:
                transition = deepcopy(current["currentTransition"])
                transition.update(
                    phase="failed",
                    failureCode=failure_code,
                )
                current["currentTransition"] = transition
                current["driftStatus"] = "unknown"
            self.store.transition(
                deployment_id,
                "reconciliation_required",
                event="remove_failed",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "failureCode": getattr(exc, "code", "remove_failed"),
                    "details": details,
                    "authorityDecision": authority_reference,
                },
                mutation=failed,
                expected_operation_id=operation_id,
                authority_outcome={
                    "status": "failed",
                    "code": getattr(exc, "code", "remove_failed"),
                    "summary": "Deployment runtime removal failed and requires observed-state reconciliation",
                    "resource": {
                        "planDigest": plan["planDigest"],
                        "expectedRevision": expected_revision,
                        "logEvidence": deepcopy(log_evidence),
                        "failureDetailsDigest": digest_value(details),
                    },
                },
            )
            raise
        def removed(current: dict[str, Any]) -> None:
            current["currentTransition"] = None
            current["desiredRevision"] = None
            current["observedRevision"] = None
            current["imageDigests"] = {}
            current["serviceHealth"] = {service["id"]: {"status": "absent"} for service in plan["spec"]["services"]}
            current["removalState"] = "runtime_removed"
            current["retainedDataState"] = (
                "retained" if retained_storage else "not_applicable"
            )
            current["storageIdentities"] = dict(retained_storage)
            infrastructure = current.get("infrastructureIdentity")
            current["infrastructureIdentity"] = (
                {
                    "networks": {},
                    "volumes": {
                        key: value
                        for key, value in infrastructure.get("volumes", {}).items()
                        if key in retained_storage
                    },
                }
                if isinstance(infrastructure, Mapping) and retained_storage
                else None
            )
            current["driftStatus"] = "in_sync"
        transition_data: dict[str, Any] = {
            **result,
            "operationId": operation_id,
            "logEvidence": log_evidence,
            "authorityDecision": authority_reference,
            "buildContextCleanup": recovered_context_cleanup,
        }
        if partial_recovery:
            if not isinstance(interrupted_request_id, str):
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "partial cleanup lacks the interrupted authority request",
                )
            transition_data.update(
                reconciledAuthorityRequestId=interrupted_request_id,
                reconciledAuthorityOutcome={
                    "status": "failed",
                    "code": f"interrupted_{interrupted_operation}_recovered",
                    "summary": (
                        "Interrupted deployment effect was safely aborted by a separately authorized exact cleanup"
                    ),
                    "resource": {
                        "deploymentId": deployment_id,
                        "lifecycleState": "removed_runtime_data_retained",
                        "planDigest": expected_revision,
                        "observedRevision": None,
                    },
                },
            )
        updated, receipt = self.store.transition(
            deployment_id,
            "removed_runtime_data_retained",
            event=(
                "interrupted_runtime_effect_aborted"
                if partial_recovery
                else "runtime_removed_data_retained"
            ),
            actor=self.actor,
            data=transition_data,
            mutation=removed,
            expected_operation_id=operation_id,
            authority_outcome={
                "status": "succeeded",
                "code": None,
                "summary": "Deployment runtime was removed while governed retained data remained preserved",
                "resource": {
                    "planDigest": plan["planDigest"],
                    "expectedRevision": expected_revision,
                    "runtimeRemoval": deepcopy(result),
                    "runtimeRemovalDigest": digest_value(result),
                    "logEvidence": deepcopy(log_evidence),
                    "buildContextCleanup": deepcopy(recovered_context_cleanup),
                },
            },
        )
        return {"state": updated, "runtime": result, "logEvidence": log_evidence, "receipt": receipt}

    def plan_purge(
        self,
        deployment_id: str,
        *,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        state = self.store.load_state(deployment_id)
        replace_expired = False
        if state["lifecycleState"] == "awaiting_approval" and isinstance(
            state.get("desiredRevision"), str
        ):
            current = self.store.load_plan(
                deployment_id,
                state["desiredRevision"],
                require_unexpired=False,
            )
            try:
                validate_plan(current, now=datetime.now(timezone.utc))
            except DeploymentRefusal as exc:
                replace_expired = (
                    exc.code == "plan_expired"
                    and current["operation"] == "purge_data"
                )
        failed_retained = (
            state["lifecycleState"] == "failed"
            and state.get("retainedDataState") == "retained_after_failed_apply"
        )
        if (
            state["lifecycleState"] != "removed_runtime_data_retained"
            and not failed_retained
            and not replace_expired
        ):
            raise DeploymentRefusal(
                "invalid_transition",
                "data purge can only be planned for exact retained deployment data",
            )
        predecessor = state.get("acceptedRevision")
        if (
            not isinstance(predecessor, str)
            and state["lifecycleState"] == "removed_runtime_data_retained"
        ):
            predecessor = state.get("approvedPlanDigest")
        if not isinstance(predecessor, str) and failed_retained:
            predecessor = state.get("desiredRevision")
        if not isinstance(predecessor, str):
            raise DeploymentRefusal("plan_not_found", "purge requires an exact predecessor")
        prior = self.store.load_plan(deployment_id, predecessor, require_unexpired=False)
        retention_from = state.get("retainedDataState")
        if not state["storageIdentities"] or retention_from not in {
            "retained",
            "retained_after_failed_apply",
        }:
            raise DeploymentRefusal(
                "retained_data_missing",
                "data purge requires exact retained storage identities",
            )
        authority_reference = self._verify_authority(
            authority_decision,
            action="plan_deployment",
            deployment_id=deployment_id,
            run_id=prior["planDigest"],
        )
        created = datetime.now(timezone.utc).replace(microsecond=0)
        seed = {"operation": "purge_data", "predecessorRevision": predecessor, "storage": state["storageIdentities"], "createdAt": timestamp(created)}
        plan_id = "plan_" + digest_value(seed)[7:31]
        plan: dict[str, Any] = {
            "schema": PLAN_SCHEMA,
            "planId": plan_id,
            "planDigest": None,
            "operation": "purge_data",
            "predecessorRevision": predecessor,
            "createdAt": timestamp(created),
            "expiresAt": timestamp(created + timedelta(seconds=PLAN_TTL_SECONDS)),
            "spec": prior["spec"],
            "sourceInventory": prior["sourceInventory"],
            "changes": [{"kind": "storage", "action": "purge", "id": key} for key in sorted(state["storageIdentities"])],
            "risks": ["irreversible_data_loss"],
            "destructiveEffects": [{"kind": "volume", "name": value, "irreversible": True} for value in sorted(state["storageIdentities"].values())],
            "dataRetentionEffects": [{"from": retention_from, "to": "purged"}],
            "authorityDecision": {"status": "awaiting_approval", "required": ["data_purge"], "reason": "persistent data purge is separately approved and irreversible"},
            "overlay": {},
            "evidencePath": str(self.store.plan_path(deployment_id, plan_id)),
        }
        plan["planDigest"] = plan_digest(plan)
        validated = validate_plan(plan, now=created)
        self.store.add_plan(
            validated,
            actor=self.actor,
            authority_reference=authority_reference,
        )
        return validated

    def purge_data(
        self,
        deployment_id: str,
        *,
        accept_plan_digest: str,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        with self.store.operation_lock(deployment_id):
            return self._purge_data_locked(
                deployment_id,
                accept_plan_digest=accept_plan_digest,
                authority_decision=authority_decision,
            )

    def _purge_data_locked(
        self,
        deployment_id: str,
        *,
        accept_plan_digest: str,
        authority_decision: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        state = self.store.load_state(deployment_id)
        interrupted_transition = state.get("currentTransition")
        recover_interrupted = (
            state["lifecycleState"] == "reconciliation_required"
            and isinstance(interrupted_transition, Mapping)
            and interrupted_transition.get("operation") == "purge_data"
            and interrupted_transition.get("planDigest") == accept_plan_digest
            and interrupted_transition.get("phase")
            in {"failed", "observation_failed", "interrupted_observed"}
        )
        interrupted_authority = (
            interrupted_transition.get("authorityDecision")
            if recover_interrupted
            else None
        )
        interrupted_request_id = (
            interrupted_authority.get("requestId")
            if isinstance(interrupted_authority, Mapping)
            else None
        )
        if state["lifecycleState"] != "awaiting_approval" and not recover_interrupted:
            raise DeploymentRefusal("invalid_transition", "deployment is not awaiting a purge approval")
        plan = self.store.load_plan(
            deployment_id,
            accept_plan_digest,
            require_unexpired=not recover_interrupted,
        )
        authority_reference = self._verify_authority(
            authority_decision,
            action="purge_deployment_data",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
        )
        if plan["operation"] != "purge_data" or plan["planDigest"] != accept_plan_digest:
            raise DeploymentRefusal("approval_mismatch", "approval must bind the exact purge plan digest")
        expected_effects = [
            {"kind": "volume", "name": name, "irreversible": True}
            for name in sorted(state["storageIdentities"].values())
        ]
        expected_changes = [
            {"kind": "storage", "action": "purge", "id": storage_id}
            for storage_id in sorted(state["storageIdentities"])
        ]
        if (
            plan["destructiveEffects"] != expected_effects
            or plan["changes"] != expected_changes
            or plan["dataRetentionEffects"]
            != [{"from": state.get("retainedDataState"), "to": "purged"}]
            or state.get("retainedDataState")
            not in {"retained", "retained_after_failed_apply"}
        ):
            raise DeploymentRefusal(
                "stale_plan",
                "purge plan no longer matches exact retained storage",
            )
        target = self.adapter.probe()
        if target["identityDigest"] != plan["spec"]["target"]["identityDigest"]:
            raise DeploymentRefusal(
                "target_identity_changed",
                "target identity changed after purge planning",
            )
        if recover_interrupted:
            _reserved, _reservation, operation_id = (
                self.store.reserve_runtime_operation(
                    deployment_id,
                    operation="purge_data",
                    actor=self.actor,
                    allowed_states={"reconciliation_required"},
                    plan_digest=plan["planDigest"],
                    authority_reference=authority_reference,
                    supersede_interrupted=True,
                )
            )
            approval_receipts: list[dict[str, Any]] = []
        else:
            _reserved, approval_receipts, operation_id = (
                self.store.approve_and_reserve(
                    deployment_id,
                    plan,
                    actor=self.actor,
                    authority_reference=authority_reference,
                )
            )
        predecessor_revision = plan.get("predecessorRevision")
        if not isinstance(predecessor_revision, str):
            raise DeploymentRefusal(
                "state_invalid",
                "purge requires an exact predecessor revision",
            )
        try:
            with self._adapter_operation(operation_id, authority_reference):
                result = self.adapter.purge_data(
                    plan["spec"],
                    expected_volumes=state["storageIdentities"],
                    expected_revision=predecessor_revision,
                    recover_interrupted=recover_interrupted,
                )
            if result.get("verifiedAbsent") is not True:
                raise AdapterError("purge_verification_failed", "data purge was not directly verified")
        except (AdapterError, DeploymentRefusal) as exc:
            details = dict(getattr(exc, "details", {}))
            failure_code = getattr(exc, "code", "purge_failed")

            def failed(current: dict[str, Any]) -> None:
                transition = deepcopy(current["currentTransition"])
                transition.update(
                    phase="failed",
                    failureCode=failure_code,
                )
                current["currentTransition"] = transition
                current["driftStatus"] = "unknown"
            self.store.transition(
                deployment_id,
                "reconciliation_required",
                event="purge_failed",
                actor=self.actor,
                data={
                    "operationId": operation_id,
                    "failureCode": getattr(exc, "code", "purge_failed"),
                    "details": details,
                    "authorityDecision": authority_reference,
                },
                mutation=failed,
                expected_operation_id=operation_id,
                authority_outcome={
                    "status": "failed",
                    "code": getattr(exc, "code", "purge_failed"),
                    "summary": "Exact persistent-data purge failed and requires observed-state reconciliation",
                    "resource": {
                        "purgePlanDigest": plan["planDigest"],
                        "predecessorRevision": predecessor_revision,
                        "expectedStorageIdentities": deepcopy(
                            state["storageIdentities"]
                        ),
                        "failureDetailsDigest": digest_value(details),
                    },
                },
            )
            raise
        def purged(current: dict[str, Any]) -> None:
            current["currentTransition"] = None
            current["storageIdentities"] = {}
            current["infrastructureIdentity"] = None
            current["retainedDataState"] = "purged"
            current["removalState"] = "runtime_removed_data_purged"
            current["desiredRevision"] = None
            current["approvedPlanDigest"] = accept_plan_digest
            current["driftStatus"] = "in_sync"
        transition_data: dict[str, Any] = {
            **result,
            "operationId": operation_id,
            "authorityDecision": authority_reference,
        }
        if recover_interrupted:
            if not isinstance(interrupted_request_id, str):
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "purge recovery lacks the interrupted authority request",
                )
            transition_data.update(
                reconciledAuthorityRequestId=interrupted_request_id,
                reconciledAuthorityOutcome={
                    "status": "failed",
                    "code": "interrupted_purge_recovered",
                    "summary": "Interrupted exact data purge was completed by a separately authorized bounded recovery",
                    "resource": {
                        "deploymentId": deployment_id,
                        "lifecycleState": "purged",
                        "planDigest": plan["planDigest"],
                        "observedRevision": None,
                    },
                },
            )
        updated, receipt = self.store.transition(
            deployment_id,
            "purged",
            event=(
                "interrupted_purge_recovered"
                if recover_interrupted
                else "persistent_data_purged"
            ),
            actor=self.actor,
            data=transition_data,
            mutation=purged,
            expected_operation_id=operation_id,
            authority_outcome={
                "status": "succeeded",
                "code": None,
                "summary": "Separately approved persistent storage was verified absent",
                "resource": {
                    "purgePlanDigest": plan["planDigest"],
                    "predecessorRevision": predecessor_revision,
                    "purgeResult": deepcopy(result),
                    "purgeResultDigest": digest_value(result),
                },
            },
        )
        return {"state": updated, "runtime": result, "approvalReceipts": approval_receipts, "receipt": receipt}

    def link_authority_receipt(
        self,
        deployment_id: str,
        receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Copy and bind one canonical action receipt to deployment truth."""

        if self._authority_manager is None:
            raise DeploymentRefusal(
                "authority_required",
                "canonical authority manager is required to link receipts",
            )
        receipt_id = receipt.get("receiptId")
        if not isinstance(receipt_id, str):
            raise DeploymentRefusal(
                "authority_receipt_invalid", "authority receipt identity is invalid"
            )
        try:
            canonical_receipt = self._authority_manager.get_receipt(receipt_id)
        except AuthorityError as exc:
            raise DeploymentRefusal(
                "authority_receipt_invalid",
                "authority receipt is not present in canonical private state",
                details={"authorityCode": exc.code},
            ) from exc
        if canonical_receipt != dict(receipt):
            raise DeploymentRefusal(
                "authority_receipt_invalid",
                "authority receipt differs from canonical private state",
            )
        decision_reference = self.store.authority_decision_reference(
            deployment_id, canonical_receipt.get("requestId")
        )
        reference = validate_authority_receipt(
            canonical_receipt,
            deployment_id=deployment_id,
            grant_id=decision_reference.get("grantId"),
            actor=self.actor,
            action=decision_reference.get("action"),
        )
        if (
            decision_reference.get("decisionDigest")
            != reference.get("decisionDigest")
            or decision_reference.get("action") != reference.get("action")
            or decision_reference.get("grantId") != reference.get("grantId")
            or decision_reference.get("reservationId")
            != reference.get("reservationId")
            or decision_reference.get("reservationDigest")
            != reference.get("reservationDigest")
            or decision_reference.get("claimId") != reference.get("claimId")
            or decision_reference.get("claimDigest")
            != reference.get("claimDigest")
        ):
            raise DeploymentRefusal(
                "authority_receipt_unbound",
                "authority receipt does not resolve the reserved deployment decision",
            )
        evidence, evidence_document = self.store.prepare_evidence(
            deployment_id,
            kind="authority_receipt",
            value=canonical_receipt,
        )
        reference = {**reference, "evidence": evidence}
        updated, link_receipt, already_linked = self.store.link_authority_receipt(
            deployment_id,
            actor=self.actor,
            reference=reference,
            evidence_document=evidence_document,
        )
        return {
            "state": updated,
            "authorityReceipt": reference,
            "receipt": link_receipt,
            "alreadyLinked": already_linked,
        }

    def reconcile_authority_receipts(
        self,
        deployment_id: str,
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Link finalized canonical receipts without replaying deployment effects."""

        if self._authority_manager is None:
            raise DeploymentRefusal(
                "authority_required",
                "canonical authority manager is required to reconcile receipts",
            )
        references = self.store.authority_decision_references(deployment_id)
        if request_id is None:
            linked_request_ids = {
                item.get("requestId")
                for item in self.store.load_state(deployment_id)[
                    "authorityReceipts"
                ]
            }
            references = [
                reference
                for reference in references
                if reference.get("requestId") not in linked_request_ids
            ]
        else:
            references = [
                reference
                for reference in references
                if reference.get("requestId") == request_id
            ]
            if not references:
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "deployment has no committed decision for this authority request",
                )
        linked: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = []
        for reference in references:
            exact_request_id = reference["requestId"]
            try:
                canonical = self._authority_manager.get_receipt_for_request(
                    exact_request_id
                )
            except AuthorityError as exc:
                raise DeploymentRefusal(
                    "authority_receipt_invalid",
                    "canonical authority receipt state could not be resolved",
                    details={"authorityCode": exc.code},
                ) from exc
            if canonical is None:
                claimed = self._authority_manager.has_claim(exact_request_id)
                outcome = (
                    self.store.authority_effect_outcome(
                        deployment_id, exact_request_id
                    )
                    if claimed
                    else None
                )
                if outcome is not None:
                    try:
                        reservation = self._authority_manager.get_reservation(
                            exact_request_id
                        )
                        claim = self._authority_manager.get_claim(exact_request_id)
                        canonical = self._authority_manager.record_action(
                            reservation["decision"],
                            result_status=outcome["status"],
                            summary=outcome["summary"],
                            code=outcome["code"],
                            resource=outcome["resource"],
                            reservation=reservation,
                            claim=claim,
                        )
                    except AuthorityError as exc:
                        if exc.code == "duplicate_record":
                            canonical = (
                                self._authority_manager.get_receipt_for_request(
                                    exact_request_id
                                )
                            )
                        if canonical is None:
                            raise DeploymentRefusal(
                                "authority_receipt_invalid",
                                "durably reconciled authority outcome could not be finalized canonically",
                                details={"authorityCode": exc.code},
                            ) from exc
                    if canonical is None:
                        raise DeploymentRefusal(
                            "authority_receipt_invalid",
                            "durably reconciled authority outcome has no canonical receipt",
                        )
                    linked.append(
                        self.link_authority_receipt(deployment_id, canonical)
                    )
                    continue
                unresolved.append(
                    {
                        "requestId": exact_request_id,
                        "claimExists": claimed,
                        "classification": (
                            "authority_effect_unfinalized"
                            if claimed
                            else "authority_decision_unfinalized"
                        ),
                    }
                )
                continue
            linked.append(self.link_authority_receipt(deployment_id, canonical))
        if unresolved:
            raise DeploymentRefusal(
                "authority_effect_unfinalized",
                "a deployment effect claim has no terminal canonical receipt and must not be replayed",
                details={"unresolved": unresolved, "linked": linked},
            )
        return {
            "deploymentId": deployment_id,
            "links": linked,
            "state": self.store.load_state(deployment_id),
        }


__all__ = ["DeploymentService", "NODE_BASE", "PYTHON_BASE"]
