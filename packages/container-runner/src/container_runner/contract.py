from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class ExecutionPlan:
    template_path: str
    instance_path: str
    runtime_path: str
    lease_id: str
    network_enabled: bool = False
    template_read_only: bool = True
    root_read_only: bool = True
    run_as_non_root: bool = True
    transactional_validation: bool = True

    def validate(self) -> None:
        for name in ("template_path", "instance_path", "runtime_path", "lease_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} is required")
        paths = [Path(self.template_path).resolve(), Path(self.instance_path).resolve(), Path(self.runtime_path).resolve()]
        if len(set(paths)) != 3:
            raise ValueError("template, instance, and runtime paths must be distinct")
        template, instance, runtime = paths
        for protected, label in ((template, "template"), (instance, "instance")):
            if runtime.is_relative_to(protected) or protected.is_relative_to(runtime):
                raise ValueError(f"runtime path must not overlap the {label} path")
        if self.network_enabled:
            raise ValueError("network must be disabled by default and cannot be enabled by this contract")
        if not self.template_read_only or not self.root_read_only or not self.run_as_non_root or not self.transactional_validation:
            raise ValueError("execution plan violates mandatory isolation controls")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {"formatVersion": "stateport.container-execution/v1", "template": {"path": self.template_path, "readOnly": self.template_read_only},
                "instance": {"path": self.instance_path, "writable": False, "singleWriterLease": self.lease_id},
                "runtime": {"path": self.runtime_path, "ephemeral": True}, "network": {"enabled": self.network_enabled},
                "security": {"rootReadOnly": self.root_read_only, "runAsNonRoot": self.run_as_non_root,
                              "noPrivilegeEscalation": True, "transactionalValidation": self.transactional_validation},
                "apply": False}

    @classmethod
    def from_dict(cls, value: Any) -> "ExecutionPlan":
        """Parse a persisted plan without accepting relaxed isolation fields."""

        if not isinstance(value, Mapping) or set(value) != {
            "formatVersion",
            "template",
            "instance",
            "runtime",
            "network",
            "security",
            "apply",
        }:
            raise ValueError("execution plan has an invalid shape")
        if value.get("formatVersion") != "stateport.container-execution/v1":
            raise ValueError("execution plan has an invalid formatVersion")
        template = value.get("template")
        instance = value.get("instance")
        runtime = value.get("runtime")
        network = value.get("network")
        security = value.get("security")
        if not all(isinstance(item, Mapping) for item in (template, instance, runtime, network, security)):
            raise ValueError("execution plan sections must be mappings")
        if set(template) != {"path", "readOnly"} or template.get("readOnly") is not True:
            raise ValueError("execution template must be read-only")
        if set(instance) != {"path", "writable", "singleWriterLease"} or instance.get("writable") is not False:
            raise ValueError("execution instance must be read-only in container_echo v1")
        if set(runtime) != {"path", "ephemeral"} or runtime.get("ephemeral") is not True:
            raise ValueError("execution runtime must be ephemeral")
        if set(network) != {"enabled"} or network.get("enabled") is not False:
            raise ValueError("execution network must be disabled")
        if set(security) != {
            "rootReadOnly",
            "runAsNonRoot",
            "noPrivilegeEscalation",
            "transactionalValidation",
        } or any(security.get(field) is not True for field in security):
            raise ValueError("execution security controls are invalid")
        if value.get("apply") is not False:
            raise ValueError("execution plan apply must remain false")
        plan = cls(
            template_path=template.get("path"),
            instance_path=instance.get("path"),
            runtime_path=runtime.get("path"),
            lease_id=instance.get("singleWriterLease"),
        )
        plan.validate()
        return plan
