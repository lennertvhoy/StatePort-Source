"""Control-plane adapter for independent validator workloads."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Mapping

from runtime_contracts import ValidatorSpec, canonical_digest

from .client import ExecutionHostClient
from .staging_identity import StagingIdentityError, staging_manifest_digest


class ValidatorRuntimeError(RuntimeError):
    """Validator admission or execution refusal."""


_IMAGE_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


class ValidatorRuntime:
    """Lower ValidatorSpec commands into sealed execution-host workloads."""

    def __init__(self, client: ExecutionHostClient, *, image_reference: str) -> None:
        if _IMAGE_REFERENCE.fullmatch(image_reference) is None:
            raise ValidatorRuntimeError("validator image reference must be digest-pinned")
        self._client = client
        self._image_reference = image_reference

    def _staging_identity(self, path: Path) -> str:
        try:
            return staging_manifest_digest(path)
        except StagingIdentityError as exc:
            raise ValidatorRuntimeError(str(exc)) from exc

    def run(self, value: Mapping[str, Any]) -> dict[str, Any]:
        validator = ValidatorSpec.from_dict(value)
        data = validator.to_dict()
        image_digest = data["imageDigest"]
        if not self._image_reference.endswith("@" + image_digest):
            raise ValidatorRuntimeError("validator image reference does not match ValidatorSpec.imageDigest")
        staging_path = Path(data["stagingPath"])
        staging_identity_digest = self._staging_identity(staging_path)
        results: list[dict[str, Any]] = []
        for ordinal, command in enumerate(data["commands"], start=1):
            current_staging_identity_digest = self._staging_identity(staging_path)
            if current_staging_identity_digest != staging_identity_digest:
                raise ValidatorRuntimeError("validator staging mutated before execution")
            command_digest = canonical_digest(command)
            workload_id = (
                f"validator-run-{data['validatorId'][:80]}-"
                f"{hashlib.sha256((command_digest + str(ordinal)).encode()).hexdigest()[:16]}"
            )
            workload = {
                "kind": "validator-run",
                "workloadId": workload_id,
                "image": {"reference": self._image_reference},
                "parameters": {
                    "validatorId": data["validatorId"],
                    "validatorSpecDigest": validator.digest,
                    "stagingIdentityDigest": staging_identity_digest,
                    "stagingPath": staging_path.as_posix(),
                    "commandDigest": command_digest,
                    "command": list(command),
                    "network": "disabled",
                    "stagingReadOnly": True,
                    "providerAccess": False,
                    "runtimeSocketAccess": False,
                    "hostMounts": [],
                },
                "timeoutSeconds": data["timeoutSeconds"],
                "outputByteBound": data["outputByteBound"],
                "resources": data["resources"],
            }
            receipt = self._client.run_validator(workload)
            result = receipt.get("result")
            if not isinstance(result, Mapping):
                raise ValidatorRuntimeError("execution host returned no validator result")
            results.append({"ordinal": ordinal, **dict(result)})
        return {
            "formatVersion": "stateport.validator-run-result/v1",
            "validatorId": data["validatorId"],
            "validatorSpecDigest": validator.digest,
            "status": "passed" if results and all(item["status"] == "passed" for item in results) else "failed",
            "commands": results,
            "evidenceDigests": [item["evidenceDigest"] for item in results],
            "evidenceDigest": canonical_digest(results),
        }


__all__ = ["ValidatorRuntime", "ValidatorRuntimeError"]
