"""Fresh operation metadata, without source inspection or execution payloads."""
from typing import Any
from .infrastructure import InfrastructureError, LocalLibvirtAdapter

from stateport_portable_execution import PortableExecutionError


def operation_projection(app: Any, execution: Any) -> dict[str, Any]:
    # Read the authoritative catalog and run store once each. No cached ownership:
    # forgotten or rebound applications disappear on the next request.
    owners = {entry["instanceId"]: entry for entry in app.catalog.operation_owners()}
    runs = []
    for record in execution.store.all():
        owner = owners.get(record.get("instanceId"))
        if owner is None or record.get("applicationId") != owner.get("applicationId"):
            continue
        receipt = record.get("closureReceipt")
        receipt_id = record.get("receiptId")
        if receipt is not None or receipt_id is not None or (
            record.get("status") == "applied" and record.get("lifecycleState") == "CLOSED"
        ):
            if not isinstance(receipt, dict) or receipt.get("receiptId") != receipt_id:
                raise PortableExecutionError("governed run closure receipt identity drifted")
            execution._validate_run_closure_receipt(record, receipt)
        public = {key: record[key] for key in (
            "runId", "id", "instanceId", "applicationId", "actionId", "engineId",
            "formatVersion", "lifecycleState", "revision", "status", "state",
            "requestedAt", "createdAt", "updatedAt",
        ) if key in record}
        engine = record.get("engine")
        if isinstance(engine, dict) and "engineId" in engine:
            public["engineId"] = engine["engineId"]
        if "updatedAt" not in public:
            timestamps = [event.get("at") for event in record.get("events", []) if event.get("at")]
            if timestamps:
                public["updatedAt"] = timestamps[-1]
        if receipt_id is not None:
            public["receiptId"] = receipt_id
        for key, value in public.items():
            if (key == "revision" and (type(value) is not int or value < 0)) or (
                key != "revision" and not isinstance(value, str)
            ):
                raise PortableExecutionError("operation metadata is invalid")
        runs.append(public)
    infrastructure = []
    observation_errors = []
    for instance_id, owner in owners.items():
        if owner.get('infrastructure') is not True:
            continue
        try:
            binding = LocalLibvirtAdapter.current_repository_binding(owner.get('repositoryPath'), owner.get('repositoryFilesystem'))
            plans, errors = LocalLibvirtAdapter.stored_operations(
                state_root=app.layout.state_root / 'infrastructure' / instance_id,
                instance_id=instance_id, repository_binding=binding)
            infrastructure.extend(plans)
            observation_errors.extend(errors)
        except (InfrastructureError, OSError) as exc:
            observation_errors.append({'instanceId': instance_id,
                                       'code': exc.code if isinstance(exc, InfrastructureError) else 'operation_store_unavailable',
                                       'message': str(exc) if isinstance(exc, InfrastructureError) else 'Stored infrastructure operations could not be read.'})
    return {"formatVersion": "stateport.operations/v1", "runs": runs,
            "infrastructureInstanceIds": [key for key, owner in owners.items() if owner.get('infrastructure') is True],
            "infrastructurePlans": infrastructure, "observationErrors": observation_errors}
