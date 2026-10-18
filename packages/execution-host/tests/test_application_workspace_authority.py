"""Real filesystem authority transaction tests; no root/container effects."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages/execution-host/src"))
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))
sys.path.insert(0, str(ROOT / "packages/updater/src"))
from execution_host import application_workspaces as authority
from execution_host import daemon_contract as contract
from execution_host.grants import GrantRefusal, GrantStore
from stateport_release.execution_host_provisioning import default_sealed_workspace_workload

NOW = "2026-09-06T00:00:00Z"


def write(path, value, mode=0o600):
    path.write_bytes(authority._authority_bytes(value))
    path.chmod(mode)


@pytest.fixture
def case(tmp_path, monkeypatch):
    # No runtime/public UID override: only this unit test patches private constants.
    monkeypatch.setattr(authority, "_ROOT_UID", os.geteuid())
    monkeypatch.setattr(authority, "_EXEC_UID", os.geteuid())
    grants, public = tmp_path / "grants", tmp_path / "public"
    grants.mkdir(mode=0o700)
    public.mkdir(mode=0o755)
    receipts = public / "receipts"
    receipts.mkdir(mode=0o755)
    revocation = {"revocationEpoch": 4, "revokedGrantIds": ["unrelated-revoked"], "pausedGrantIds": ["unrelated-paused"]}
    write(grants / "revocation.json", revocation)
    default = default_sealed_workspace_workload()
    request = {"formatVersion": authority.REQUEST_FORMAT, "instanceId": "example", "applicationId": "projectstate",
               "catalogIdentityDigest": "sha256:" + "a" * 64, "issuerContextDigest": "sha256:" + "b" * 64,
               "profileDigest": contract.canonical_digest(default), "sourceMode": "empty", "createdAt": NOW,
               "expiresAt": "2026-09-06T00:15:00Z", "grantExpiresAt": "2026-10-06T00:00:00Z"}
    request["requestDigest"] = contract.canonical_digest(request)
    wid = authority.workspace_authority_workload_id(request)
    spec = deepcopy(default)
    spec["workloadId"] = spec["parameters"]["workspaceId"] = wid
    spec["parameters"]["volumeName"] = "stateport-workspace-" + wid
    spec["parameters"]["ownership"] = {"instanceId": request["instanceId"], "applicationId": request["applicationId"],
                                         "catalogIdentityDigest": request["catalogIdentityDigest"], "runId": None}
    spec = contract.validate_workload_spec(spec)
    grant = {"formatVersion": "stateport.execution-host-grant/v2", "grantId": "workspace-grant-" + request["requestDigest"][7:39],
             "peerUid": 65531, "operations": ["createWorkload", "listWorkloads", "status", "start", "stop", "logs", "execWorkload", "removeWorkload"],
             "workloadIds": [wid], "workloadKinds": ["workspace"], "workloadSpecDigests": {wid: contract.canonical_digest(spec)},
             "imageReference": spec["image"]["reference"], "baseRevision": None, "issuedAt": NOW,
             "expiresAt": request["grantExpiresAt"], "revocationEpoch": 4,
             "budgets": {"maxTimeoutSeconds": 3600, "maxOutputBytes": 65536, "maxMemoryMaxBytes": 268435456,
                         "maxPidsMax": 128, "maxActiveWorkloads": 1, "maxCpuQuotaPercent": 100, "maxDiskMaxBytes": 268435456}}
    binding = {"grantId": grant["grantId"], "authorityGrantDigest": contract.canonical_digest(grant), "workload": spec}
    args = {"grant": grant, "binding": binding, "context_digest": request["issuerContextDigest"],
            "operator": {"user": "operator", "uid": 1000, "gid": 1000}, "grants_dir": grants,
            "bindings_path": public / "bindings.json", "receipt_dir": receipts,
            "verify_current": lambda: None, "clock": lambda: NOW}
    return request, args


def issue(case):
    request, args = case
    return authority.issue_workspace_authority(request, **args)


def store(case):
    return GrantStore(case[1]["grants_dir"], clock=lambda: NOW)


def test_publication_is_live_exact_private_and_idempotent(case):
    result = issue(case)
    request, args = case
    assert result["status"] == "issued"
    assert store(case).assert_live(args["grant"]["grantId"])["workloadIds"] == args["grant"]["workloadIds"]
    snapshot = {p: (p.read_bytes(), p.stat().st_ino) for p in args["grants_dir"].iterdir() if p.is_file()}
    assert issue(case) == result
    assert snapshot == {p: (p.read_bytes(), p.stat().st_ino) for p in args["grants_dir"].iterdir() if p.is_file()}
    assert (args["grants_dir"] / (args["grant"]["grantId"] + ".json")).stat().st_mode & 0o777 == 0o600
    assert args["bindings_path"].stat().st_mode & 0o777 == 0o644
    receipt = args["receipt_dir"] / (request["requestDigest"][7:] + ".json")
    assert receipt.stat().st_mode & 0o777 == 0o644
    assert (args["receipt_dir"] / ".transactions").stat().st_mode & 0o777 == 0o700
    rev = json.loads((args["grants_dir"] / "revocation.json").read_text())
    assert rev == {"revocationEpoch": 4, "revokedGrantIds": ["unrelated-revoked"], "pausedGrantIds": ["unrelated-paused"]}


@pytest.mark.parametrize("phase", ["prepared", "paused", "grant-written", "binding-published", "before-activation", "activated"])
def test_interrupted_transaction_resumes_only_exact_owned_state(case, monkeypatch, phase):
    def interrupt(actual):
        if actual == phase:
            raise RuntimeError("injected interruption")
    monkeypatch.setattr(authority, "_authority_checkpoint", interrupt)
    with pytest.raises(RuntimeError, match="injected"):
        issue(case)
    args = case[1]
    receipt = args["receipt_dir"] / (case[0]["requestDigest"][7:] + ".json")
    assert not receipt.exists()
    if phase != "activated":
        with pytest.raises(GrantRefusal):
            store(case).assert_live(args["grant"]["grantId"])
    monkeypatch.setattr(authority, "_authority_checkpoint", lambda phase: None)
    assert issue(case)["status"] == "issued"
    assert issue(case)["status"] == "issued"


@pytest.mark.parametrize("change", ["revoke", "epoch", "unrelated", "refresh-pause"])
def test_concurrent_revocation_is_preserved_and_never_activated(case, monkeypatch, change):
    path = case[1]["grants_dir"] / "revocation.json"
    observed = None
    def change_state(phase):
        nonlocal observed
        if phase != "before-activation":
            return
        value = json.loads(path.read_text())
        if change == "revoke": value["revokedGrantIds"].append(case[1]["grant"]["grantId"])
        if change == "epoch": value["revocationEpoch"] += 1
        if change == "unrelated": value["revokedGrantIds"].append("new-unrelated")
        write(path, value)
        observed = path.read_bytes()
    monkeypatch.setattr(authority, "_authority_checkpoint", change_state)
    with pytest.raises(ValueError): issue(case)
    assert path.read_bytes() == observed
    with pytest.raises(GrantRefusal): store(case).assert_live(case[1]["grant"]["grantId"])
    monkeypatch.setattr(authority, "_authority_checkpoint", lambda phase: None)
    with pytest.raises(ValueError): issue(case)
    assert path.read_bytes() == observed


@pytest.mark.parametrize("state", ["missing", "corrupt", "symlink", "world-readable"])
def test_invalid_private_revocation_refuses_without_grant(case, state, tmp_path):
    path = case[1]["grants_dir"] / "revocation.json"
    if state == "missing": path.unlink()
    if state == "corrupt": path.write_text("not JSON")
    if state == "world-readable": path.chmod(0o644)
    if state == "symlink":
        other = tmp_path / "other.json"
        other.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(other)
    with pytest.raises((ValueError, OSError)): issue(case)
    assert not (case[1]["grants_dir"] / (case[1]["grant"]["grantId"] + ".json")).exists()


@pytest.mark.parametrize("field,value", [("peerUid", 1000), ("workloadIds", ["default-dev"]), ("operations", ["createWorkload", "runValidator"]), ("expiresAt", "2999-01-01T00:00:00Z")])
def test_grant_expansion_refuses_before_writes(case, field, value):
    case[1]["grant"][field] = value
    case[1]["binding"]["authorityGrantDigest"] = contract.canonical_digest(case[1]["grant"])
    with pytest.raises(ValueError): issue(case)
    assert not list(case[1]["receipt_dir"].iterdir())


def test_context_changes_after_binding_leaves_only_paused_grant(case, monkeypatch):
    # The captured callback checks current installed state, never mutable arguments.
    stale = False
    def check():
        if stale: raise ValueError("stale context")
    def checkpoint(phase):
        nonlocal stale
        stale = phase == "binding-published"
    case[1]["verify_current"] = check
    monkeypatch.setattr(authority, "_authority_checkpoint", checkpoint)
    with pytest.raises(ValueError, match="stale context"): issue(case)
    with pytest.raises(GrantRefusal): store(case).assert_live(case[1]["grant"]["grantId"])


def test_request_extra_authority_and_digest_changes_refuse(case):
    request = deepcopy(case[0])
    request["path"] = "/host"
    with pytest.raises(ValueError): authority.validate_workspace_authority_request(request)
    request = deepcopy(case[0]); request["applicationId"] = "other"
    with pytest.raises(ValueError): authority.validate_workspace_authority_request(request)


def test_completed_revoked_authority_is_never_reactivated(case):
    issue(case)
    path = case[1]["grants_dir"] / "revocation.json"
    rev = json.loads(path.read_text()); rev["revokedGrantIds"].append(case[1]["grant"]["grantId"])
    write(path, rev); before = path.read_bytes()
    with pytest.raises(ValueError, match="revoked"): issue(case)
    assert path.read_bytes() == before


@pytest.mark.parametrize("target", ["binding", "grant", "directory"])
def test_publication_swap_before_activation_refuses(case, monkeypatch, target):
    def change(phase):
        if phase != "before-activation": return
        args = case[1]
        if target == "directory":
            directory = args["bindings_path"].parent
            directory.rename(directory.with_name("replaced-public"))
            directory.mkdir(mode=0o755)
        else:
            path = args["bindings_path"] if target == "binding" else args["grants_dir"] / (args["grant"]["grantId"] + ".json")
            # Same bytes with a replacement inode still fails the exact CAS.
            data, mode = path.read_bytes(), path.stat().st_mode & 0o777
            path.unlink(); path.write_bytes(data); path.chmod(mode)
    monkeypatch.setattr(authority, "_authority_checkpoint", change)
    with pytest.raises((ValueError, OSError)): issue(case)
    with pytest.raises(GrantRefusal): store(case).assert_live(case[1]["grant"]["grantId"])


def test_unrelated_grants_and_bindings_survive(case):
    args = case[1]
    sentinel = args["grants_dir"] / "default-dev.json"
    sentinel.write_bytes(b"unrelated grant bytes\n"); sentinel.chmod(0o600)
    previous = deepcopy(args["binding"])
    previous["grantId"] = "another-grant"
    previous["workload"]["workloadId"] = "another-workspace"
    previous["workload"]["parameters"]["workspaceId"] = "another-workspace"
    previous["workload"]["parameters"]["volumeName"] = "stateport-workspace-another-workspace"
    previous["workload"]["parameters"]["ownership"]["instanceId"] = "another-instance"
    write(args["bindings_path"], {"formatVersion": authority.FORMAT, "bindings": [previous]}, 0o644)
    before = sentinel.read_bytes(), sentinel.stat().st_ino
    issue(case)
    assert (sentinel.read_bytes(), sentinel.stat().st_ino) == before
    assert json.loads(args["bindings_path"].read_text())["bindings"][0] == previous


def test_different_grant_for_same_workspace_requires_explicit_renewal(case):
    previous = deepcopy(case[1]["binding"]); previous["grantId"] = "prior-grant"
    write(case[1]["bindings_path"], {"formatVersion": authority.FORMAT, "bindings": [previous]}, 0o644)
    with pytest.raises(ValueError, match="renewal_unsupported"): issue(case)
    assert json.loads(case[1]["bindings_path"].read_text())["bindings"] == [previous]


@pytest.mark.parametrize("mutation", ["request", "operator", "binding"])
def test_mutable_input_change_during_revalidation_refuses(case, mutation):
    def verify():
        if mutation == "operator": case[1]["operator"]["uid"] = 2000
        elif mutation == "binding": case[1]["binding"]["workload"]["parameters"]["ownership"]["applicationId"] = "changed"
        # request scalars are defensively copied by validation, so caller edits
        # cannot change the independently frozen request or resulting authority.
        else: case[0]["instanceId"] = "changed"
    case[1]["verify_current"] = verify
    if mutation == "request":
        assert issue(case)["instanceId"] == "example"
    else:
        with pytest.raises(ValueError, match="inputs changed"): issue(case)


@pytest.mark.parametrize("now", ["2026-09-05T23:59:59Z", "2026-09-06T00:15:00Z", "2026-10-07T00:00:00Z"])
def test_review_expiry_and_future_request_refuse(case, now):
    case[1]["clock"] = lambda: now
    with pytest.raises(ValueError, match="expired"): issue(case)
    assert not case[1]["bindings_path"].exists()


def test_unproven_activation_gap_refuses_receipt_recovery(case, monkeypatch):
    create = authority._authority_create
    def interrupt(directory, name, *args, **kwargs):
        if name.endswith(".activated.json"):
            raise RuntimeError("unobserved hard crash")
        return create(directory, name, *args, **kwargs)
    monkeypatch.setattr(authority, "_authority_create", interrupt)
    with pytest.raises(RuntimeError): issue(case)
    monkeypatch.setattr(authority, "_authority_create", create)
    with pytest.raises(ValueError, match="recovery is unproven"): issue(case)
    assert not (case[1]["receipt_dir"] / (case[0]["requestDigest"][7:] + ".json")).exists()


def test_concurrent_exact_issuance_serializes_to_identical_receipt(case):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(issue, case)
        second = pool.submit(issue, case)
        assert first.result(timeout=5) == second.result(timeout=5)


def test_recovered_intent_records_actual_activation_time(case, monkeypatch):
    def interrupt(phase):
        if phase == "before-activation": raise RuntimeError("interrupted intent")
    monkeypatch.setattr(authority, "_authority_checkpoint", interrupt)
    with pytest.raises(RuntimeError): issue(case)
    case[1]["clock"] = lambda: "2026-09-06T00:01:00Z"
    monkeypatch.setattr(authority, "_authority_checkpoint", lambda phase: None)
    assert issue(case)["activatedAt"] == "2026-09-06T00:01:00Z"


def transport(case):
    args = case[1]
    return {"formatVersion": authority.TRANSPORT_FORMAT,
            "bindings": [{**deepcopy(args["binding"]), "grant": deepcopy(args["grant"])}]}


def test_transport_preimage_is_untrusted_detached_and_v1_stays_strict(case, tmp_path):
    raw = transport(case)
    path = tmp_path / "transport.json"
    write(path, raw, 0o666)
    observed = authority.read_binding_transport(path)
    assert observed == raw["bindings"]
    raw["bindings"][0]["workload"]["parameters"]["ownership"]["applicationId"] = "changed"
    assert observed[0]["workload"]["parameters"]["ownership"]["applicationId"] != "changed"
    with pytest.raises(ValueError):
        authority.read_bindings(path, operator_uid=os.geteuid())
    write(path, {"formatVersion": authority.FORMAT, "bindings": [case[1]["binding"]]})
    with pytest.raises(ValueError, match="v2"):
        authority.read_binding_transport(path)
    path.unlink()
    with pytest.raises(OSError):
        authority.read_binding_transport(path)


@pytest.mark.parametrize("change", ["digest", "grant_id", "spec", "image", "operations", "peer", "extra_workload", "missing_preimage"])
def test_transport_refuses_tampered_preimages(case, change):
    raw = transport(case)
    row = raw["bindings"][0]
    if change == "digest":
        row["authorityGrantDigest"] = "sha256:" + "f" * 64
    elif change == "grant_id":
        row["grant"]["grantId"] = "other"
    elif change == "spec":
        row["workload"]["parameters"]["ownership"]["applicationId"] = "other"
    elif change == "image":
        row["grant"]["imageReference"] = "docker.io/library/other@sha256:" + "a" * 64
    elif change == "operations":
        row["grant"]["operations"].remove("listWorkloads")
    elif change == "peer":
        row["grant"]["peerUid"] = 12345
    elif change == "extra_workload":
        row["grant"]["workloadIds"].append("other")
    else:
        del row["grant"]
    if change in {"image", "operations", "peer", "extra_workload"}:
        row["authorityGrantDigest"] = contract.canonical_digest(row["grant"])
    with pytest.raises(ValueError):
        authority.validate_binding_transport(raw)


def test_self_consistent_transport_still_requires_private_daemon(case):
    issue(case)
    raw = transport(case)
    row = raw["bindings"][0]
    row["workload"]["parameters"]["ownership"]["applicationId"] = "other"
    row["grant"]["workloadSpecDigests"][row["workload"]["workloadId"]] = contract.canonical_digest(row["workload"])
    row["authorityGrantDigest"] = contract.canonical_digest(row["grant"])
    assert authority.validate_binding_transport(raw)
    with pytest.raises(GrantRefusal, match="digest"):
        store(case).verify(request={"requester": {"grantId": row["grantId"], "authorityGrantDigest": row["authorityGrantDigest"]}, "operation": "listWorkloads", "timeoutSeconds": 1, "outputByteBound": 1024}, peer_uid=65531, payload={}, active_count=lambda _: 0)


@pytest.mark.parametrize("kind", ["symlink", "parent_symlink", "hardlink", "oversize", "directory"])
def test_transport_refuses_unsafe_input_types(case, tmp_path, kind):
    path = tmp_path / "input.json"
    write(path, transport(case))
    if kind == "symlink":
        target = tmp_path / "link"
        target.symlink_to(path)
        path = target
    elif kind == "parent_symlink":
        parent = tmp_path / "parent"
        parent.symlink_to(tmp_path, target_is_directory=True)
        path = parent / path.name
    elif kind == "hardlink":
        os.link(path, tmp_path / "other")
    elif kind == "oversize":
        path.write_bytes(b"x" * (authority.MAX_BYTES + 1))
    else:
        path = tmp_path
    with pytest.raises((ValueError, OSError)):
        authority.read_binding_transport(path)


def test_v2_transaction_publishes_exact_preimage_and_preserves_receipt(case):
    case[1]["binding_format"] = authority.TRANSPORT_FORMAT
    result = issue(case)
    args = case[1]
    rows = authority.read_binding_transport(args["bindings_path"])
    assert rows == transport(case)["bindings"]
    assert result["bindingDigest"] == contract.canonical_digest(args["binding"])
    row = rows[0]
    verified = store(case).verify(request={"requester": {"grantId": row["grantId"], "authorityGrantDigest": row["authorityGrantDigest"]}, "operation": "listWorkloads", "timeoutSeconds": 1, "outputByteBound": 1024}, peer_uid=65531, payload={}, active_count=lambda _: 0)
    assert verified["workloadSpecDigests"][row["workload"]["workloadId"]] == contract.canonical_digest(row["workload"])
    assert issue(case) == result
    case[1]["binding_format"] = authority.FORMAT
    before = args["bindings_path"].read_bytes()
    with pytest.raises(ValueError):
        issue(case)
    assert args["bindings_path"].read_bytes() == before


@pytest.mark.parametrize("prior_format", [authority.FORMAT, authority.TRANSPORT_FORMAT])
def test_publication_never_silently_migrates_existing_transport(case, prior_format):
    args = case[1]
    write(args["bindings_path"], {"formatVersion": prior_format, "bindings": []}, 0o644)
    args["binding_format"] = authority.TRANSPORT_FORMAT if prior_format == authority.FORMAT else authority.FORMAT
    original = args["bindings_path"].read_bytes()
    revocation = (args["grants_dir"] / "revocation.json").read_bytes()
    with pytest.raises(ValueError):
        issue(case)
    assert args["bindings_path"].read_bytes() == original
    assert (args["grants_dir"] / "revocation.json").read_bytes() == revocation
    assert not (args["grants_dir"] / (args["grant"]["grantId"] + ".json")).exists()


def test_transport_changed_during_read_refuses(case, tmp_path, monkeypatch):
    path = tmp_path / "input.json"
    write(path, transport(case))
    original = os.read
    def changed(fd, count):
        value = original(fd, count)
        path.write_bytes(value + b" ")
        return value
    monkeypatch.setattr(authority.os, "read", changed)
    with pytest.raises(ValueError, match="changed"):
        authority.read_binding_transport(path)


def test_v2_preimage_liveness_withdrawal_remains_private(case):
    case[1]["binding_format"] = authority.TRANSPORT_FORMAT
    issue(case)
    row = authority.read_binding_transport(case[1]["bindings_path"])[0]
    rev = case[1]["grants_dir"] / "revocation.json"
    document = json.loads(rev.read_bytes())
    document["pausedGrantIds"].append(row["grantId"])
    write(rev, document)
    # Structurally intact public bytes never constitute live authority.
    assert authority.read_binding_transport(case[1]["bindings_path"])
    with pytest.raises(GrantRefusal):
        store(case).verify(request={"requester": {"grantId": row["grantId"], "authorityGrantDigest": row["authorityGrantDigest"]}, "operation": "listWorkloads", "timeoutSeconds": 1, "outputByteBound": 1024}, peer_uid=65531, payload={}, active_count=lambda _: 0)


@pytest.mark.parametrize("budget", ["maxTimeoutSeconds", "maxOutputBytes", "maxMemoryMaxBytes", "maxPidsMax", "maxCpuQuotaPercent", "maxDiskMaxBytes"])
def test_transport_refuses_digest_bound_but_underbudget_spec(case, budget):
    raw = transport(case)
    row = raw["bindings"][0]
    spec = row["workload"]
    demands = {"maxTimeoutSeconds": spec["timeoutSeconds"], "maxOutputBytes": spec["outputByteBound"],
               "maxMemoryMaxBytes": spec["resources"]["memoryMaxBytes"], "maxPidsMax": spec["resources"]["pidsMax"],
               "maxCpuQuotaPercent": spec["parameters"]["cpuQuotaPercent"], "maxDiskMaxBytes": spec["parameters"]["diskMaxBytes"]}
    row["grant"]["budgets"][budget] = demands[budget] - 1
    assert contract.validate_grant_document(row["grant"]) == row["grant"]
    row["authorityGrantDigest"] = contract.canonical_digest(row["grant"])
    with pytest.raises(ValueError, match="budget"):
        authority.validate_binding_transport(raw)


def terminal_case(case):
    request, args = deepcopy(case)
    profile = authority.terminal_authority_profile(default_sealed_workspace_workload())
    request["profileDigest"] = contract.canonical_digest(profile)
    request["requestDigest"] = contract.canonical_digest({key: value for key, value in request.items() if key != "requestDigest"})
    wid = authority.workspace_authority_workload_id(request)
    spec = args["binding"]["workload"]
    spec["workloadId"] = spec["parameters"]["workspaceId"] = wid
    spec["parameters"]["volumeName"] = "stateport-workspace-" + wid
    grant = args["grant"]
    grant.update(grantId="workspace-grant-" + request["requestDigest"][7:39], workloadIds=[wid],
                 workloadSpecDigests={wid: contract.canonical_digest(spec)}, operations=profile["operations"])
    args["binding"] = {"grantId": grant["grantId"], "authorityGrantDigest": contract.canonical_digest(grant), "workload": spec}
    args["binding_format"] = authority.TRANSPORT_FORMAT
    args["authority_profile"] = profile
    return request, args


def test_terminal_profile_explicitly_binds_ops_and_preserves_default(case):
    original = default_sealed_workspace_workload()
    selected = terminal_case(case)
    request, args = selected
    assert request["profileDigest"] != contract.canonical_digest(original)
    assert args["binding"]["workload"]["workloadId"] != case[1]["binding"]["workload"]["workloadId"]
    result = issue(selected)
    assert result["profileDigest"] == contract.canonical_digest(args["authority_profile"])
    assert issue(selected) == result
    assert default_sealed_workspace_workload() == original
    row = authority.read_binding_transport(args["bindings_path"])[0]
    for operation in ("openTerminal", "resizeTerminal", "signalTerminal", "closeTerminal"):
        verified = store(selected).verify(request={"requester": {"grantId": row["grantId"], "authorityGrantDigest": row["authorityGrantDigest"]}, "operation": operation, "timeoutSeconds": 1, "outputByteBound": 1024}, peer_uid=65531, payload={"workloadId": row["workload"]["workloadId"]}, active_count=lambda _: 0)
        assert operation in verified["operations"]


@pytest.mark.parametrize("change", ["missing_profile", "old_digest", "old_format", "operation_injection", "operation_removal", "profile_ops", "profile_id", "source_mode", "workload_image", "workload_shell", "workload_network"])
def test_terminal_profile_refuses_downgrade_or_widening_before_grant(case, change):
    selected = terminal_case(case)
    request, args = selected
    if change == "missing_profile":
        del args["authority_profile"]
    elif change == "old_digest":
        request["profileDigest"] = case[0]["profileDigest"]
        request["requestDigest"] = contract.canonical_digest({key: value for key, value in request.items() if key != "requestDigest"})
    elif change == "old_format":
        args["binding_format"] = authority.FORMAT
    elif change == "operation_injection":
        args["grant"]["operations"].append("collectGarbage")
    elif change == "operation_removal":
        args["grant"]["operations"] = [op for op in args["grant"]["operations"] if op != "closeTerminal"]
    elif change == "profile_ops":
        args["authority_profile"]["operations"].append("runValidator")
    elif change == "profile_id":
        args["authority_profile"]["profileId"] = "stateport.empty-workspace/v1"
    elif change == "source_mode":
        args["authority_profile"]["sourceMode"] = "copy"
    elif change == "workload_image":
        args["binding"]["workload"]["image"]["reference"] = "docker.io/library/other@sha256:" + "a" * 64
    elif change == "workload_shell":
        args["binding"]["workload"]["parameters"]["shell"] = ["/bin/bash"]
    else:
        args["binding"]["workload"]["parameters"]["networkMode"] = "slirp4netns"
    args["binding"]["authorityGrantDigest"] = contract.canonical_digest(args["grant"])
    before = (args["grants_dir"] / "revocation.json").read_bytes()
    with pytest.raises(ValueError):
        issue(selected)
    assert (args["grants_dir"] / "revocation.json").read_bytes() == before
    assert not args["bindings_path"].exists()
    assert not (args["grants_dir"] / (args["grant"]["grantId"] + ".json")).exists()


def test_terminal_profile_cannot_renew_existing_application(case):
    case[1]["binding_format"] = authority.TRANSPORT_FORMAT
    issue(case)
    before = case[1]["bindings_path"].read_bytes()
    with pytest.raises(ValueError, match="renewal_unsupported"):
        issue(terminal_case(case))
    assert case[1]["bindings_path"].read_bytes() == before


def source_case(case, tmp_path):
    """Real committed files and archive, with only transaction UIDs simulated."""
    import base64
    import hashlib
    import tempfile
    import subprocess
    from execution_host.deployment_staging import build_deployment_archive
    from execution_host.workspace_source import verify_source_commit

    root = tmp_path / 'reviewed-source'
    root.mkdir(mode=0o700)
    (root / 'README.md').write_bytes(b'operator reviewed source\n')
    (root / 'run.sh').write_bytes(b'#!/bin/sh\nprintf reviewed\\n\n')
    (root / 'run.sh').chmod(0o700)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL)
    git('init', '-q')
    git('-c', 'user.name=Authority Test', '-c', 'user.email=test@example.invalid', 'add', '.')
    git('-c', 'user.name=Authority Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'reviewed')
    inventory = [{'path': name, 'mode': mode, 'contentDigest': 'sha256:' + hashlib.sha256((root / name).read_bytes()).hexdigest()}
                 for name, mode in [('README.md', '100644'), ('run.sh', '100755')]]
    context = [{**{'path': row['path'], 'mode': row['mode']}, 'size': (root / row['path']).stat().st_size, 'sha256': row['contentDigest']} for row in inventory]
    with tempfile.TemporaryFile() as archive:
        metadata = build_deployment_archive(archive, plan={'sourceInventory': inventory, 'overlay': {}}, context_root=root, overlay_root=root, context_digest=contract.canonical_digest(context))
    source = {'baseRevision': git('rev-parse', 'HEAD').decode().strip(), 'commitObject': base64.b64encode(git('cat-file', 'commit', 'HEAD')).decode(),
              'sourceInventory': inventory, 'sourceArchive': metadata, 'descriptorDigest': 'sha256:' + 'd' * 64}
    request, args = terminal_case(case)
    profile = authority.source_authority_profile(default_sealed_workspace_workload())
    request.update(formatVersion=authority.SOURCE_REQUEST_FORMAT, sourceMode='reviewed-commit', source=source,
                   sourceDigest=contract.canonical_digest(source), profileDigest=contract.canonical_digest(profile))
    request['requestDigest'] = contract.canonical_digest({key: value for key, value in request.items() if key != 'requestDigest'})
    spec = authority.workspace_authority_workload_spec(request, profile['workload'])
    grant = args['grant']
    wid = spec['workloadId']
    grant.update(grantId='workspace-grant-' + request['requestDigest'][7:39], workloadIds=[wid],
                 workloadSpecDigests={wid: contract.canonical_digest(spec)}, baseRevision=source['baseRevision'])
    args['authority_profile'] = profile
    args['binding'] = {'grantId': grant['grantId'], 'authorityGrantDigest': contract.canonical_digest(grant), 'workload': spec}
    def verify():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            verify_source_commit(fd, source, owner_uid=os.geteuid())
        finally:
            os.close(fd)
    args['verify_current'] = verify
    return (request, args), root


def test_reviewed_source_transaction_binds_commit_files_and_preserves_empty(case, tmp_path):
    selected, root = source_case(case, tmp_path)
    request, args = selected
    assert authority.validate_workspace_authority_request(request) == request
    receipt = issue(selected)
    assert issue(selected) == receipt
    row = authority.read_binding_transport(args['bindings_path'])[0]
    assert row['workload']['parameters']['sourceSeed']['sourceInventory'] == request['source']['sourceInventory']
    assert store(selected).assert_live(row['grantId'])['baseRevision'] == request['source']['baseRevision']
    renewed = {**request, 'requestDigest': 'sha256:' + 'e' * 64}
    changed = {**request, 'sourceDigest': 'sha256:' + 'f' * 64}
    assert authority.workspace_authority_workload_id(renewed) == row['workload']['workloadId']
    assert authority.workspace_authority_workload_id(changed) != row['workload']['workloadId']
    assert 'sourceSeed' not in default_sealed_workspace_workload()['parameters']
    (root / 'README.md').write_bytes(b'changed after issuance\n')
    with pytest.raises(ValueError):
        issue(selected)


@pytest.mark.parametrize('phase', ['binding-published', 'before-activation'])
def test_source_change_before_activation_leaves_authority_paused(case, tmp_path, monkeypatch, phase):
    selected, root = source_case(case, tmp_path)
    def change(actual):
        if actual == phase:
            (root / 'README.md').write_bytes(b'unreviewed replacement\n')
    monkeypatch.setattr(authority, '_authority_checkpoint', change)
    with pytest.raises(ValueError):
        issue(selected)
    with pytest.raises(GrantRefusal):
        store(selected).assert_live(selected[1]['grant']['grantId'])
    rev = json.loads((selected[1]['grants_dir'] / 'revocation.json').read_text())
    assert selected[1]['grant']['grantId'] in rev['pausedGrantIds']


@pytest.mark.parametrize('change', ['legacy_version', 'empty_mode', 'source_digest', 'missing_profile', 'empty_profile', 'grant_revision'])
def test_source_authority_refuses_downgrade_and_unbound_material(case, tmp_path, change):
    selected, _ = source_case(case, tmp_path)
    request, args = selected
    if change == 'legacy_version':
        request['formatVersion'] = authority.REQUEST_FORMAT
    elif change == 'empty_mode':
        request['sourceMode'] = 'empty'
    elif change == 'source_digest':
        request['sourceDigest'] = 'sha256:' + 'e' * 64
    elif change == 'missing_profile':
        args.pop('authority_profile')
    elif change == 'empty_profile':
        args['authority_profile'] = authority.terminal_authority_profile(default_sealed_workspace_workload())
    else:
        args['grant']['baseRevision'] = None
        args['binding']['authorityGrantDigest'] = contract.canonical_digest(args['grant'])
    request['requestDigest'] = contract.canonical_digest({key: value for key, value in request.items() if key != 'requestDigest'})
    before = (args['grants_dir'] / 'revocation.json').read_bytes()
    with pytest.raises(ValueError):
        issue(selected)
    assert (args['grants_dir'] / 'revocation.json').read_bytes() == before
    assert not args['bindings_path'].exists()
