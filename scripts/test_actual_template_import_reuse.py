"""The RESUMED start of the actual-template journey must consult the product.

``apps/web/tests/live-core-fixture.py`` answers a resumed service start from its
own durable JSON record (``_durable_actual_template_records``). That function
returns the FIXTURE's recorded ``managedRoot`` / ``installReceiptId`` /
``sourceReview`` values, so before this file's coverage existed a restarted
product that had lost its instance catalog, or whose managed copy directory had
been deleted, still reported "three imported templates" and the journey asserted
survival of state the product did not hold: a test that cannot fail on the
defect it is offered for.

These tests hold the resume path to the product's own catalog entry and durable
install receipt, and prove each guard can be made to fail.

WHAT IS AND IS NOT EXERCISED HERE
- The product code under test is real: ``PersistentApp``/``PersistentCatalog``
  write the catalog entry and compute ``pathState`` and ``observedSource``, and
  ``_digest`` derives the receipt id exactly as the service derives it.
- The template SOURCES are throwaway Git repositories whose commits replace the
  production pins, following the arrangement already used by
  ``scripts/test_template_lifecycle_journey_controller.py``. The real
  ``ProjectState_Template``/``StudyState_Template`` sibling checkouts are
  currently dirty working trees, so they cannot satisfy the fixture's own
  clean-and-pinned invariant.
- The HTTP plan/inspect/install layer is NOT exercised. It needs a built
  ``apps/web/dist``; in this environment that leg already fails
  independently of anything here (see ``_install_product_state`` for the exact
  boundary that is doubled). What is exercised is everything the resume leg
  reads: the catalog, the managed copy on disk, and the durable receipt.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
# The journey module puts every packages/*/src on sys.path; import it for that
# bootstrap rather than re-implementing the product path list here.
sys.path.insert(0, str(ROOT / "scripts"))
import run_template_lifecycle_journey  # noqa: E402  (side effect: sys.path bootstrap)

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.app import _digest, initialize_instance_repository  # noqa: E402
from stateport_persistent_app.execution_host_proxy import prepare_workspace_source_seed  # noqa: E402
from execution_host.application_workspaces import catalog_identity  # noqa: E402
from test_execution_host_daemon import _workspace_spec  # noqa: E402

FIXTURE_PATH = ROOT / "apps" / "web" / "tests" / "live-core-fixture.py"
FIXTURE_SPEC = importlib.util.spec_from_file_location("live_core_fixture_reuse", FIXTURE_PATH)
fixture = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(fixture)


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(("git", "-C", str(root), *arguments), check=True, capture_output=True, text=True)
    return result.stdout.strip()


# The minimum real content each adapter needs to be recognized. Without these
# the origins are not templates, and the product's own workspace source review
# (_workspace_source_archive -> TemplateAdapterRegistry.require) would refuse the
# managed copy, so a content check over the managed copy could not be exercised
# against real product behaviour.
_ADAPTER_CONTENT = {
    "projectstate-v6": {
        "PROJECT.md": "# Outcome\n",
        "STATE.yaml": "version: projectstate-template-v6\nprofile: core\ncurrent_slice: {id: one}\n",
    },
    "studystate": {
        "state/STUDYDD_MODE.yaml": "mode: template\n",
        "state/STUDY_STATE.yaml": "targets: []\nworkflow: {stage: initialize}\n",
    },
    "statespec-template": {
        "template.yaml": (
            "apiVersion: statedd.stateport.io/v1alpha1\n"
            "kind: Template\n"
            "metadata: {id: reuse-generic, name: Reuse Generic, version: 1.0.0}\n"
            "spec:\n"
            "  domain: project\n"
            "  lifecycle: [draft, active]\n"
            "  allowedActions: [{name: read_state, level: L0}]\n"
            "  schemas: []\n"
            "  agentContract:\n"
            "    role: assistant\n"
            "    responsibilities: [Inspect the declared template]\n"
            "    forbiddenActions: [Execute repository commands]\n"
        ),
    },
}


def _origin(parent: Path, name: str, adapter: str) -> tuple[Path, str]:
    """A real local Git repository holding a template the product recognizes."""
    root = parent / name
    root.mkdir()
    for relative, content in _ADAPTER_CONTENT[adapter].items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    (root / "README.md").write_text(f"# {name}\n", encoding="utf-8")
    _git(root, "init", "-q", "--initial-branch=main")
    _git(root, "add", "--all")
    _git(root, "-c", "commit.gpgSign=false", "commit", "-q", "-m", "pinned origin")
    return root, _git(root, "rev-parse", "HEAD")


def _workspace_source_review(entry: dict, instance_id: str) -> dict:
    """The product's own workspace source seed for one catalog entry.

    Exactly the spec ``_import_actual_templates`` builds, so the resume leg's
    recomputation and the import leg's first measurement are the same product
    call on the same shape and a difference between them can only be a change in
    the managed copy's content.
    """
    spec = _workspace_spec(
        "ui-" + instance_id,
        parameters={
            "ownership": {
                "applicationId": entry["applicationId"],
                "instanceId": entry["instanceId"],
                "catalogIdentityDigest": catalog_identity(entry),
                "runId": None,
            }
        },
    )
    return prepare_workspace_source_seed(entry, spec)["parameters"]["sourceSeed"]


class _ForbiddenService:
    """A service process the fixture must not need on a resumed start."""

    def __getattr__(self, name: str):
        raise AssertionError(f"a resumed start must not reach the service: {name}")


def _install_product_state(app, records: list[dict]) -> list[dict]:
    """Stand in for the HTTP install, writing only PRODUCT-owned durable state.

    Doubled boundary: the network plan/inspect/install exchange, which needs a
    built ``apps/web/dist``. Everything downstream of it is the product's own
    code -- ``catalog.register`` writes the entry and computes ``pathState`` and
    ``observedSource``; the receipt is written where the service writes it; the
    receipt id is derived with the service's own ``_digest`` over the same
    receipt document.
    """
    layout = app.layout
    receipts = layout.operations_root / "template-imports"
    receipts.mkdir(parents=True, exist_ok=True)
    for record in records:
        instance_id = record["instanceId"]
        name = f"Imported {record['adapterId']}"
        application_id = f"app-{record['adapterId']}"
        source_commit = record["sourceCommit"]
        source_tree = _git(Path(record["sourceRoot"]), "rev-parse", "HEAD^{tree}")
        destination = layout.instances_root / instance_id
        destination.mkdir(parents=True)
        # The real install materializes the pinned tree, then writes the product's
        # own incarnation marker, and only THEN initializes the instance Git base
        # over the result -- so the marker is committed and the base is clean.
        # Reproducing that order is what makes the managed copy reviewable by the
        # product's own workspace source archive, and therefore content-checkable.
        origin_root = Path(record["sourceRoot"])
        for item in sorted(origin_root.rglob("*")):
            relative = item.relative_to(origin_root)
            if ".git" in relative.parts:
                continue
            target = destination / relative
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target)
        incarnation = PersistentApp._make_managed_incarnation(destination, instance_id)
        # initialize_instance_repository returns the base commit as a plain
        # string; that string is what the product writes to receipt["baseGit"].
        base_git = initialize_instance_repository(destination)
        assert isinstance(base_git, str) and len(base_git) == 40, base_git
        origin = {
            "formatVersion": "stateport.managed-template-source/v1",
            "management": "isolated_template",
            "templateId": application_id,
            "adapterId": record["adapterId"],
            "sourceKind": "local_git_repository",
            "resolvedCommit": source_commit,
            "resolvedTree": source_tree,
            "workingTreeChangesExcluded": True,
        }
        entry = app.catalog.register(
            destination,
            instance_id=instance_id,
            name=name,
            source=origin,
            application_id=application_id,
            managed_incarnation=incarnation,
        )
        template = {"applicationId": application_id, "adapterId": record["adapterId"]}
        receipt = {
            "formatVersion": "stateport.template-install-receipt/v1",
            "operation": "template-import",
            "instanceId": instance_id,
            "applicationId": application_id,
            "planDigest": "sha256:" + "1" * 64,
            "inspectionDigest": "sha256:" + "2" * 64,
            "source": origin,
            "template": template,
            "baseGit": base_git,
            "managedIncarnation": incarnation,
            "catalogIdentity": {
                "instanceId": entry["instanceId"],
                "applicationId": entry["applicationId"],
                "createdAt": entry["createdAt"],
                "filesystemIdentityDigest": _digest(entry["filesystem"]),
            },
            "approval": {"actorId": "test-actor", "decision": "approved", "planDigest": "sha256:" + "1" * 64},
            "effects": {},
            "createdAt": "2026-01-01T00:00:00Z",
        }
        (receipts / f"{instance_id}.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        # Derived the way the SERVICE derives it -- service_process.py builds
        # `"template-import-" + str(result["receiptDigest"])[7:31]` from
        # `receiptDigest`, which the install handler sets to `_digest(receipt)`.
        # Deliberately NOT via fixture._durable_template_receipt_id: using the
        # function under test to produce the expected value would make the
        # receipt-id comparison agree with any derivation, including a wrong
        # one, which is a guard that cannot fail.
        service_receipt_id = "template-import-" + str(_digest(receipt))[7:31]
        record.update({
            "name": name,
            "managedRoot": entry["path"],
            "installReceiptId": service_receipt_id,
            # The product's own measured content identity of the managed copy,
            # not a stand-in: a fabricated digest here would make any later
            # comparison of the managed copy's content vacuous.
            "sourceReview": _workspace_source_review(entry, instance_id),
        })
    return records


def _arrange(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A real disposable layout, throwaway pinned origins, and the real app.

    The repository's own scripts directory is linked into the fake repository so
    the fixture imports the real journey module, and the two template origins are
    throwaway repositories whose commits replace the production pins, so the real
    sibling checkouts are never read and the run stays hermetic.
    """
    monkeypatch.setattr(sys, "path", list(sys.path))
    origins = {}
    pins = []
    for name, adapter, _ in fixture.ACTUAL_TEMPLATE_SOURCES:
        _, commit = _origin(tmp_path, name, adapter)
        origins[name] = commit
        pins.append((name, adapter, commit))
    monkeypatch.setattr(fixture, "ACTUAL_TEMPLATE_SOURCES", tuple(pins))
    repo_root = tmp_path / "StatePort"
    repo_root.mkdir()
    (repo_root / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
    for name in ("CONFIG", "DATA", "STATE"):
        monkeypatch.setenv("XDG_" + name + "_HOME", str(tmp_path / name.lower()))
    # The service child sets this before the actual-template import runs.
    data_root = tmp_path / "data" / "stateport"
    monkeypatch.setenv("STATEPORT_REPOSITORY_ROOTS", str(data_root / "live-core-import-candidates"))
    layout = LocalLayout.from_environment()
    layout.initialize()
    app = PersistentApp(layout)
    assert app.layout.data_root == data_root
    return app, repo_root, data_root, origins


def _first_start(app, repo_root, data_root, monkeypatch):
    """Run one real first start so the durable record exists, then return it."""
    monkeypatch.setattr(
        fixture, "_import_actual_templates",
        lambda _app, _repo_root, _service, records, *, web_root=None: _install_product_state(_app, records),
    )
    records = fixture._actual_template_imports(app, repo_root, _ForbiddenService())
    assert (data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).is_file()
    return records


def _receipt(app, instance_id: str) -> Path:
    return app.layout.operations_root / "template-imports" / f"{instance_id}.json"


def _catalog_document(app) -> dict:
    return json.loads(app.layout.catalog_file.read_text(encoding="utf-8"))


def _catalog_entry_in(document: dict, instance_id: str) -> dict:
    """The entry object inside the document that will be written back.

    Deliberately taken from the document itself: a separately parsed copy would
    be mutated in isolation and the write-back would silently discard it, which
    would make every catalog mutation below a no-op and every refusal untested.
    """
    for entry in document["entries"]:
        if entry["instanceId"] == instance_id:
            return entry
    raise AssertionError(f"no catalog entry for {instance_id}")


# ---------------------------------------------------------------- the guard --


def test_resumed_start_returns_the_three_records_when_the_product_still_holds_them(tmp_path, monkeypatch):
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    durable = (data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).read_bytes()

    # A second import, clone, or service use is a failure of this increment.
    monkeypatch.setattr(fixture, "_import_actual_templates", _ForbiddenService())
    resumed = fixture._actual_template_imports(app, repo_root, _ForbiddenService())

    # The same three records, and the product really does hold all three.
    assert resumed == records
    assert [record["instanceId"] for record in resumed] == [
        "actual-projectstate-v6", "actual-studystate", "actual-statespec-template",
    ]
    for record in resumed:
        entry = app.catalog.get(record["instanceId"])
        assert entry["pathState"] == "present"
        assert entry["path"] == record["managedRoot"]
        assert entry["observedSource"]["resolvedCommit"] == record["sourceCommit"]
        assert _receipt(app, record["instanceId"]).is_file()
    assert (data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).read_bytes() == durable


def test_durable_records_signature_takes_the_product_app():
    """The resume path cannot consult the product without being given it."""
    import inspect
    parameters = list(inspect.signature(fixture._durable_actual_template_records).parameters)
    assert parameters == ["app", "data_root", "roots"]
    source = FIXTURE_PATH.read_text(encoding="utf-8")
    assert "_durable_actual_template_records(app, data_root, roots)" in source


def _refusal_labels(message: str) -> list[str]:
    """The mismatch labels the resume guard reported, split out of the message.

    Matching a substring of the whole message is not enough: the refusal embeds
    the product's own exception text, and a label can appear there by accident
    (the catalog's "catalog instance IDs must be unique and sorted" is not a
    report about this guard). So the assertion is made against the labels the
    guard itself produced.
    """
    _, separator, tail = message.partition(" is not this installed pinned import: ")
    assert separator, f"refusal is not a mismatch report: {message}"
    return [item.strip() for item in tail.split(",")]


# Refusals that are not mismatch reports, so they are matched as whole text.
_REFUSAL_TEXTS = {
    "is absent from the product catalog",
    "has no durable install receipt to verify",
}


@pytest.mark.parametrize("instance_index,expected", [
    (0, "is absent from the product catalog"),
    (0, "managed copy path state"),
    (0, "catalog source commit"),
    (0, "has no durable install receipt to verify"),
    (2, "catalog source tree"),
    (1, "catalog management"),
    (1, "catalog template adapter"),
    (1, "catalog template application"),
    (1, "catalog managed path"),
    (1, "recorded receipt id"),
    (1, "receipt source commit"),
    (1, "receipt source tree"),
    (1, "receipt instance"),
    (1, "receipt application"),
    (1, "catalog name"),
    (1, "catalog source format"),
    (1, "catalog application"),
])
def test_resumed_start_refuses_loudly_on_each_way_the_product_can_differ(
    tmp_path, monkeypatch, instance_index, expected
):
    """Every guard in the resume path is falsifiable against real product state."""
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    instance_id = records[instance_index]["instanceId"]
    first = _ForbiddenService()
    monkeypatch.setattr(fixture, "_import_actual_templates", first)
    # Rehearse the unmutated resume once, so a later refusal can only come from
    # the mutation below and not from an arrangement that never worked.
    assert fixture._actual_template_imports(app, repo_root, _ForbiddenService()) == records

    catalog = _catalog_document(app)
    entry = _catalog_entry_in(catalog, instance_id)
    receipt_path = _receipt(app, instance_id)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    if expected == "is absent from the product catalog":
        catalog["entries"] = [item for item in catalog["entries"] if item["instanceId"] != instance_id]
    elif expected == "managed copy path state":
        # The managed copy really disappears; the catalog is untouched.
        shutil.rmtree(app.layout.instances_root / instance_id)
    elif expected == "catalog source commit":
        entry["metadata"]["source"]["resolvedCommit"] = "b" * 40
    elif expected == "catalog source tree":
        entry["metadata"]["source"]["resolvedTree"] = "c" * 40
    elif expected == "catalog management":
        entry["metadata"]["source"]["management"] = "registered"
    elif expected == "catalog template adapter":
        entry["metadata"]["source"]["adapterId"] = "some-other-adapter"
    elif expected == "catalog template application":
        entry["metadata"]["source"]["templateId"] = "some-other-application"
    elif expected == "catalog managed path":
        # The fixture's recorded managedRoot drifts from the product's catalog
        # path. The managed copy itself stays present, so this exercises the
        # path comparison alone and not the pathState check above it.
        document = json.loads((data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).read_text(encoding="utf-8"))
        for item in document["records"]:
            if item["instanceId"] == instance_id:
                item["managedRoot"] = str(app.layout.instances_root / "somewhere-else")
        (data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    elif expected == "catalog name":
        entry["name"] = "Renamed behind the fixture's back"
    elif expected == "catalog source format":
        entry["metadata"]["source"]["formatVersion"] = "stateport.managed-template-source/v2"
    elif expected == "catalog application":
        entry["metadata"]["applicationId"] = "app-somebody-else"
    elif expected == "has no durable install receipt to verify":
        receipt_path.unlink()
    elif expected == "recorded receipt id":
        document = json.loads((data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).read_text(encoding="utf-8"))
        for item in document["records"]:
            if item["instanceId"] == instance_id:
                item["installReceiptId"] = "template-import-" + "0" * 24
        (data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    elif expected == "receipt source commit":
        receipt["source"]["resolvedCommit"] = "d" * 40
    elif expected == "receipt source tree":
        receipt["source"]["resolvedTree"] = "e" * 40
    elif expected == "receipt instance":
        receipt["instanceId"] = "actual-somebody-else"
    elif expected == "receipt application":
        receipt["applicationId"] = "app-somebody-else"
    else:  # pragma: no cover - a guard without a mutation is not covered
        raise AssertionError(f"no mutation for {expected}")

    if expected != "has no durable install receipt to verify":
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    app.layout.catalog_file.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")

    # A refusal, never a re-install, never a re-import, never a fallback value.
    with pytest.raises(RuntimeError) as raised:
        fixture._actual_template_imports(app, repo_root, _ForbiddenService())
    message = str(raised.value)
    if expected in _REFUSAL_TEXTS:
        assert expected in message
    else:
        assert message.startswith(
            f"resumed actual template instance {instance_id} is not this installed pinned import: "
        )
        # The label must be one the guard itself emitted, not a substring of the
        # product's own exception text embedded in the same message.
        assert expected in _refusal_labels(message), message


def test_the_catalog_instance_id_comparison_is_defence_in_depth_only(tmp_path, monkeypatch):
    """One guard cannot be falsified in isolation, and that is recorded here.

    The product's catalog is keyed by ``instanceId`` and its document validator
    requires those ids to be unique and sorted, so an entry whose stored id
    differs from the id being looked up cannot be built: renaming an entry makes
    the whole document invalid, and the product reports "catalog instance IDs
    must be unique and sorted". That message CONTAINS the substring "catalog
    instance", so a naive substring assertion on a refusal message would pass for
    the wrong reason. This test pins both facts. The reachable falsifier for a
    lost instance is the absent-catalog-entry refusal, covered above; the id
    comparison is kept as defence in depth and is not claimed as covered.
    """
    from stateport_persistent_app.app import AppError

    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    catalog = _catalog_document(app)
    _catalog_entry_in(catalog, records[1]["instanceId"])["instanceId"] = "actual-somebody-else"
    app.layout.catalog_file.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")

    with pytest.raises(AppError) as raised:
        app.catalog.get(records[1]["instanceId"])
    message = str(raised.value)
    assert "catalog instance" in message
    # This is exactly why the refusal assertions above are made against the
    # guard's own mismatch labels rather than a substring of the message.
    assert "is not this installed pinned import" not in message


def test_resumed_start_refuses_a_symlinked_receipt(tmp_path, monkeypatch):
    """A receipt path that is a symlink is not the product's own durable record."""
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    instance_id = records[0]["instanceId"]
    receipt_path = _receipt(app, instance_id)
    elsewhere = receipt_path.with_suffix(".elsewhere.json")
    receipt_path.rename(elsewhere)
    receipt_path.symlink_to(elsewhere)
    monkeypatch.setattr(fixture, "_import_actual_templates", _ForbiddenService())

    with pytest.raises(RuntimeError, match="has no durable install receipt to verify"):
        fixture._actual_template_imports(app, repo_root, _ForbiddenService())


def test_resumed_start_names_every_mismatch_at_once(tmp_path, monkeypatch):
    """The refusal reports the whole disagreement, not only the first field."""
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    instance_id = records[1]["instanceId"]
    catalog = json.loads(app.layout.catalog_file.read_text(encoding="utf-8"))
    for entry in catalog["entries"]:
        if entry["instanceId"] == instance_id:
            entry["name"] = "Renamed"
            entry["metadata"]["source"]["management"] = "registered"
    app.layout.catalog_file.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")
    monkeypatch.setattr(fixture, "_import_actual_templates", _ForbiddenService())

    with pytest.raises(RuntimeError) as raised:
        fixture._actual_template_imports(app, repo_root, _ForbiddenService())
    message = str(raised.value)
    labels = _refusal_labels(message)
    assert "catalog name" in labels
    assert "catalog management" in labels
    # Every other field of that instance still agrees, so nothing else is named.
    assert labels == ["catalog name", "catalog management"]
    assert instance_id in message


def test_an_impure_reused_source_is_still_refused_before_the_product_is_consulted(tmp_path, monkeypatch):
    """The existing refusal order is preserved: pinned source first, then product."""
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    (Path(records[0]["sourceRoot"]) / "untracked.txt").write_text("drift\n", encoding="utf-8")
    monkeypatch.setattr(fixture, "_import_actual_templates", _ForbiddenService())

    with pytest.raises(RuntimeError, match="actual template clone identity is not clean and pinned"):
        fixture._actual_template_imports(app, repo_root, _ForbiddenService())


# ------------------------------------------- the three residual gaps closed here --
#
# Each of the following was reproduced against 67797ece, where the guard did not
# fire. The product is correct in all three cases; what was missing was the
# guard's own named refusal.


def test_gap1_managed_copy_content_drift_is_refused(tmp_path, monkeypatch):
    """GAP 1: overwriting the managed copy's content must be a named refusal.

    MEASURED, not assumed. ``PersistentCatalog`` records no ``contentIdentity``
    for a managed instance: the real catalog entry and the raw catalog document
    both lack the key, and only ``metadata.managedIncarnation`` (the marker's own
    digest and inode) is revalidated, which is why ``pathState`` still reads
    ``present`` after the content changes. The product DOES hold a content
    identity for a managed instance, but in the workspace source seed that
    ``_import_actual_templates`` already measures and records as ``sourceReview``:
    a per-file ``contentDigest`` inventory plus the base revision. So the guard
    recomputes that same product call and compares.
    """
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    instance_id = records[0]["instanceId"]
    managed_root = Path(records[0]["managedRoot"])
    # Prove the fixture's premise: the recorded review really is a content
    # identity, with a per-file digest the drift below must change.
    assert any(
        row["path"] == "README.md" for row in records[0]["sourceReview"]["sourceInventory"]
    ), records[0]["sourceReview"]
    (managed_root / "README.md").write_text("content drifted behind the fixture's back\n", encoding="utf-8")
    # The product's own catalog still calls the instance present and active, so
    # no pre-existing label of the guard disagrees here.
    assert app.catalog.get(instance_id)["pathState"] == "present"
    monkeypatch.setattr(fixture, "_import_actual_templates", _ForbiddenService())

    with pytest.raises(RuntimeError) as raised:
        fixture._actual_template_imports(app, repo_root, _ForbiddenService())
    message = str(raised.value)
    assert "managed copy content" in message, message


def test_gap2_an_archived_catalog_entry_is_refused(tmp_path, monkeypatch):
    """GAP 2: an archived instance must be the guard's own named mismatch.

    ``catalog.get`` does not raise for an archived entry, so every pre-existing
    label still agreed and the guard stayed silent. The product's own managed
    binding already requires an active entry
    (``service_process.py`` ``workspace_catalog_entry``); this makes the resume
    guard hold the same requirement itself, instead of relying on a different
    layer to happen to raise.
    """
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    instance_id = records[1]["instanceId"]
    catalog = _catalog_document(app)
    _catalog_entry_in(catalog, instance_id)["status"] = "archived"
    app.layout.catalog_file.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")
    # The premise: the product's catalog really does hand this entry back.
    assert app.catalog.get(instance_id)["status"] == "archived"
    monkeypatch.setattr(fixture, "_import_actual_templates", _ForbiddenService())

    with pytest.raises(RuntimeError) as raised:
        fixture._actual_template_imports(app, repo_root, _ForbiddenService())
    message = str(raised.value)
    assert message.startswith(
        f"resumed actual template instance {instance_id} is not this installed pinned import: "
    ), message
    assert "catalog status" in _refusal_labels(message), message


def test_gap3_a_missing_durable_record_over_live_instances_is_refused(tmp_path, monkeypatch):
    """GAP 3: the guard must not be routed around by deleting the fixture's record.

    With the record file gone, ``_durable_actual_template_records`` used to return
    ``None`` and the resumed start re-entered ``_import_actual_templates`` -- the
    re-import that function's own docstring says must never happen, and the very
    act that would recreate the product state whose survival is being measured.
    The product refuses that re-import ("template import destination already
    exists"), but the harness neither proved nor asserted it.
    """
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    # Only the FIXTURE's own record is removed. The product still holds all three.
    (data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).unlink()
    assert sorted(entry["instanceId"] for entry in app.catalog.list()) == sorted(
        record["instanceId"] for record in records
    )
    reimported = []

    def reimport(*arguments, **keywords):
        reimported.append(True)
        raise AssertionError("a resumed start must never re-import the actual templates")

    monkeypatch.setattr(fixture, "_import_actual_templates", reimport)

    with pytest.raises(RuntimeError) as raised:
        fixture._actual_template_imports(app, repo_root, _ForbiddenService())
    message = str(raised.value)
    assert reimported == [], "the resume leg reached the re-import path"
    assert "already holds actual-template instances" in message, message
    for record in records:
        assert record["instanceId"] in message, message


def test_gap3_guard_does_not_fire_on_a_genuine_first_start(tmp_path, monkeypatch):
    """The other side of GAP 3: a clean data root must still import, not refuse."""
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    # No durable record AND no product instances: this is a genuine first start.
    assert not (data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).exists()
    assert app.catalog.list() == []
    seen: list[dict] = []

    def importing(_app, _repo_root, _service, records, *, web_root=None):
        seen.append([record["instanceId"] for record in records])
        return _install_product_state(_app, records)

    monkeypatch.setattr(fixture, "_import_actual_templates", importing)

    records = fixture._actual_template_imports(app, repo_root, _ForbiddenService())

    assert seen == [["actual-projectstate-v6", "actual-studystate", "actual-statespec-template"]]
    assert len(records) == 3
    assert (data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).is_file()


# ------------------------------------------------------- the first-import path --


def test_first_start_still_imports_through_the_http_path_and_records_durably(tmp_path, monkeypatch):
    """A first start is unchanged in effect: import, then record, no verify yet.

    The verify-or-refuse guard belongs to the RESUMED leg only. A first start
    installs the instances and writes the durable record, so the guard must not
    run before the product holds anything.
    """
    app, repo_root, data_root, origins = _arrange(tmp_path, monkeypatch)
    seen: list[dict] = []

    def importing(_app, _repo_root, _service, records, *, web_root=None):
        seen.append([record["instanceId"] for record in records])
        return _install_product_state(_app, records)

    monkeypatch.setattr(fixture, "_import_actual_templates", importing)

    # Nothing is installed yet: the catalog is empty and no receipt exists.
    assert app.catalog.list() == []
    assert not (app.layout.operations_root / "template-imports").exists()

    records = fixture._actual_template_imports(app, repo_root, _ForbiddenService())

    # Exactly one import, over the three expected instanceIds.
    assert seen == [["actual-projectstate-v6", "actual-studystate", "actual-statespec-template"]]
    assert [record["adapterId"] for record in records] == [
        "projectstate-v6", "studystate", "statespec-template",
    ]
    for record in records:
        source = Path(record["sourceRoot"])
        assert source.is_dir()
        assert _git(source, "rev-parse", "HEAD") == record["sourceCommit"]
        assert _git(source, "status", "--porcelain=v1", "--untracked-files=all") == ""
    assert records[0]["sourceCommit"] == origins["ProjectState_Template"]
    assert records[1]["sourceCommit"] == origins["StudyState_Template"]
    # The completed import is durable, and the product holds all three.
    document = json.loads((data_root / fixture.ACTUAL_TEMPLATE_IMPORTS_RECORDS).read_text(encoding="utf-8"))
    assert document["formatVersion"] == fixture.ACTUAL_TEMPLATE_IMPORTS_FORMAT
    assert [record["instanceId"] for record in document["records"]] == [
        record["instanceId"] for record in records
    ]
    assert sorted(entry["instanceId"] for entry in app.catalog.list()) == sorted(
        record["instanceId"] for record in records
    )
    assert os.environ["STATEPORT_REPOSITORY_ROOTS"] == os.pathsep.join([
        str(data_root / "live-core-import-candidates"), str(data_root / "actual-template-sources"),
    ])


def test_first_import_path_source_is_untouched_by_the_resume_repair():
    """``_import_actual_templates`` must not consult the durable-record verifier.

    The repair is resume-only. A first start reads no durable record, so a call
    into the resume verifier from the first-import path would be a real defect.
    """
    source = FIXTURE_PATH.read_text(encoding="utf-8")
    body = source.split("def _import_actual_templates(", 1)[1].split("\ndef ", 1)[0]
    assert "_verify_resumed_actual_template" not in body
    assert "_durable_actual_template_records" not in body
    # The resume verifier is reached from the resume path, and only there.
    assert source.count("_verify_resumed_actual_template(app, record)") == 1
    assert source.count("_durable_actual_template_records(app, data_root, roots)") == 1


def test_the_fixture_derives_the_receipt_id_exactly_as_the_service_does(tmp_path, monkeypatch):
    """The receipt-id check must be independent of the derivation it checks.

    The service builds the id from ``_digest(receipt)``; the fixture recomputes
    it to decide whether the recorded id is still the id of the receipt on disk.
    If this test compared the two through the fixture's own helper, a wrong
    derivation would agree with itself and the guard could not fail.
    """
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    service_source = (ROOT / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "service_process.py").read_text(encoding="utf-8")
    assert '"receiptId": "template-import-"' in service_source
    assert 'str(result["receiptDigest"])[7:31]' in service_source

    for record in records:
        receipt = json.loads(_receipt(app, record["instanceId"]).read_text(encoding="utf-8"))
        assert record["installReceiptId"] == "template-import-" + str(_digest(receipt))[7:31]
        assert record["installReceiptId"] == fixture._durable_template_receipt_id(receipt)


def test_durable_records_helper_is_not_used_without_the_product(tmp_path, monkeypatch):
    """A first start with no durable record returns None and imports instead."""
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    roots = data_root / "actual-template-sources"
    assert fixture._durable_actual_template_records(app, data_root, roots) is None


def test_hashes_are_recomputed_not_copied_from_the_fixture(tmp_path, monkeypatch):
    """The tree compared against the catalog is measured from the real source."""
    app, repo_root, data_root, _ = _arrange(tmp_path, monkeypatch)
    records = _first_start(app, repo_root, data_root, monkeypatch)
    for record in records:
        source = Path(record["sourceRoot"])
        rows = [
            (path.relative_to(source).as_posix(), path.stat().st_mode & 0o7777, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in sorted(source.rglob("*")) if path.is_file() and ".git" not in path.relative_to(source).parts
        ]
        assert record["sourceIdentityBefore"]["filesDigest"] == hashlib.sha256(
            json.dumps(rows, sort_keys=True).encode()
        ).hexdigest()
        assert record["sourceIdentityBefore"]["tree"] == _git(source, "rev-parse", "HEAD^{tree}")
        assert record["sourceIdentityBefore"]["status"] == ""


if __name__ == "__main__":
    # Direct execution is a real run, not an import that silently exits 0.
    sys.exit(pytest.main([__file__, "-q"]))
