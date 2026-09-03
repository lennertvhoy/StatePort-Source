from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "stateport-execution-host-provision"


def _heredocs() -> list[str]:
    source = SCRIPT.read_text(encoding="utf-8")
    return re.findall(r"<<'PY'\n(.*?)\nPY\n", source, flags=re.DOTALL)


def _cleanup_source() -> str:
    return _heredocs()[2]


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _cleanup_documents() -> tuple[dict[str, object], dict[str, object]]:
    images = [
        {
            "imageId": "stateport-api",
            "reference": "registry.example/stateport-api@sha256:" + "1" * 64,
            "digest": "sha256:" + "1" * 64,
        },
        {
            "imageId": "stateport-execution-host",
            "reference": "registry.example/stateport-execution-host@sha256:" + "2" * 64,
            "digest": "sha256:" + "2" * 64,
        },
    ]
    signed = {
        "release": {"releaseId": "stateport-alpha.4"},
        "source": {"commit": "c" * 40, "tree": "d" * 40},
        "artifacts": {"installer": {"digest": "sha256:" + "3" * 64}},
        "targets": [
            {
                "targetId": "linux-amd64-rootless-podman-quadlet",
                "topologyDigest": "sha256:" + "4" * 64,
            }
        ],
        "images": images,
    }
    subject_digest = _canonical_digest(signed)
    index = {
        "signed": signed,
        "signatures": [{"subjectDigest": subject_digest}],
    }
    receipt: dict[str, object] = {
        "schema": "stateport.execution-host-provisioning-receipt/v1",
        "result": "succeeded",
        "evidenceClass": "clean-host-executed",
        "releaseId": "stateport-alpha.4",
        "releaseIndexDigest": _canonical_digest(index),
        "signedPayloadDigest": subject_digest,
        "sourceCommit": "c" * 40,
        "sourceTree": "d" * 40,
        "installerDigest": "sha256:" + "3" * 64,
        "targetId": "linux-amd64-rootless-podman-quadlet",
        "topologyDigest": "sha256:" + "4" * 64,
        "image": {
            "imageId": "stateport-execution-host",
            "expectedDigest": "sha256:" + "2" * 64,
        },
        "subordinateIds": {
            "user": "stateport-exec",
            "start": 100000,
            "count": 65536,
        },
        "controlSubordinateIds": {
            "user": "stateport-control",
            "start": 165536,
            "count": 65536,
        },
    }
    receipt["receiptDigest"] = _canonical_digest(receipt)
    return index, receipt


def _binding_block() -> str:
    source = _cleanup_source()
    return source[
        source.index("receipt_body = dict(receipt)") : source.index(
            '\nexec_user = "stateport-exec"'
        )
    ]


def test_every_embedded_python_program_compiles() -> None:
    programs = _heredocs()
    assert len(programs) == 3
    for position, source in enumerate(programs):
        compile(source, f"stateport-execution-host-provision:{position}", "exec")


def test_compiled_cosign_pin_matches_the_bootstrap_fetch() -> None:
    sys_path = [str(ROOT / "scripts")]
    import sys

    sys.path.insert(0, sys_path[0])
    try:
        import render_wsl2_install_bootstrap as wsl2_bootstrap
    finally:
        sys.path.remove(sys_path[0])
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(r'^EXPECTED_COSIGN = "(sha256:[0-9a-f]{64})"$', source, flags=re.M)
    assert match is not None
    assert match.group(1) == f"sha256:{wsl2_bootstrap.COSIGN_SHA256}"
    tools = (ROOT / "config" / "release-tool-inputs.yaml").read_text(encoding="utf-8")
    build_tool = re.search(
        r"cosign:\n(?:.*\n)*?\s+executableDigest: (sha256:[0-9a-f]{64})", tools
    )
    assert build_tool is not None
    assert match.group(1) != build_tool.group(1)


def test_materialization_recovery_removes_every_staging_form(tmp_path: Path) -> None:
    source = _heredocs()[1]
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "remove_partial"
    )
    module_root = tmp_path / "stateport" / "provisioning"
    manifest = tmp_path / "etc" / "provisioning.manifest"
    cosign_root = tmp_path / "tools" / "cosign"
    public_key_root = tmp_path / "etc" / "release.pub"
    for path in (module_root,):
        path.mkdir(parents=True)
    for path in (manifest, cosign_root, public_key_root):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("partial", encoding="ascii")
    stale_directory = module_root.parent / ".bootstrap.interrupted"
    stale_directory.mkdir()
    stale_file = module_root.parent / ".provisioning.interrupted"
    stale_file.write_text("partial", encoding="ascii")
    stale_symlink = module_root.parent / ".bootstrap.link"
    stale_symlink.symlink_to(stale_file)
    temporary_paths = (
        cosign_root.with_name(f".{cosign_root.name}.tmp"),
        public_key_root.with_name(f".{public_key_root.name}.tmp"),
        manifest.with_name(f".{manifest.name}.tmp"),
    )
    for path in temporary_paths:
        path.write_text("partial", encoding="ascii")

    namespace = {
        "Path": Path,
        "shutil": __import__("shutil"),
        "module_root": module_root,
        "manifest": manifest,
        "cosign_root": cosign_root,
        "public_key_root": public_key_root,
    }
    executable = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    exec(compile(executable, "materialize-recovery", "exec"), namespace)
    namespace["remove_partial"]()

    assert not module_root.exists()
    assert not manifest.exists()
    assert not cosign_root.exists()
    assert not public_key_root.exists()
    assert not stale_directory.exists()
    assert not stale_file.exists()
    assert not stale_symlink.exists() and not stale_symlink.is_symlink()
    assert all(not path.exists() for path in temporary_paths)


def test_normal_materialization_recovers_orphan_staging_before_intent() -> None:
    source = _heredocs()[1]
    recovery = source[
        source.index("orphaned_staging = any(") : source.index("\nintent_fd = os.open(")
    ]
    calls: list[str] = []

    class Missing:
        def exists(self) -> bool:
            return False

        def is_symlink(self) -> bool:
            return False

    class Present(Missing):
        def exists(self) -> bool:
            return True

    class Parent:
        def glob(self, pattern: str) -> list[Missing]:
            return [Present()] if pattern == ".bootstrap.*" else []

    class ModuleRoot(Missing):
        parent = Parent()

    namespace = {
        "module_root": ModuleRoot(),
        "materialize_intent": Missing(),
        "manifest": Missing(),
        "cosign_root": Missing(),
        "public_key_root": Missing(),
        "remove_partial": lambda: calls.append("recovered"),
    }
    exec(compile(recovery, "materialize-control-flow", "exec"), namespace)
    assert namespace["orphaned_staging"] is True
    assert calls == ["recovered"]


def _materialize_guard_source() -> str:
    source = _heredocs()[1]
    return source[
        source.index("if materialize_intent.exists():") : source.index("\nintent_fd = os.open(")
    ]


def _materialize_namespace(tmp_path: Path, wheel_bytes: bytes) -> dict[str, object]:
    module_root = tmp_path / "stateport" / "provisioning"
    manifest = tmp_path / "etc" / "provisioning.manifest"
    cosign_root = tmp_path / "tools" / "cosign"
    public_key_root = tmp_path / "etc" / "release.pub"
    for path in (manifest, cosign_root, public_key_root):
        path.parent.mkdir(parents=True, exist_ok=True)
    return {
        "Path": Path,
        "hashlib": hashlib,
        "io": __import__("io"),
        "zipfile": __import__("zipfile"),
        "module_root": module_root,
        "manifest": manifest,
        "cosign_root": cosign_root,
        "public_key_root": public_key_root,
        "materialize_intent": SimpleNamespace(
            exists=lambda: False, is_symlink=lambda: False, is_file=lambda: False
        ),
        "remove_partial": lambda: None,
        "wheel_bytes": wheel_bytes,
        "cosign_bytes": b"pinned-cosign",
        "public_key_bytes": b"pinned-key",
    }


def _wheel_bytes() -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("stateport_release/__init__.py", b"release-module")
        archive.writestr("stateport_release/sub/engine.py", b"engine-module")
        archive.writestr("execution_host/__init__.py", b"host-module")
        archive.writestr("unrelated/package.py", b"not-provisioning")
        archive.writestr("stateport_release/cached.pyc", b"bytecode")
    return buffer.getvalue()


def _converged_tree(namespace: dict[str, object]) -> None:
    entries = {
        "stateport_release/__init__.py": b"release-module",
        "stateport_release/sub/engine.py": b"engine-module",
        "execution_host/__init__.py": b"host-module",
    }
    module_root = namespace["module_root"]
    for name, content in entries.items():
        destination = module_root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    namespace["manifest"].write_bytes(
        (
            "\n".join(
                f"{hashlib.sha256(content).hexdigest()}  {name}"
                for name, content in sorted(entries.items())
            )
            + "\n"
        ).encode("ascii")
    )
    namespace["cosign_root"].write_bytes(b"pinned-cosign")
    namespace["public_key_root"].write_bytes(b"pinned-key")


def test_materialization_adopts_byte_identical_existing_tree(tmp_path: Path) -> None:
    namespace = _materialize_namespace(tmp_path, _wheel_bytes())
    _converged_tree(namespace)
    with pytest.raises(SystemExit) as outcome:
        exec(compile(_materialize_guard_source(), "materialize-guard", "exec"), namespace)
    assert outcome.value.code == 0


@pytest.mark.parametrize(
    "drift",
    ["module-content", "extra-file", "manifest", "cosign", "public-key"],
)
def test_materialization_still_refuses_drifted_existing_tree(
    tmp_path: Path, drift: str
) -> None:
    namespace = _materialize_namespace(tmp_path, _wheel_bytes())
    _converged_tree(namespace)
    if drift == "module-content":
        (namespace["module_root"] / "execution_host" / "__init__.py").write_bytes(b"drifted")
    elif drift == "extra-file":
        (namespace["module_root"] / "stateport_release" / "extra.py").write_bytes(b"extra")
    elif drift == "manifest":
        namespace["manifest"].write_bytes(b"drifted\n")
    elif drift == "cosign":
        namespace["cosign_root"].write_bytes(b"drifted")
    else:
        namespace["public_key_root"].write_bytes(b"drifted")
    with pytest.raises(SystemExit, match="refusing to replace"):
        exec(compile(_materialize_guard_source(), "materialize-guard", "exec"), namespace)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("releaseId", "release identity"),
        ("releaseIndexDigest", "release identity"),
        ("signedPayloadDigest", "release identity"),
        ("sourceCommit", "release identity"),
        ("sourceTree", "release identity"),
        ("installerDigest", "release identity"),
        ("targetId", "target identity"),
        ("topologyDigest", "target identity"),
    ],
)
def test_cleanup_refuses_each_mismatched_candidate_identity(
    field: str, message: str
) -> None:
    index, receipt = _cleanup_documents()
    receipt[field] = "tampered"
    receipt.pop("receiptDigest")
    receipt["receiptDigest"] = _canonical_digest(receipt)
    namespace = {
        "hashlib": hashlib,
        "json": json,
        "index": index,
        "receipt": receipt,
        "signed": index["signed"],
        "subject_digest": index["signatures"][0]["subjectDigest"],
    }

    with pytest.raises(SystemExit, match=message):
        exec(compile(_binding_block(), "cleanup-binding", "exec"), namespace)


def test_cleanup_inventory_contains_every_signed_image() -> None:
    index, receipt = _cleanup_documents()
    namespace = {
        "hashlib": hashlib,
        "json": json,
        "index": index,
        "receipt": receipt,
        "signed": index["signed"],
        "subject_digest": index["signatures"][0]["subjectDigest"],
    }
    exec(compile(_binding_block(), "cleanup-binding", "exec"), namespace)
    references = [image["reference"] for image in index["signed"]["images"]]
    assert namespace["all_references"] == references


def test_qualification_cleanup_removes_both_subordinate_mappings() -> None:
    source = _cleanup_source()
    assert 'for user in (control_user, exec_user)' in source


def test_cleanup_subordinate_mapping_contract_accepts_legacy_and_current_receipts() -> None:
    function = _cleanup_functions("subordinate_mappings")["subordinate_mappings"]
    function.__globals__.update(
        {"exec_user": "stateport-exec", "control_user": "stateport-control"}
    )
    legacy = {
        "subordinateIds": {"user": "stateport-exec", "start": 100000, "count": 65536}
    }
    assert function(legacy) == [("stateport-exec", 100000, 165535)]
    current = {
        **legacy,
        "controlSubordinateIds": {
            "user": "stateport-control",
            "start": 165536,
            "count": 65536,
        },
    }
    assert function(current) == [
        ("stateport-exec", 100000, 165535),
        ("stateport-control", 165536, 231071),
    ]
    with pytest.raises(SystemExit, match="stateport-control"):
        function({**legacy, "controlSubordinateIds": {"user": "stateport-control"}})


def _cleanup_functions(*names: str) -> dict[str, object]:
    tree = ast.parse(_cleanup_source())
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    namespace: dict[str, object] = {}
    executable = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    exec(compile(executable, "cleanup-functions", "exec"), namespace)
    return namespace


@pytest.mark.parametrize(
    ("returncode", "expected", "refuses"),
    [(0, True, False), (1, False, False), (2, None, True), (255, None, True)],
)
def test_execution_store_image_probe_accepts_only_exact_statuses(
    returncode: int, expected: bool | None, refuses: bool
) -> None:
    namespace = _cleanup_functions("image_exists")

    namespace.update({
        "runuser_env": ["runuser"],
        "subprocess": SimpleNamespace(
            run=lambda *_args, **_kwargs: SimpleNamespace(returncode=returncode)
        ),
        "ENV": {},
    })
    if refuses:
        with pytest.raises(SystemExit, match="image absence probe failed"):
            namespace["image_exists"]("example@sha256:" + "1" * 64)
    else:
        assert namespace["image_exists"]("example@sha256:" + "1" * 64) is expected


@pytest.mark.parametrize(
    ("returncode", "stdout", "expected", "refuses"),
    [
        (3, "inactive\n", True, False),
        (0, "active\n", False, False),
        (3, "failed\n", None, True),
        (4, "unknown\n", None, True),
        (255, "", None, True),
    ],
)
def test_execution_service_probe_accepts_only_exact_inactive_status(
    returncode: int, stdout: str, expected: bool | None, refuses: bool
) -> None:
    namespace = _cleanup_functions("service_inactive")
    namespace.update({
        "runuser_env": ["runuser"],
        "subprocess": SimpleNamespace(
            run=lambda *_args, **_kwargs: SimpleNamespace(
                returncode=returncode, stdout=stdout
            )
        ),
        "ENV": {},
    })
    if refuses:
        with pytest.raises(SystemExit, match="service absence probe failed"):
            namespace["service_inactive"]("stateport.service")
    else:
        assert namespace["service_inactive"]("stateport.service") is expected
