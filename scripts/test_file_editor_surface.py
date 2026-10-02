#!/usr/bin/env python3
"""Static and unit-level checks for the optional CodeMirror file workbench surface."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[1]
_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _plain_output(value: str) -> str:
    return _ANSI_ESCAPE.sub("", value)

WEB = ROOT / "apps" / "web"
FILES = WEB / "src" / "features" / "files"


def test_codemirror_is_lockfile_pinned_and_built_reproducibly() -> None:
    package = json.loads((WEB / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((WEB / "package-lock.json").read_text(encoding="utf-8"))
    dockerfile = (WEB / "Dockerfile").read_text(encoding="utf-8")
    service = (ROOT / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "service_process.py").read_text(encoding="utf-8")
    dependencies = package["dependencies"]
    assert dependencies["@uiw/react-codemirror"].startswith("^4.")
    assert dependencies["@codemirror/merge"].startswith("^6.")
    assert "monaco-editor" not in json.dumps(package)
    locked = lock["packages"]["node_modules/@uiw/react-codemirror"]
    assert locked["version"] == "4.25.11" and locked["integrity"].startswith("sha512-")
    assert lock["packages"]["node_modules/@codemirror/merge"]["version"] == "6.12.2"
    assert lock["packages"]["node_modules/@codemirror/merge"]["integrity"].startswith("sha512-")
    assert lock["packages"]["node_modules/codemirror"]["version"] == "6.0.2"
    assert "npm ci --ignore-scripts" in dockerfile and "npm run build" in dockerfile
    assert "monaco" not in service


def test_editor_is_lazy_loaded_only_inside_a_permitted_application_workbench() -> None:
    app = (WEB / "src" / "App.tsx").read_text(encoding="utf-8")
    workbench_shell = (WEB / "src" / "shell" / "WorkbenchShell.tsx").read_text(encoding="utf-8")
    study = yaml.safe_load((ROOT / "fixtures" / "application-experiences" / "study-state.yaml").read_text(encoding="utf-8"))
    development = yaml.safe_load((ROOT / "fixtures" / "application-experiences" / "development-workspace.yaml").read_text(encoding="utf-8"))
    # The whole editor surface is one route-level lazy chunk; nothing imports
    # it eagerly and it renders only inside the workbench tools registry.
    assert "lazy(() => import('@/features/files/FilesTool'))" in app
    assert "import FilesTool" not in app
    assert "capabilities: ['file_viewer', 'editor']" in workbench_shell
    assert "toolAvailable" in workbench_shell and "hasCapability" in workbench_shell
    assert "This application does not include" in workbench_shell
    forbidden = {"workbench", "file_viewer", "editor", "terminal", "cto_orchestration", "benchmark_evidence"}
    assert forbidden.isdisjoint(study["capabilities"])
    assert {"workbench", "file_viewer", "editor"} <= set(development["capabilities"])


def test_files_surface_uses_safe_dom_and_never_accepts_a_host_root() -> None:
    sources = {
        path.relative_to(FILES).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(FILES.rglob("*"))
        if path.suffix in {".ts", ".tsx"} and "__tests__" not in path.as_posix()
    }
    assert sources
    for relative, source in sources.items():
        for forbidden in (
            ".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write", "document.writeln",
            "eval(", "new Function", "dangerouslySetInnerHTML", "localStorage", "sessionStorage",
            "projectRoot", "hostPath",
        ):
            assert forbidden not in source, (relative, forbidden)
    combined = "\n".join(sources.values())
    assert "createElement" in combined
    transport = (WEB / "src" / "client" / "http" / "transport.ts").read_text(encoding="utf-8")
    domains = (WEB / "src" / "client" / "http" / "domainsCore.ts").read_text(encoding="utf-8")
    endpoints = (WEB / "src" / "client" / "http" / "endpoints.ts").read_text(encoding="utf-8")
    # Writes stay CSRF-bound on the same-origin session and instance-bound:
    # the broker host root is never accepted as input, paths travel encoded,
    # and the response identity must match the requested path.
    assert "credentials: 'same-origin'" in transport
    assert "X-StatePort-CSRF" in transport
    assert "const enc = encodeURIComponent" in endpoints
    assert "file-workspace/${enc(operation)}" in endpoints
    assert "read.metadata.path !== path" in domains
    assert "The file must be read before it can be written" in domains
    assert "expectedBaseSha: baseSha" in domains


def test_editor_surface_covers_governed_desktop_and_read_only_capabilities() -> None:
    domains = (WEB / "src" / "client" / "http" / "domainsCore.ts").read_text(encoding="utf-8")
    editor = (FILES / "CodeEditor.tsx").read_text(encoding="utf-8")
    commands = (FILES / "editorCommands.ts").read_text(encoding="utf-8")
    diff = (FILES / "DiffView.tsx").read_text(encoding="utf-8")
    store = (FILES / "filesStore.ts").read_text(encoding="utf-8")
    language = (FILES / "language.ts").read_text(encoding="utf-8")
    tool = (FILES / "FilesTool.tsx").read_text(encoding="utf-8")
    dialog = (FILES / "SavePreviewDialog.tsx").read_text(encoding="utf-8")
    tokens = (WEB / "src" / "styles" / "tokens.css").read_text(encoding="utf-8")
    package = json.loads((WEB / "package.json").read_text(encoding="utf-8"))
    for feature in ("listDirectory", "readFile", "prepareWrite", "previewDiff", "commitWrite", "discardWrite"):
        assert f"'{feature}'" in domains, feature
    assert "openSearchPanel" in commands and "@codemirror/search" in editor
    assert "@codemirror/merge" in diff and "MergeView" in diff
    assert "export function docIsDirty" in store
    assert "md: { name: 'Markdown', support: () => markdown() }" in language
    assert "expectedBaseSha" in domains and "baseShas" in domains
    # Governed writes never save silently: a diff preview confirms every
    # write, stale bases refuse with a two-version resolution, and
    # broker-declared read-only files are enforced in the editor state.
    assert "Compare active file with last saved" in tool
    assert 'data-testid="confirm-save"' in dialog and 'data-testid="discard-changes"' in dialog
    assert "This file changed on disk since you opened it" in dialog
    assert "Save my version anyway" in dialog and "Reload disk version" in dialog
    assert "EditorState.readOnly.of(true)" in editor
    assert "The file changed on disk after it was opened." in domains
    # Responsive layout and accessibility preferences stay explicit.
    assert "useIsMobile" in tool and "Mobile: file picker + full-screen editor" in tool
    assert '[data-motion="reduced"]' in tokens
    assert "@fontsource/jetbrains-mono" in package["dependencies"]


def test_dynamic_preservation_distinguishes_equivalent_mobile_work_from_gaps() -> None:
    dynamic = yaml.safe_load(
        (ROOT / "config" / "frontend-dynamic-preservation.v1.yaml").read_text(encoding="utf-8")
    )
    controls = {item["id"]: item for item in dynamic["controls"]}
    behaviors = {item["id"]: item for item in dynamic["behaviors"]}
    operations = {item["operation"]: item for item in dynamic["operations"]}
    # Markdown preview and the governed mobile editor both point at executable
    # product evidence rather than frozen requirements or lookalike syntax
    # highlighting.
    assert controls["editor-preview-markdown"]["evidence"] == {
        "file": "apps/web/src/features/files/MarkdownPreview.tsx",
        "contains": "Noncanonical draft preview.",
    }
    assert behaviors["mobile-governed-editor"]["evidence"] == {
        "file": "apps/web/src/features/files/FilesTool.tsx",
        "contains": 'data-testid="mobile-review-save"',
    }
    # Create/rename/delete remain broker-owned, but are now connected through
    # the same application-scoped adapter and exact-review UI as ordinary
    # writes. The dynamic contract no longer points at a known UI gap.
    assert {"createFile", "renamePath", "deletePath"} <= operations.keys()
    domains = (WEB / "src" / "client" / "http" / "domainsCore.ts").read_text(encoding="utf-8")
    for operation in ("createFile", "renamePath", "deletePath"):
        assert f"postOperation(instanceId, '{operation}'" in domains
        assert operations[operation]["evidence"]["file"] == "apps/web/src/client/http/domainsCore.ts"
    mutation_dialog = (FILES / "FileMutationDialog.tsx").read_text(encoding="utf-8")
    assert "The broker may already have committed" in mutation_dialog
    assert 'data-testid={`file-${intent.kind}-confirm`}' in mutation_dialog


def test_governed_write_flow_and_store_guards_execute_in_vitest() -> None:
    result = subprocess.run(
        ["npm", "run", "test", "--", "src/features/files"],
        cwd=WEB,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = _plain_output(result.stdout)
    assert result.returncode == 0, output
    assert re.search(r"Test Files\s+\d+\s+passed", output), output
    assert re.search(r"Tests\s+\d+\s+passed", output), output
    assert not re.search(r"(?:Test Files|Tests)\s+\d+\s+failed", output), output


def test_editor_modules_typecheck_under_strict_typescript() -> None:
    result = subprocess.run(
        ["npm", "run", "typecheck"],
        cwd=WEB,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout


if __name__ == "__main__":
    raise SystemExit(__import__("pytest").main([__file__]))
