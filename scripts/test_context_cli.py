#!/usr/bin/env python3
"""CLI acceptance smoke for the StateIR -> StatePack read-only path."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_SRC = ROOT / "packages" / "statedd-core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))

from statedd_core import create_instance


def test_context_build_and_inspect_cli_are_json_and_read_only() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = workspace / "template"
        shutil.copytree(ROOT / "templates" / "classdd", template)
        instance = workspace / "instance"
        create_instance(
            template,
            instance,
            instance_id="demo",
            name="Demo",
            owner_name="Alice",
            owner_handle="@alice",
        )
        state = instance / "state" / "class.yaml"
        state.write_text("class:\n  nextLesson:\n    topic: networking\n", encoding="utf-8")
        before = {
            path.relative_to(instance).as_posix(): path.read_bytes()
            for path in instance.rglob("*")
            if path.is_file()
        }
        built = subprocess.run(
            [
                str(ROOT / "stateport"),
                "context-build",
                str(instance),
                "--task",
                "show networking lesson",
                "--model",
                "test-model",
                "--budget",
                "200",
                "--template-path",
                str(template),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert built.returncode == 0, built.stdout + built.stderr
        pack = json.loads(built.stdout)
        assert pack["manifest"]["formatVersion"] == "statepack/v1"
        assert pack["manifest"]["generatedFor"]["model"] == "test-model"
        pack_path = workspace / "pack.json"
        pack_path.write_text(json.dumps(pack), encoding="utf-8")
        inspected = subprocess.run(
            [str(ROOT / "stateport"), "context-inspect", str(pack_path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert inspected.returncode == 0, inspected.stdout + inspected.stderr
        assert json.loads(inspected.stdout)["valid"] is True
        second_built = subprocess.run(
            [
                str(ROOT / "stateport"),
                "context-build",
                str(instance),
                "--task",
                "show networking lesson",
                "--model",
                "test-model",
                "--budget",
                "200",
                "--profile",
                "human",
                "--template-path",
                str(template),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert second_built.returncode == 0, second_built.stdout + second_built.stderr
        second_path = workspace / "second-pack.json"
        second_path.write_text(second_built.stdout, encoding="utf-8")
        compared = subprocess.run(
            [
                str(ROOT / "stateport"),
                "context-compare",
                str(pack_path),
                str(second_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert compared.returncode == 0, compared.stdout + compared.stderr
        comparison = json.loads(compared.stdout)
        assert comparison["equal"] is False
        assert "profile" in comparison["differences"]
        after = {
            path.relative_to(instance).as_posix(): path.read_bytes()
            for path in instance.rglob("*")
            if path.is_file()
        }
        assert after == before


if __name__ == "__main__":
    test_context_build_and_inspect_cli_are_json_and_read_only()
    print("PASS")
