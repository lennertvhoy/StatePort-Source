"""Parser tests for scripts/check_container_apk_pins.py (no podman involved)."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("check_container_apk_pins", ROOT / "scripts" / "check_container_apk_pins.py")
checker = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = checker
_SPEC.loader.exec_module(checker)

DIGEST = "sha256:" + "a" * 64


def _parse(tmp_path: Path, text: str, name: str = "Dockerfile"):
    path = tmp_path / "images" / "x" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return checker.parse_dockerfile(path, tmp_path)


def test_multi_stage_with_names_and_stage_to_stage_from(tmp_path: Path) -> None:
    stages = _parse(
        tmp_path,
        f"""\
FROM docker.io/library/golang:1.26-alpine3.23@{DIGEST} AS builder
RUN apk add --no-cache git=2.52.0-r0

FROM builder AS tools
RUN apk add --no-cache make=4.4.1-r3

FROM docker.io/library/python:3.13-alpine3.23@{DIGEST}
RUN echo hello
""",
    )
    assert [s.name for s in stages] == ["builder", "tools", None]
    assert stages[0].base.endswith(f"@{DIGEST}") and stages[0].parent is None
    assert stages[1].parent == 0 and stages[1].base is None
    assert [s.packages for s in stages[1].steps] == [["make=4.4.1-r3"]]
    assert stages[2].steps == []
    base, items = checker.chain_for(stages, stages[1])
    assert base == stages[0].base
    assert [(o.index, s.packages) for o, s in items] == [(0, ["git=2.52.0-r0"]), (1, ["make=4.4.1-r3"])]


def test_arg_default_resolves_in_from_and_unresolved_is_reported(tmp_path: Path) -> None:
    stages = _parse(
        tmp_path,
        f"""\
ARG ALPINE=3.23
ARG BASE=docker.io/library/python:3.13-alpine${{ALPINE}}@{DIGEST}
FROM ${{BASE}}
RUN apk add libssl3=3.5.9-r0
FROM --platform=linux/amd64 ${{MISSING}} AS other
RUN apk add curl=1-r0
""",
    )
    assert stages[0].base == f"docker.io/library/python:3.13-alpine3.23@{DIGEST}"
    assert stages[0].problems == []
    assert stages[1].name == "other"
    assert any("unresolved" in p and "MISSING" in p for p in stages[1].problems)


def test_tag_only_base_is_flagged(tmp_path: Path) -> None:
    stages = _parse(tmp_path, "FROM alpine:3.23\nRUN apk add curl=1-r0\n")
    assert any("not pinned by digest" in p for p in stages[0].problems)


def test_continuation_lines_comments_and_cleanup_chain(tmp_path: Path) -> None:
    stages = _parse(
        tmp_path,
        f"""\
FROM alpine:3.23@{DIGEST}
# standalone comment
RUN apk add --no-cache \\
      git=2.52.0-r0 \\
      # a comment inside the continuation is dropped
      bubblewrap=0.12.0-r0 \\
    && rm -f /var/log/apk.log \\
    && git config --system --add safe.directory /workspace
""",
    )
    (step,) = stages[0].steps
    assert step.kind == "apk"
    assert step.options == ["--no-cache"]
    assert step.packages == ["git=2.52.0-r0", "bubblewrap=0.12.0-r0"]
    assert step.line == 3
    assert step.unpinned == []


def test_edge_repositories_both_spellings_and_virtual(tmp_path: Path) -> None:
    stages = _parse(
        tmp_path,
        f"""\
FROM alpine:3.23@{DIGEST}
RUN apk add --no-cache \\
      --repository https://dl-cdn.alpinelinux.org/alpine/edge/main \\
      --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \\
      -X https://example.invalid/extra \\
      --virtual .build-deps \\
      crun=1.30.1-r0 libgcc=15.2.0-r9
""",
    )
    (step,) = stages[0].steps
    assert step.repositories == [
        "https://dl-cdn.alpinelinux.org/alpine/edge/main",
        "https://dl-cdn.alpinelinux.org/alpine/edge/community",
        "https://example.invalid/extra",
    ]
    assert step.packages == ["crun=1.30.1-r0", "libgcc=15.2.0-r9"]
    assert "--virtual" in step.options and ".build-deps" in step.options and ".build-deps" not in step.packages


def test_two_apk_invocations_in_one_run_and_conditional_branch(tmp_path: Path) -> None:
    stages = _parse(
        tmp_path,
        f"""\
FROM alpine:3.23@{DIGEST}
RUN apk add --no-cache a=1-r0 && apk add --no-cache b=2-r0 ; \\
    if [ -n "$X" ]; then apk add c=3-r0; fi
""",
    )
    steps = stages[0].steps
    assert [s.packages for s in steps] == [["a=1-r0"], ["b=2-r0"], ["c=3-r0"]]
    assert [s.ordinal for s in steps] == [1, 2, 3]


def test_unpinned_and_range_pins_are_flagged(tmp_path: Path) -> None:
    stages = _parse(tmp_path, f"FROM alpine:3.23@{DIGEST}\nRUN apk add --no-cache git curl=1-r0 'zlib>=1.3' 'ssl~1.1' bare=\n")
    (step,) = stages[0].steps
    assert step.unpinned == ["git", "zlib>=1.3", "ssl~1.1", "bare="]


def test_apt_install_with_update_options_and_copy_into_etc_apt(tmp_path: Path) -> None:
    source = tmp_path / "images" / "x" / "snapshot.sources"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"Types: deb\nURIs: https://snapshot.example/\n")
    stages = _parse(
        tmp_path,
        f"""\
FROM ubuntu:24.04@{DIGEST}
RUN apt-get update \\
    && apt-get install --no-install-recommends -y ca-certificates=20260601~24.04.1 \\
    && rm -rf /var/lib/apt/lists/*
COPY images/x/snapshot.sources /etc/apt/sources.list.d/ubuntu.sources
COPY images/x/snapshot.sources /usr/share/ignored
RUN apt-get -o Acquire::Retries=3 update && apt-get -y install -t noble curl=8.5.0-2 jq=1.7.1-3
""",
    )
    first, second = stages[0].steps
    assert first.kind == "apt" and first.refresh_index and first.pre_files == []
    assert first.options == ["--no-install-recommends", "-y"]
    assert first.packages == ["ca-certificates=20260601~24.04.1"]
    assert second.packages == ["curl=8.5.0-2", "jq=1.7.1-3"]
    assert second.options == ["-y", "-t", "noble"]
    (dest, b64), = second.pre_files
    assert dest == "/etc/apt/sources.list.d/ubuntu.sources"
    assert base64.b64decode(b64) == b"Types: deb\nURIs: https://snapshot.example/\n"
    assert not second.unpinned


def test_non_package_runs_and_quoted_text_are_ignored(tmp_path: Path) -> None:
    stages = _parse(
        tmp_path,
        f"""\
FROM alpine:3.23@{DIGEST}
RUN echo "apk add fake=1 && apt-get install nope" > /tmp/note && apk info -v
RUN apk del git
RUN npm ci && node -e 'console.log("apk add x=1")'
""",
    )
    assert stages[0].steps == []


def test_heredoc_run_body_is_parsed(tmp_path: Path) -> None:
    stages = _parse(
        tmp_path,
        f"""\
FROM alpine:3.23@{DIGEST}
RUN <<EOF
set -eu
apk add --no-cache git=2.52.0-r0
EOF
RUN true
""",
    )
    assert [s.packages for s in stages[0].steps] == [["git=2.52.0-r0"]]
    assert len(stages) == 1


def test_discover_finds_apps_and_images_only(tmp_path: Path) -> None:
    for rel in ("apps/a/Dockerfile", "images/b/Containerfile", "images/c/Dockerfile.edge", "packages/z/Dockerfile", "apps/a/README.md"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("FROM scratch\n")
    found = [str(p.relative_to(tmp_path)) for p in checker.discover(tmp_path)]
    assert found == ["apps/a/Dockerfile", "images/b/Containerfile", "images/c/Dockerfile.edge"]


def test_generated_script_simulates_then_applies_and_orders_steps(tmp_path: Path) -> None:
    stages = _parse(
        tmp_path,
        f"""\
FROM alpine:3.23@{DIGEST}
RUN apk add --no-cache a=1-r0
RUN apk add --no-cache --repository https://edge.example/main b=2-r0
""",
    )
    _, items = checker.chain_for(stages, stages[0])
    script = checker.build_script(items, stages[0])
    lines = script.splitlines()
    assert lines.index("apk add -s --no-cache a=1-r0 2>&1") < lines.index("apk add --no-cache a=1-r0 >/tmp/.apply.log 2>&1")
    assert lines.index("echo '@@BEGIN own:1'") > lines.index("apk add --no-cache a=1-r0 >/tmp/.apply.log 2>&1")
    assert "apk add -s --no-cache --repository https://edge.example/main b=2-r0 2>&1" in lines
    # the last step is only simulated, never applied
    assert "apk add --no-cache --repository https://edge.example/main b=2-r0 >/tmp/.apply.log 2>&1" not in lines


def test_script_output_parser_reads_rc_and_apply_failures() -> None:
    out = "\n".join([
        "@@BEGIN own:0", "(1/1) Installing a", "@@RC own:0 0",
        "@@BEGIN own:1", "ERROR: unable to select packages:", "  b-2: breaks", "@@RC own:1 2", "@@END",
    ])
    parsed = checker.parse_script_output(out)
    assert parsed["own:0"][0] == 0
    assert parsed["own:1"][0] == 2 and "unable to select" in parsed["own:1"][1]
    failed = checker.parse_script_output("@@BEGIN own:0\n@@RC own:0 0\n@@APPLYFAIL own:0\nboom\n@@END")
    assert failed["own:0"][0] == 0 and failed["own:0!apply"][0] == 1 and "boom" in failed["own:0!apply"][1]


def test_dry_run_prints_plan_without_podman(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "apps" / "web" / "Dockerfile"
    path.parent.mkdir(parents=True)
    path.write_text(f"FROM alpine:3.23@{DIGEST}\nRUN apk add --no-cache git=2.52.0-r0\n")

    def boom(*_a, **_k):
        raise AssertionError("podman must not run in --dry-run")

    monkeypatch.setattr(checker.subprocess, "run", boom)
    assert checker.main(["--dry-run", "--repo-root", str(tmp_path)]) == 0
    assert "git=2.52.0-r0" in capsys.readouterr().out
    assert checker.main(["--dry-run", "--json", "--only", "apps/web/Dockerfile", "--repo-root", str(tmp_path)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["files"][0]["stages"][0]["steps"][0]["packages"] == ["git=2.52.0-r0"]
    assert checker.main(["--dry-run", "--only", "apps/nope/Dockerfile", "--repo-root", str(tmp_path)]) == 2


def test_real_repository_has_expected_stage_and_step_inventory() -> None:
    files = {str(p.relative_to(ROOT)): checker.parse_dockerfile(p, ROOT) for p in checker.discover(ROOT)}
    assert "apps/web/Dockerfile" in files and "images/stateport-execution-host/Containerfile" in files
    for rel, stages in files.items():
        for stage in stages:
            assert stage.problems == [], (rel, stage.problems)
            for step in stage.steps:
                assert step.unpinned == [], (rel, step.line, step.unpinned)
    web_steps = [s for st in files["apps/web/Dockerfile"] for s in st.steps]
    assert [s.kind for s in web_steps] == ["apk"] and len(web_steps[0].packages) == 9
    host = files["images/stateport-execution-host/Containerfile"]
    assert [len(s.steps) for s in host] == [1, 2]
    assert host[1].steps[1].repositories == [
        "https://dl-cdn.alpinelinux.org/alpine/edge/main",
        "https://dl-cdn.alpinelinux.org/alpine/edge/community",
    ]
    assert [len(s.steps) for s in files["images/stateport-dev-workspace/Containerfile"]] == [2, 0]
    assert [s.kind for st in files["images/stateport-playwright/Containerfile"] for s in st.steps] == ["apt"]
