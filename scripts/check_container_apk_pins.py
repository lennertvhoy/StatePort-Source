#!/usr/bin/env python3
"""Replay the exact apk/apt package pins of every container build against live indexes.

Exact package pins (``apk add pkg=1.2-r0``, ``apt-get install pkg=1.2``) fail
closed when the distribution repository rolls forward: Alpine keeps only the
current release of each package in v3.x and edge, so a pin that resolved last
week can be gone today.  The error is only discovered at build time, minutes
into a heavy release run.  This checker finds it in seconds, before the build.

For every Containerfile/Dockerfile under ``apps/*/`` and ``images/*/`` it
parses each build stage (FROM with ARG defaults, ``AS`` names and stage-to-stage
``FROM``), extracts every ``apk add`` / ``apt-get install`` invocation in
order (including ``--repository`` variants and multi-line continuations) and
replays them inside ONE throwaway container per stage that starts from the
stage's exact base image:

* each invocation is first simulated (``apk add -s`` / ``apt-get install -s``)
  and the PASS/FAIL result is recorded;
* the invocation is then really applied so that the next invocation of the same
  stage sees the state the real build would produce;
* apt invocations that are preceded by ``apt-get update`` in the same RUN
  refresh the index first, and ``COPY`` of files into ``/etc/apt/`` (for
  example a snapshot sources file) is replayed in order.

Steps after a failed step are reported SKIP: their input state is unknown.
Unpinned (or non-exact) package arguments are a FAIL as well.  Only apk/apt
effects are replayed, not other RUN/COPY steps; a package that another RUN step
removes or changes outside the package manager is outside this model.

Exit status: 0 only when every step passes, 1 on any FAIL/ERROR, 2 on usage
errors.  Needs the ``podman`` CLI and network access for the real run;
``--dry-run`` only parses and prints the plan.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

APK_OPTS_WITH_ARG = {
    "--repository", "-X", "--virtual", "-t", "--keys-dir", "--root", "-p",
    "--arch", "-a", "--cache-dir", "--repositories-file", "--wait",
    "--timeout", "--progress-fd", "--cache-max-age", "--allow-untrusted-key",
}
APT_OPTS_WITH_ARG = {"-o", "-t", "-c", "--target-release", "--option"}
SHELL_LEADERS = {"then", "do", "else", "elif", "if", "while", "until", "{", "!", "exec", "time"}
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
INSTRUCTION = re.compile(r"^\s*([A-Za-z]+)\b\s*(.*)$", re.DOTALL)
HEREDOC = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")


@dataclass
class PkgStep:
    kind: str  # "apk" or "apt"
    line: int
    ordinal: int  # nth package-manager invocation within its RUN
    options: list[str]
    repositories: list[str]
    packages: list[str]
    refresh_index: bool = False  # RUN also runs `apt-get update`
    pre_files: list[tuple[str, str]] = field(default_factory=list)  # (dest, b64 content)

    @property
    def unpinned(self) -> list[str]:
        out = []
        for pkg in self.packages:
            name, sep, version = pkg.partition("=")
            if not sep or not version or any(c in name for c in "<>~/"):
                out.append(pkg)
        return out


@dataclass
class Stage:
    index: int
    name: str | None
    base_raw: str
    base: str | None  # resolved image reference (None when it is a stage reference)
    parent: int | None  # index of the parent stage for `FROM <stage>`
    line: int
    steps: list[PkgStep] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"stage[{self.index}]" + (f" {self.name}" if self.name else "")


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def logical_instructions(text: str) -> list[tuple[int, str, str]]:
    """Return (first line, keyword, argument text) for each instruction.

    Handles backslash continuations, comment lines inside a continuation and
    shell heredocs.
    """
    lines = text.splitlines()
    out: list[tuple[int, str, str]] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i + 1
        parts: list[str] = []
        while i < len(lines):
            cur = lines[i]
            if parts and cur.strip().startswith("#"):
                i += 1  # comment line inside a continuation is dropped
                continue
            text_line = cur.rstrip()
            cont = text_line.endswith("\\")
            parts.append(text_line[:-1] if cont else text_line)
            if not cont:
                break
            i += 1
        joined = " ".join(p.strip() for p in parts if p.strip())
        heredocs = HEREDOC.findall(joined)
        body: list[str] = []
        for delim in heredocs:
            i += 1
            while i < len(lines) and lines[i].strip() != delim:
                body.append(lines[i])
                i += 1
        if body:
            joined = joined + "\n" + "\n".join(body)
        match = INSTRUCTION.match(joined)
        if match:
            out.append((start, match.group(1).upper(), match.group(2)))
        i += 1
    return out


def expand_vars(value: str, variables: dict[str, str]) -> tuple[str, list[str]]:
    """Expand $VAR, ${VAR} and ${VAR:-default}; return (text, unresolved names)."""
    missing: list[str] = []
    pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")

    def sub(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(3)
        default = match.group(2)
        if name in variables:
            return variables[name]
        if default is not None:
            return default
        missing.append(name)
        return match.group(0)

    return pattern.sub(sub, value), missing


def split_shell(text: str) -> list[str]:
    """Split a shell command on && || ; | and newlines, respecting quotes."""
    segments: list[str] = []
    buf: list[str] = []
    quote = ""
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 1
            elif c == quote:
                quote = ""
        elif c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(text[i + 1])
            i += 1
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c in ";|\n" or (c == "&" and text[i : i + 2] == "&&"):
            if c in "&|" and text[i : i + 2] == c * 2:
                i += 1
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


def _tokens(segment: str) -> list[str]:
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        tokens = segment.split()
    while tokens and (tokens[0] in SHELL_LEADERS or ENV_ASSIGN.match(tokens[0])):
        tokens.pop(0)
    return tokens


def parse_pkg_invocations(command: str, line: int, pre_files: list[tuple[str, str]]) -> list[PkgStep]:
    """Extract apk add / apt-get install invocations from one RUN command."""
    segments = split_shell(command)
    refresh = any(
        len(t) >= 2 and t[0] in {"apt-get", "apt"} and "update" in t[1:3]
        for t in (_tokens(s) for s in segments)
    )
    steps: list[PkgStep] = []
    ordinal = 0
    for segment in segments:
        tokens = _tokens(segment)
        if not tokens:
            continue
        tool = tokens[0].rsplit("/", 1)[-1]
        if tool == "apk":
            verb_at = next((k for k, t in enumerate(tokens[1:], 1) if not t.startswith("-")), None)
            if verb_at is None or tokens[verb_at] != "add":
                continue
            before = tokens[1:verb_at]
            rest = tokens[verb_at + 1 :]
            options, repos, pkgs = list(before), [], []
            k = 0
            while k < len(rest):
                tok = rest[k]
                if tok.startswith("-"):
                    if "=" in tok and tok.startswith("--"):
                        flag, _, val = tok.partition("=")
                        options.append(tok)
                        if flag == "--repository":
                            repos.append(val)
                    elif tok in APK_OPTS_WITH_ARG and k + 1 < len(rest):
                        options.extend([tok, rest[k + 1]])
                        if tok in {"--repository", "-X"}:
                            repos.append(rest[k + 1])
                        k += 1
                    else:
                        options.append(tok)
                else:
                    pkgs.append(tok)
                k += 1
            if pkgs:
                ordinal += 1
                steps.append(PkgStep("apk", line, ordinal, options, repos, pkgs))
        elif tool in {"apt-get", "apt"}:
            verb_at = None
            k = 1
            while k < len(tokens):
                tok = tokens[k]
                if tok.startswith("-"):
                    k += 2 if tok in APT_OPTS_WITH_ARG else 1
                    continue
                verb_at = k
                break
            if verb_at is None or tokens[verb_at] != "install":
                continue
            options = [t for t in tokens[1:verb_at]]
            rest = tokens[verb_at + 1 :]
            pkgs = []
            k = 0
            while k < len(rest):
                tok = rest[k]
                if tok.startswith("-"):
                    options.append(tok)
                    if tok in APT_OPTS_WITH_ARG and k + 1 < len(rest):
                        options.append(rest[k + 1])
                        k += 1
                else:
                    pkgs.append(tok)
                k += 1
            if pkgs:
                ordinal += 1
                steps.append(PkgStep("apt", line, ordinal, options, [], pkgs, refresh_index=refresh))
    if steps and pre_files:
        steps[0].pre_files = list(pre_files)
        pre_files.clear()
    return steps


def parse_dockerfile(path: Path, repo_root: Path = REPO_ROOT) -> list[Stage]:
    text = path.read_text(encoding="utf-8")
    global_args: dict[str, str] = {}
    stages: list[Stage] = []
    pending_files: list[tuple[str, str]] = []
    for line, keyword, arg in logical_instructions(text):
        if keyword == "ARG" and not stages:
            name, sep, default = arg.strip().partition("=")
            name = name.strip()
            if sep:
                global_args[name] = expand_vars(default.strip().strip("\"'"), global_args)[0]
            continue
        if keyword == "FROM":
            tokens = [t for t in arg.split() if not t.startswith("--")]
            image_raw = tokens[0] if tokens else ""
            name = None
            if len(tokens) >= 3 and tokens[1].upper() == "AS":
                name = tokens[2]
            image, missing = expand_vars(image_raw, global_args)
            stage = Stage(len(stages), name, image_raw, None, None, line)
            parent = next(
                (s.index for s in stages if s.name and s.name.lower() == image.lower()), None
            )
            if parent is not None:
                stage.parent = parent
            else:
                stage.base = image
                if missing:
                    stage.problems.append(f"unresolved FROM variable(s): {', '.join(sorted(set(missing)))}")
                elif "@sha256:" not in image:
                    stage.problems.append("base image is not pinned by digest; the replay uses the tag")
            stages.append(stage)
            pending_files = []
            continue
        if not stages:
            continue
        stage = stages[-1]
        if keyword == "COPY":
            tokens = [t for t in shlex.split(arg) if not t.startswith("--")]
            if len(tokens) == 2 and tokens[1].startswith("/etc/apt/"):
                src = repo_root / tokens[0]
                if src.is_file():
                    pending_files.append((tokens[1], base64.b64encode(src.read_bytes()).decode()))
        elif keyword == "RUN":
            stage.steps.extend(parse_pkg_invocations(arg, line, pending_files))
    return stages


def discover(repo_root: Path) -> list[Path]:
    found: set[Path] = set()
    for pattern in ("apps/*/", "images/*/"):
        for directory in repo_root.glob(pattern):
            for candidate in directory.iterdir():
                name = candidate.name
                if candidate.is_file() and (
                    name in {"Dockerfile", "Containerfile"}
                    or name.startswith(("Dockerfile.", "Containerfile."))
                    or name.endswith((".Dockerfile", ".Containerfile"))
                ):
                    found.add(candidate)
    return sorted(found)


# --------------------------------------------------------------------------
# Replay
# --------------------------------------------------------------------------


def chain_for(stages: list[Stage], stage: Stage) -> tuple[str | None, list[tuple[Stage, PkgStep]]]:
    """Root base image and ordered (owner stage, step) list including ancestor stages."""
    lineage: list[Stage] = []
    cur: Stage | None = stage
    seen: set[int] = set()
    while cur is not None and cur.index not in seen:
        seen.add(cur.index)
        lineage.append(cur)
        cur = stages[cur.parent] if cur.parent is not None else None
    lineage.reverse()
    root = lineage[0]
    steps = [(owner, step) for owner in lineage for step in owner.steps]
    return root.base, steps


def build_script(items: list[tuple[Stage, PkgStep]], target: Stage) -> str:
    """Shell script that simulates then applies each step, with machine-readable markers."""
    out = ["export DEBIAN_FRONTEND=noninteractive", "set +e"]
    for n, (owner, step) in enumerate(items):
        own = owner.index == target.index
        tag = f"{'own' if own else 'anc'}:{n}"
        for dest, b64 in step.pre_files:
            out.append(f"mkdir -p {shlex.quote(str(Path(dest).parent))}")
            out.append(f"printf %s {shlex.quote(b64)} | base64 -d > {shlex.quote(dest)}")
        q = lambda xs: " ".join(shlex.quote(x) for x in xs)  # noqa: E731
        out.append(f"echo '@@BEGIN {tag}'")
        if step.kind == "apk":
            sim = f"apk add -s {q(step.options)} {q(step.packages)}"
            real = f"apk add {q(step.options)} {q(step.packages)}"
        else:
            if step.refresh_index:
                out.append("apt-get update >/tmp/.update.log 2>&1; urc=$?")
                out.append(
                    f"if [ $urc -ne 0 ]; then tail -n 15 /tmp/.update.log; "
                    f"echo '@@RC {tag} '$urc; echo '@@END'; exit 0; fi"
                )
            sim = f"apt-get install -s {q(step.options)} {q(step.packages)}"
            real = f"apt-get install {q(step.options)} {q(step.packages)}"
        out.append(f"{sim} 2>&1")
        out.append("rc=$?")
        out.append(f"echo '@@RC {tag} '$rc")
        out.append("if [ $rc -ne 0 ]; then echo '@@END'; exit 0; fi")
        if n < len(items) - 1:
            out.append(f"{real} >/tmp/.apply.log 2>&1")
            out.append("arc=$?")
            out.append(f"if [ $arc -ne 0 ]; then echo '@@APPLYFAIL {tag}'; tail -n 40 /tmp/.apply.log; echo '@@END'; exit 0; fi")
    out.append("echo '@@END'")
    return "\n".join(out) + "\n"


def parse_script_output(output: str) -> dict[str, tuple[int, str]]:
    """Map step tag -> (rc, text); an apply failure is stored under ``tag!apply``."""
    results: dict[str, tuple[int, str]] = {}
    current: str | None = None
    apply_tag: str | None = None
    text: list[str] = []
    for raw in output.splitlines():
        if raw.startswith("@@BEGIN "):
            current, apply_tag, text = raw.split(" ", 1)[1].strip(), None, []
        elif raw.startswith("@@RC ") and current:
            results[current] = (int(raw.split()[2]), "\n".join(text[-25:]).strip())
        elif raw.startswith("@@APPLYFAIL "):
            apply_tag, text = raw.split(" ", 1)[1].strip() + "!apply", []
        elif raw.startswith("@@END"):
            if apply_tag:
                results[apply_tag] = (1, "applying the step failed after a passing simulation:\n" + "\n".join(text).strip())
            current = apply_tag = None
        elif current is not None or apply_tag is not None:
            text.append(raw)
    return results


def run_stage(
    stages: list[Stage], stage: Stage, rel: str, network: str | None, timeout: int
) -> list[dict]:
    base, items = chain_for(stages, stage)
    own = [(o, s) for o, s in items if o.index == stage.index]
    records: list[dict] = []

    def record(step: PkgStep, status: str, detail: str) -> dict:
        extra = step.unpinned
        if status == "PASS" and extra:
            status, detail = "FAIL", "unpinned or non-exact packages: " + ", ".join(extra)
        elif status == "FAIL" and extra:
            detail += "\nalso unpinned or non-exact packages: " + ", ".join(extra)
        return {
            "file": rel,
            "stage": stage.index,
            "stage_name": stage.name,
            "base": base,
            "line": step.line,
            "ordinal": step.ordinal,
            "kind": step.kind,
            "repositories": step.repositories,
            "packages": step.packages,
            "status": status,
            "detail": detail,
        }

    if base is None or any("unresolved" in p for p in stage.problems):
        return [record(s, "ERROR", "; ".join(stage.problems) or "no base image") for _, s in own]

    script = build_script(items, stage)
    cmd = ["podman", "run", "--rm", "-i", "--entrypoint", "/bin/sh"]
    if network:
        cmd += ["--network", network]
    cmd += [base, "-s"]
    try:
        proc = subprocess.run(
            ["nice", "-n", "19", *cmd], input=script, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return [record(s, "ERROR", f"podman replay timed out after {timeout}s") for _, s in own]
    results = parse_script_output(proc.stdout)
    if not results and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()[-1500:]
        return [record(s, "ERROR", f"could not start the base container: {detail}") for _, s in own]
    blocked = False
    for n, (owner, step) in enumerate(items):
        tag = f"{'own' if owner.index == stage.index else 'anc'}:{n}"
        res = results.get(tag)
        applyfail = results.get(tag + "!apply")
        if owner.index != stage.index:
            if blocked:
                continue
            if res is None or res[0] != 0 or applyfail:
                blocked = True
                reason = (applyfail or res or (0, "no output from the container"))[1]
                records.extend(
                    record(s, "SKIP", f"blocked: earlier step in {owner.label} (line {step.line}) failed:\n{reason}")
                    for _, s in own
                )
            continue
        if blocked:
            records.append(record(step, "SKIP", "blocked by an earlier failing step"))
        elif res is None:
            records.append(record(step, "ERROR", "no result from the container; stderr: " + proc.stderr.strip()[-500:]))
            blocked = True
        elif applyfail:
            records.append(record(step, "ERROR", applyfail[1]))
            blocked = True
        elif res[0] == 0:
            records.append(record(step, "PASS", ""))
        else:
            records.append(record(step, "FAIL", res[1]))
            blocked = True
    return records


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def describe(step: PkgStep) -> str:
    repos = f" repos={','.join(step.repositories)}" if step.repositories else ""
    return f"{step.kind} {len(step.packages)} pkg(s){repos}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", action="append", default=[], metavar="PATH",
                        help="check only Containerfiles whose path ends with / equals PATH (repeatable)")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON instead of text")
    parser.add_argument("--dry-run", action="store_true", help="parse and print the plan; do not run podman")
    parser.add_argument("--network", default=None, help="value for podman run --network (default: podman's)")
    parser.add_argument("--jobs", type=int, default=1, help="stages replayed in parallel (default 1)")
    parser.add_argument("--timeout", type=int, default=600, help="seconds per stage container (default 600)")
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()

    files = discover(repo_root)
    if args.only:
        wanted = [o.strip("./") if o.startswith("./") else o for o in args.only]
        files = [f for f in files if any(str(f.relative_to(repo_root)).endswith(w) for w in wanted)]
        if not files:
            print(f"no Containerfile matches --only {args.only}", file=sys.stderr)
            return 2

    plan: list[tuple[str, list[Stage], Stage]] = []
    file_info = []
    for path in files:
        rel = str(path.relative_to(repo_root))
        stages = parse_dockerfile(path, repo_root)
        file_info.append({
            "file": rel,
            "stages": [
                {"stage": s.index, "name": s.name, "base": s.base, "parent": s.parent,
                 "problems": s.problems,
                 "steps": [{"line": st.line, "kind": st.kind, "repositories": st.repositories,
                            "packages": st.packages} for st in s.steps]}
                for s in stages
            ],
        })
        for stage in stages:
            if stage.steps:
                plan.append((rel, stages, stage))

    if args.dry_run:
        if args.json:
            print(json.dumps({"dry_run": True, "files": file_info}, indent=2))
        else:
            for rel, stages, stage in plan:
                base, items = chain_for(stages, stage)
                print(f"{rel} {stage.label} base={base or '(unresolved)'}")
                for problem in stage.problems:
                    print(f"  warning: {problem}")
                for owner, step in items:
                    mark = "" if owner.index == stage.index else f" (inherited from {owner.label})"
                    print(f"  line {step.line}: {describe(step)}{mark}: {' '.join(step.packages)}")
            skipped = [f["file"] for f in file_info if not any(s["steps"] for s in f["stages"])]
            for rel in skipped:
                print(f"{rel}: no apk/apt package steps")
        return 0

    records: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = [
            pool.submit(run_stage, stages, stage, rel, args.network, args.timeout)
            for rel, stages, stage in plan
        ]
        for future in futures:
            records.extend(future.result())

    summary = {k: sum(1 for r in records if r["status"] == k) for k in ("PASS", "FAIL", "ERROR", "SKIP")}
    ok = bool(records) and summary["FAIL"] == 0 and summary["ERROR"] == 0 and summary["SKIP"] == 0
    if args.json:
        print(json.dumps({"ok": ok, "summary": summary, "results": records}, indent=2))
    else:
        for r in records:
            stage = f"stage[{r['stage']}]" + (f" {r['stage_name']}" if r["stage_name"] else "")
            repos = f" repos={','.join(r['repositories'])}" if r["repositories"] else ""
            print(f"{r['status']:5} {r['file']} {stage} line {r['line']} #{r['ordinal']} "
                  f"{r['kind']} {len(r['packages'])} pkg(s){repos}")
            if r["detail"]:
                for text in r["detail"].splitlines():
                    print(f"        {text}")
        print(f"summary: {summary['PASS']} pass, {summary['FAIL']} fail, "
              f"{summary['ERROR']} error, {summary['SKIP']} skip")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
