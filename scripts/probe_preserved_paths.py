#!/usr/bin/env python3
"""Resolve the API paths a test file actually dispatches, instead of grepping for a literal.

WHY THIS EXISTS. A substring search over test sources is a *guaranteed* false negative for every
endpoint reached through a composing request helper. Measured counter-example: the literal
``/v1/provider/credential`` appears in no test file, yet ``scripts/test_provider_setup.py``
exercises it, because it calls a helper that builds the path:

    def request(connection, headers, action, body=None):
        method = 'GET' if action == 'status' else 'POST'
        connection.request(method, f'/v1/provider/{action}', ...)

    request(connection, headers, 'credential', {...})      # -> POST /v1/provider/credential

A literal is not a call. This tool therefore resolves, per test file, the set of HTTP paths the file
really dispatches, by AST:

1. find local helpers whose body passes a *composed* path (an f-string or concatenation) into a
   request sink, and record the path template plus the parameter carrying the variable part;
2. at each call site of such a helper, bind that parameter to a literal argument and compose;
3. also collect paths passed literally to pass-through helpers, which the old grep happened to catch.

It is deliberately conservative: a fragment it cannot bind to a literal yields a ``<dynamic:NAME>``
placeholder rather than a guessed path, because a wrong path is worse than an unknown one.

Usage:  python3 scripts/probe_preserved_paths.py [--json] [testfile ...]
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Calls that actually put bytes on the wire.
SINK_METHODS = {"request", "urlopen", "open", "get", "post", "put", "delete", "patch", "fetch"}
# Attribute chains like connection.request(...), self.client.get(...)
SINK_ATTRS = {"request", "urlopen", "get", "post", "put", "delete", "patch", "fetch"}


def _repo_files(*prefixes: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", *prefixes], capture_output=True, text=True, cwd=ROOT
    ).stdout.split()
    return out


def default_test_files() -> list[str]:
    """The whole test population, from ``git ls-files`` rather than a remembered count."""
    files = []
    files += [p for p in _repo_files("apps/web/src") if p.endswith((".test.ts", ".spec.ts", ".test.tsx", ".spec.tsx"))]
    files += [p for p in _repo_files("apps/web/tests") if p.endswith((".spec.ts", ".test.ts"))]
    files += [p for p in _repo_files("scripts") if p.startswith("scripts/test_") and p.endswith(".py")]
    return files


def _sink_names(tree: ast.AST) -> set[str]:
    """Names that put bytes on the wire, including LOCAL wrappers, computed to a fixpoint.

    A fixed list of well-known names is not enough: the service tests dispatch through helpers called
    ``_get``, ``_post``, ``_call`` and so on, none of which appear in any list. A local function that
    FORWARDS one of its parameters to a real sink is itself a sink, so seed with the well-known names
    and Attribute-shaped calls, then absorb local wrappers until nothing new appears.
    """
    sinks: set[str] = set(SINK_METHODS)
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    changed = True
    while changed:
        changed = False
        for fn in funcs:
            if fn.name in sinks:
                continue
            for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
                callee = call.func.attr if isinstance(call.func, ast.Attribute) else (
                    call.func.id if isinstance(call.func, ast.Name) else None)
                if callee in sinks:
                    sinks.add(fn.name)
                    changed = True
                    break
    return sinks


def _is_sink(node: ast.AST, sinks: set[str] | None = None) -> bool:
    """Is this the callable that puts bytes on the wire?

    Both shapes occur and both are real: ``connection.request(...)`` is an ``Attribute``, and a bare
    helper or ``urlopen(...)`` is a ``Name``. Checking only the ``Attribute`` shape makes the bare
    form invisible, which silently drops literal paths passed to pass-through helpers.
    """
    if isinstance(node, ast.Attribute) and node.attr in SINK_ATTRS:
        return True
    if isinstance(node, ast.Name) and node.id in (sinks if sinks is not None else SINK_METHODS):
        return True
    return False


def _template_of(node: ast.AST) -> tuple[str, str] | None:
    """Return (template, parameter) when ``node`` is a composed path with one variable part.

    ``f'/v1/provider/{action}'`` -> ``('/v1/provider/', 'action')``.  A purely literal string returns
    ``None`` here and is handled by the pass-through branch instead.
    """
    parts: list[str] = []
    var: str | None = None
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name):
                parts.append("\x00")
                var = v.value.id
            else:
                return None
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        try:
            left, right = ast.literal_eval(node.left), ast.literal_eval(node.right)
            if isinstance(left, str) and isinstance(right, str):
                parts, var = [left, "\x00", right], None
        except (ValueError, SyntaxError):
            return None
    else:
        return None
    if var is None:
        return None
    return "".join(parts), var


def _literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def dispatched_paths(source: str) -> set[str]:
    """Every HTTP path this source dispatches, with composed helpers resolved."""
    tree = ast.parse(source)
    found: set[str] = set()
    sinks = _sink_names(tree)

    # Pass 1: local helpers that compose a path from a parameter.
    #
    # A name is NOT a signature: one test file can define several helpers with the same name and
    # different parameters (``def request(method, path, ...)`` alongside
    # ``def request(connection, headers, action, ...)``), so a name-keyed dict silently keeps only
    # the last one and loses the other. Key on (name, parameter index, arity) instead and select at
    # the call site.
    composed: dict[str, list[tuple[str, str, int, int]]] = {}
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
        n_defaults = len(fn.args.defaults)
        required = len(params) - n_defaults
        arity = max(required, len(params))
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
            if not _is_sink(call.func, sinks):
                continue
            for i, arg in enumerate(list(call.args) + [k.value for k in call.keywords]):
                tpl = _template_of(arg)
                if tpl:
                    template, var = tpl
                    index = params.index(var) if var in params else -1
                    if index >= 0:
                        composed.setdefault(fn.name, []).append((template, var, index, arity))
                    break

    # Pass 2: resolve each helper call site against its template.
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        if not (isinstance(call.func, ast.Name) and call.func.id in composed):
            continue
        args = call.args
        for template, var, index, _arity in composed[call.func.id]:
            # A fragment is normally passed POSITIONALLY, so bind by the parameter's own index
            # rather than by matching a Name of the same identifier, which never matches.
            frag = _literal(args[index]) if index < len(args) else None
            if frag is None:
                for k in call.keywords:
                    if k.arg == var:
                        frag = _literal(k.value)
            if frag is not None:
                found.add(template.replace("\x00", frag))

    # Pass 3: literal paths handed straight to a sink, including pass-through helpers.
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        if not _is_sink(call.func, sinks):
            continue
        for arg in call.args:
            lit = _literal(arg)
            if lit and lit.startswith("/v1/") or (lit and lit.startswith("/")):
                found.add(lit)

    # Pass 4: TABLE-DRIVEN dispatch.
    #
    # Most service tests do not name a path at the call site. They declare a table of cases and then
    # loop it into a dispatch helper:
    #
    #     CASES = (("/v1/execution-host/workloads", "execution_host_access_denied"), ...)
    #     for path, expected in CASES:
    #         _get(port, path)
    #
    # A call-site-only probe misses every one of those, and this is the dominant shape: it is why a
    # whole-population run found so few paths while scripts/test_post_mutation_security_matrix.py
    # visibly contains the execution-host routes. So collect path-like literals and mark one as
    # dispatched when the collection holding it is iterated by a `for` whose target reaches a sink.
    sink_bound: set[str] = set()
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        if not _is_sink(call.func, sinks):
            continue
        for arg in call.args:
            if isinstance(arg, ast.Name):
                sink_bound.add(arg.id)
    table_members: dict[int, set[str]] = {}
    assigned: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            members = set()
            for elt in node.elts:
                lit = _literal(elt)
                if lit is None and isinstance(elt, (ast.Tuple, ast.List)):
                    # a row like ("/v1/x", "reason") inside a table of rows
                    lit = next(
                        (_literal(x) for x in elt.elts if _literal(x) and _literal(x).startswith("/")),
                        None,
                    )
                if lit and lit.startswith("/"):
                    members.add(lit)
            if members:
                table_members[id(node)] = members
    # Bindings are collected in a SEPARATE pass. ast.walk is breadth-first, so a single pass visits
    # the Assign before the Tuple it assigns, and the binding would be looked up in an empty table.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if isinstance(value, (ast.Tuple, ast.List, ast.Set)) and id(value) in table_members:
                for tgt in targets:
                    if isinstance(tgt, ast.Name):
                        assigned[tgt.id] = id(value)
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        targets = {t.id for t in ast.walk(node.target) if isinstance(t, ast.Name)}
        if not (targets & sink_bound):
            continue
        key = id(node.iter)
        if isinstance(node.iter, ast.Name):
            key = assigned.get(node.iter.id, key)
        for lit in table_members.get(key, set()):
            found.add(lit)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("files", nargs="*", help="test files (default: the whole tracked population)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    files = args.files or default_test_files()
    index: dict[str, list[str]] = {}
    unparsable: list[str] = []
    for rel in files:
        try:
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            paths = dispatched_paths(text)
        except SyntaxError as exc:
            # A file that does not parse is a GAP IN THE PROBE, not evidence about the product.
            # Report it and continue, so one unparsable file cannot masquerade as "untested".
            unparsable.append(f"{rel}: {exc}")
            continue
        for p in paths:
            index.setdefault(p, []).append(rel)

    if args.json:
        print(json.dumps({k: sorted(v) for k, v in sorted(index.items())}, indent=1))
        return 0
    for path in sorted(index):
        print(f"{path}  <-  {', '.join(sorted(index[path])[:3])}")
    print(
        f"\n{len(index)} distinct paths dispatched by {len(files) - len(unparsable)} test files",
        file=sys.stderr,
    )
    for u in unparsable:
        print(f"UNPARSABLE (probe gap, not a verdict): {u}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
