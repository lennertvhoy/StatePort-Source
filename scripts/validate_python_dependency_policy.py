#!/usr/bin/env python3
"""Validate hashed Python locks, image consumers, providers, and licenses."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "python-dependency-policy.v1.json"
LICENSE_PATH = ROOT / "config" / "python-dependency-licenses.v1.json"
PACKAGE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)")


class PythonDependencyPolicyError(RuntimeError):
    """The Python dependency supply-chain contract is incomplete or stale."""


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PythonDependencyPolicyError(f"could not parse {path.name}") from exc
    if not isinstance(value, Mapping):
        raise PythonDependencyPolicyError(f"{path.name} must contain an object")
    return value


def _lock(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise PythonDependencyPolicyError(f"could not read {path.name}") from exc
    records: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line and not line[0].isspace() and not line.startswith("#") and PACKAGE.match(line):
            if current:
                records.append(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        records.append(current)
    packages: dict[str, str] = {}
    for record in records:
        match = PACKAGE.match(record[0])
        if match is None:
            raise PythonDependencyPolicyError(f"unparseable lock record in {path.name}")
        name, version = _normalized(match.group(1)), match.group(2)
        if name in packages:
            raise PythonDependencyPolicyError(f"duplicate locked package {name}")
        if "--hash=sha256:" not in "\n".join(record):
            raise PythonDependencyPolicyError(f"locked package {name} has no SHA-256 hash")
        packages[name] = version
    if not packages:
        raise PythonDependencyPolicyError(f"{path.name} contains no locked packages")
    return packages


def _roots(path: Path) -> dict[str, str]:
    packages: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = PACKAGE.match(stripped)
        if match is None:
            raise PythonDependencyPolicyError(f"dependency input {path.name} must contain exact pins")
        packages[_normalized(match.group(1))] = match.group(2)
    return packages


def _native_opencode_consumer(root: Path, relative: str, dockerfile: str) -> None:
    """The shipped agent is npm-integrity governed, never a PyPI extra.

    OpenCode is consumed as a maintained upstream release.  A recipe that
    mentions it must install the exact platform tarball recorded in
    ``config/provider-runtime-inputs.yaml``, cross-check the audited lock
    entry, verify the pinned SRI against the downloaded bytes, and assert the
    extracted binary's sha256 and reported version.
    """
    if "opencode" not in dockerfile:
        return
    try:
        provider = yaml.safe_load(
            (root / "config/provider-runtime-inputs.yaml").read_text()
        )["opencode"]
        version = provider["version"]
        platform = (
            provider["platforms"]["musl"]
            if "opencode-linux-x64-musl" in dockerfile
            else provider["platforms"]["glibc"]
        )
        lock = _json(root / provider["npm"]["packageLock"])["packages"]
        entry = lock["node_modules/" + platform["package"]]
        if (
            entry["version"] != version
            or entry["resolved"] != platform["tarball"]
            or entry["integrity"] != platform["integrity"]
        ):
            raise ValueError("native agent lock entry differs from the pin")
        required = (
            "COPY config/opencode-runtime/package.json config/opencode-runtime/package-lock.json",
            "ARG STATEPORT_OPENCODE_LOCK_PACKAGE=" + platform["package"],
            "ARG STATEPORT_OPENCODE_TARBALL=" + platform["tarball"],
            "ARG STATEPORT_OPENCODE_SRI=" + platform["integrity"],
            "ARG STATEPORT_OPENCODE_BINARY_SHA256=" + platform["observedBinarySha256"],
            "lock platform tarball differs from the pin",
            "tarball integrity differs from the pin",
            "STATEPORT_OPENCODE_BINARY_SHA256#sha256:",
        )
        if not all(value in dockerfile for value in required):
            raise ValueError("native agent is not imported and verified from its locked package")
        if not (
            re.search(r'opencode --version\)" = "' + re.escape(version) + '"', dockerfile)
            or re.search(r'opencode --version\)" = "\$STATEPORT_OPENCODE_VERSION"', dockerfile)
        ):
            raise ValueError("native agent version assertion is missing")
    except (KeyError, TypeError, ValueError, OSError, yaml.YAMLError) as exc:
        raise PythonDependencyPolicyError(
            f"{relative} has an undeclared or unverified native agent"
        ) from exc


def validate(root: Path = ROOT) -> dict[str, int]:
    policy = _json(root / "config" / "python-dependency-policy.v1.json")
    if set(policy) != {"schema", "runtime", "development", "providers"} or policy["schema"] != "stateport.python-dependency-policy/v1":
        raise PythonDependencyPolicyError("Python dependency policy shape is invalid")
    runtime = policy["runtime"]
    development = policy["development"]
    providers = policy["providers"]
    if not all(isinstance(item, Mapping) for item in (runtime, development, providers)):
        raise PythonDependencyPolicyError("Python dependency policy sections must be objects")
    runtime_lock = _lock(root / str(runtime["lock"]))
    development_lock = _lock(root / str(development["lock"]))
    if not set(_roots(root / str(runtime["input"]))).issubset(runtime_lock):
        raise PythonDependencyPolicyError("runtime dependency roots are absent from the lock")
    if not set(_roots(root / str(development["input"]))).issubset(development_lock):
        raise PythonDependencyPolicyError("development dependency roots are absent from the lock")
    if runtime.get("requireHashes") is not True or development.get("requireHashes") is not True:
        raise PythonDependencyPolicyError("all Python lock consumers must require hashes")
    provider_input = root / str(providers["input"])
    if _roots(provider_input):
        raise PythonDependencyPolicyError("public alpha provider extras must remain empty until explicitly governed")
    if providers.get("pythonPackagesShipped") != [] or providers.get("missingBehavior") != "typed_unavailable":
        raise PythonDependencyPolicyError("provider absence must be explicit and fail typed")
    consumers = runtime.get("consumers")
    if not isinstance(consumers, list) or consumers != sorted(consumers) or len(consumers) != len(set(consumers)):
        raise PythonDependencyPolicyError("runtime Dockerfile consumers must be unique and sorted")
    for relative in consumers:
        dockerfile = (root / str(relative)).read_text(encoding="utf-8")
        if "COPY requirements/runtime-linux-amd64.txt" not in dockerfile:
            raise PythonDependencyPolicyError(f"{relative} does not copy the exact runtime lock")
        if "--require-hashes" not in dockerfile:
            raise PythonDependencyPolicyError(f"{relative} does not enforce dependency hashes")
        install_text = dockerfile.replace("\\\n", " ")
        obsolete_python_provider = re.search(
            r"\bpip3?\b[^;&|\n]*\binstall\b[^;&|\n]*\bcodex[-_.]cli\b", install_text
        )
        if "|| true" in dockerfile or "pip install --no-cache-dir openai" in dockerfile or obsolete_python_provider:
            raise PythonDependencyPolicyError(f"{relative} contains a best-effort or undeclared provider install")
        for line in dockerfile.splitlines():
            if "pip install" in line and "--require-hashes" not in line:
                raise PythonDependencyPolicyError(f"{relative} contains an unhashed pip install")
        _native_opencode_consumer(root, str(relative), dockerfile)
    licenses = _json(root / "config" / "python-dependency-licenses.v1.json")
    if licenses.get("schema") != "stateport.python-dependency-licenses/v1" or licenses.get("reviewStatus") != "metadata_inventory_not_legal_advice":
        raise PythonDependencyPolicyError("Python license inventory boundary is invalid")
    entries = licenses.get("packages")
    if not isinstance(entries, list) or not entries:
        raise PythonDependencyPolicyError("Python license inventory is empty")
    inventory: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise PythonDependencyPolicyError("Python license entry is invalid")
        name = _normalized(str(entry.get("name", "")))
        version = entry.get("version")
        if not name or not isinstance(version, str) or name in inventory:
            raise PythonDependencyPolicyError("Python license package identity is invalid")
        if not isinstance(entry.get("licenseExpression"), str) or not isinstance(entry.get("metadataSource"), str):
            raise PythonDependencyPolicyError(f"Python license metadata is incomplete for {name}")
        inventory[name] = version
    expected = {**development_lock, **runtime_lock}
    if inventory != expected:
        raise PythonDependencyPolicyError("Python license inventory does not exactly match locked packages")
    return {"runtimePackages": len(runtime_lock), "developmentPackages": len(development_lock), "licensedPackages": len(inventory)}


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        result = validate(ROOT)
    except (PythonDependencyPolicyError, KeyError, OSError, UnicodeError) as exc:
        print(f"FAIL: {exc}")
        return 1
    print(
        "PASS: Python runtime/dev locks are exact, hashed, licensed, and provider-separated "
        f"({result['runtimePackages']} runtime; {result['developmentPackages']} development)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
