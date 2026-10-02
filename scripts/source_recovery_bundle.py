#!/usr/bin/env python3
"""Prepare or verify one owner-private immutable application-source bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/statedd-core/src"))

from statedd_core import load_source_contract, resolve_source_contract  # noqa: E402


FORMAT = "stateport.private-source-recovery/v1"
BUNDLE_NAME = "source.bundle"
RECEIPT_NAME = "receipt.json"
CANDIDATE_REF = "refs/heads/stateport-source-candidate"
MAX_BUNDLE_BYTES = 1024 * 1024 * 1024
GIT_SAFE_OPTIONS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.fsmonitorHook=",
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
    "-c",
    "core.sshCommand=",
    "-c",
    "http.proxy=",
    "-c",
    "http.extraHeader=",
)


class RecoveryBundleError(RuntimeError):
    """The private source carrier could not be prepared or verified safely."""


def _git_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _git(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    failure: str,
) -> str:
    try:
        result = subprocess.run(
            ["git", *GIT_SAFE_OPTIONS, *arguments],
            cwd=cwd or Path("/"),
            env=_git_environment(),
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RecoveryBundleError(failure) from exc
    if result.returncode != 0:
        raise RecoveryBundleError(failure)
    return result.stdout.strip()


def _absolute_existing(path: Path, *, kind: str) -> Path:
    configured = path.expanduser()
    if not configured.is_absolute() or configured.is_symlink():
        raise RecoveryBundleError(f"{kind} must be an absolute non-symlink path")
    try:
        resolved = configured.resolve(strict=True)
    except OSError as exc:
        raise RecoveryBundleError(f"{kind} does not exist") from exc
    if resolved != configured:
        raise RecoveryBundleError(f"{kind} must not traverse symbolic links")
    return resolved


def _credential_free_repository(value: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"https", "ssh"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RecoveryBundleError("source profile repository must be a credential-free HTTPS or SSH URL")


def _private_regular_file(path: Path, *, label: str) -> os.stat_result:
    if path.is_symlink() or not path.is_file():
        raise RecoveryBundleError(f"{label} is missing or unsafe")
    info = path.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RecoveryBundleError(f"{label} must be owner-private and single-link")
    return info


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _inspect_bundle(bundle: Path, profile: Path) -> dict[str, Any]:
    contract = load_source_contract(profile)
    _credential_free_repository(contract.repository)
    info = bundle.stat()
    if info.st_size <= 0 or info.st_size > MAX_BUNDLE_BYTES:
        raise RecoveryBundleError("source bundle size is outside the supported bound")
    listed = _git(
        ["bundle", "list-heads", str(bundle)],
        failure="source bundle head inventory is invalid",
    )
    if listed != f"{contract.commit} {CANDIDATE_REF}":
        raise RecoveryBundleError("source bundle does not expose the exact candidate ref")

    with tempfile.TemporaryDirectory(prefix="stateport-source-recovery-") as temporary:
        recovered = Path(temporary) / "source"
        _git(
            ["clone", "--quiet", "--no-checkout", str(bundle), str(recovered)],
            failure="source bundle could not be recovered",
        )
        _git(
            ["-C", str(recovered), "checkout", "--quiet", "--detach", contract.commit],
            failure="source bundle does not contain the required commit",
        )
        _git(
            ["-C", str(recovered), "remote", "set-url", "origin", contract.repository],
            failure="source bundle recovery origin could not be normalized",
        )
        try:
            resolved = resolve_source_contract(contract, repository_override=recovered)
        except (OSError, ValueError) as exc:
            raise RecoveryBundleError("source bundle content does not match the source contract") from exc
        descriptor = resolved.descriptor

    expected = {
        "commit": contract.commit,
        "tree": contract.expected_tree,
        "manifestDigest": contract.expected_manifest_digest,
    }
    observed = {
        "commit": descriptor.get("resolvedCommit"),
        "tree": descriptor.get("resolvedTree"),
        "manifestDigest": descriptor.get("manifestDigest"),
    }
    if observed != expected or not isinstance(descriptor.get("sourceDigest"), str):
        raise RecoveryBundleError("source bundle identity differs from the source contract")
    return {
        "repository": contract.repository,
        "templateId": contract.template_id,
        "sourceClass": contract.source_class,
        "productionEligible": contract.production_eligible,
        **expected,
        "sourceDigest": descriptor["sourceDigest"],
    }


def _receipt(identity: Mapping[str, Any], bundle: Path) -> dict[str, Any]:
    return {
        "formatVersion": FORMAT,
        "repository": identity["repository"],
        "ref": CANDIDATE_REF,
        "commit": identity["commit"],
        "tree": identity["tree"],
        "manifestDigest": identity["manifestDigest"],
        "sourceDigest": identity["sourceDigest"],
        "templateId": identity["templateId"],
        "sourceClass": identity["sourceClass"],
        "productionEligible": identity["productionEligible"],
        "bundle": {
            "file": BUNDLE_NAME,
            "sha256": _sha256(bundle),
            "bytes": bundle.stat().st_size,
        },
    }


def _write_receipt(path: Path, value: Mapping[str, Any]) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare_bundle(*, repository: Path, profile: Path, output_root: Path) -> dict[str, Any]:
    source = _absolute_existing(repository, kind="source repository")
    profile = _absolute_existing(profile, kind="source profile")
    if not source.is_dir() or not profile.is_file():
        raise RecoveryBundleError("source repository or profile has the wrong type")
    contract = load_source_contract(profile)
    _credential_free_repository(contract.repository)
    commit = _git(
        ["-C", str(source), "rev-parse", f"{contract.commit}^{{commit}}"],
        failure="source repository does not contain the required commit",
    )
    tree = _git(
        ["-C", str(source), "rev-parse", f"{contract.commit}^{{tree}}"],
        failure="source repository does not contain the required tree",
    )
    origin = _git(
        ["-C", str(source), "remote", "get-url", "origin"],
        failure="source repository origin is unavailable",
    )
    if commit != contract.commit or tree != contract.expected_tree or origin != contract.repository:
        raise RecoveryBundleError("source repository identity differs from the source contract")
    git_directory = Path(
        _git(
            ["-C", str(source), "rev-parse", "--absolute-git-dir"],
            failure="source repository object storage could not be inspected",
        )
    )
    alternates = git_directory / "objects/info/alternates"
    if alternates.exists() and alternates.read_text(encoding="utf-8").strip():
        raise RecoveryBundleError("source repository may not depend on alternate object storage")

    configured_output = output_root.expanduser()
    if not configured_output.is_absolute() or configured_output.exists() or configured_output.is_symlink():
        raise RecoveryBundleError("output root must be a new absolute path")
    parent = _absolute_existing(configured_output.parent, kind="output parent")
    output = parent / configured_output.name
    output.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix=".stateport-source-bundle-", dir=parent) as temporary:
            temporary_root = Path(temporary)
            bare = temporary_root / "source.git"
            staged_bundle = temporary_root / BUNDLE_NAME
            _git(["init", "--quiet", "--bare", str(bare)], failure="source bundle staging failed")
            _git(
                ["-C", str(bare), "fetch", "--quiet", "--no-tags", str(source), contract.commit],
                failure="source bundle staging could not fetch the required commit",
            )
            _git(
                ["-C", str(bare), "update-ref", CANDIDATE_REF, contract.commit],
                failure="source bundle staging could not bind the candidate ref",
            )
            _git(
                ["-C", str(bare), "bundle", "create", str(staged_bundle), CANDIDATE_REF],
                failure="source bundle creation failed",
            )
            os.chmod(staged_bundle, 0o600)
            identity = _inspect_bundle(staged_bundle, profile)
            destination = output / BUNDLE_NAME
            os.rename(staged_bundle, destination)
            os.chmod(destination, 0o600)
            receipt = _receipt(identity, destination)
            _write_receipt(output / RECEIPT_NAME, receipt)
        _fsync_directory(output)
        _fsync_directory(parent)
        return receipt
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def verify_bundle(*, profile: Path, bundle_root: Path) -> dict[str, Any]:
    profile = _absolute_existing(profile, kind="source profile")
    root = _absolute_existing(bundle_root, kind="bundle root")
    root_info = root.stat()
    if (
        not profile.is_file()
        or not root.is_dir()
        or root_info.st_uid != os.getuid()
        or stat.S_IMODE(root_info.st_mode) & 0o077
    ):
        raise RecoveryBundleError("bundle root must be an owner-private directory")
    bundle = root / BUNDLE_NAME
    receipt_path = root / RECEIPT_NAME
    bundle_info = _private_regular_file(bundle, label="source bundle")
    _private_regular_file(receipt_path, label="source bundle receipt")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveryBundleError("source bundle receipt is invalid") from exc
    required = {
        "formatVersion",
        "repository",
        "ref",
        "commit",
        "tree",
        "manifestDigest",
        "sourceDigest",
        "templateId",
        "sourceClass",
        "productionEligible",
        "bundle",
    }
    if not isinstance(receipt, dict) or set(receipt) != required or receipt.get("formatVersion") != FORMAT:
        raise RecoveryBundleError("source bundle receipt shape is invalid")
    artifact = receipt.get("bundle")
    if not isinstance(artifact, dict) or set(artifact) != {"file", "sha256", "bytes"}:
        raise RecoveryBundleError("source bundle artifact receipt is invalid")
    if (
        artifact.get("file") != BUNDLE_NAME
        or artifact.get("sha256") != _sha256(bundle)
        or artifact.get("bytes") != bundle_info.st_size
    ):
        raise RecoveryBundleError("source bundle bytes differ from the receipt")
    identity = _inspect_bundle(bundle, profile)
    expected = _receipt(identity, bundle)
    if receipt != expected:
        raise RecoveryBundleError("source bundle receipt identity differs from recovered content")
    return receipt


def _summary(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "succeeded",
        "formatVersion": value["formatVersion"],
        "commit": value["commit"],
        "tree": value["tree"],
        "manifestDigest": value["manifestDigest"],
        "sourceDigest": value["sourceDigest"],
        "bundleSha256": value["bundle"]["sha256"],
        "bundleBytes": value["bundle"]["bytes"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--repository", type=Path, required=True)
    prepare.add_argument("--profile", type=Path, required=True)
    prepare.add_argument("--output-root", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--profile", type=Path, required=True)
    verify.add_argument("--bundle-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            value = prepare_bundle(
                repository=args.repository,
                profile=args.profile,
                output_root=args.output_root,
            )
        else:
            value = verify_bundle(profile=args.profile, bundle_root=args.bundle_root)
    except (OSError, RecoveryBundleError, ValueError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(_summary(value), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
