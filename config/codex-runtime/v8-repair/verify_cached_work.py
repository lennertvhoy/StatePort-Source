#!/usr/bin/env python3
"""Verify a stopped native pilot work tree before allowing compilation to resume.

The cached work tree is untrusted build state.  This command reconstructs the
source and tool trees from the recipe's hash-checked inputs into a new staging
root, then compares the trees directly.  It never treats a digest made from the
cached tree as provenance and never inspects or reuses generated targets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Iterator

from fetch import verify_inputs
from pilot import HERE, unpack, vendor
from prepare import prepare_native, recipe, sha256


class VerificationError(ValueError):
    """The cached work tree cannot be used for continuation."""


def _regular_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"expected regular file: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _kind(path: Path) -> str:
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    return "other"


def _walk(root: Path) -> Iterator[Path]:
    yield root
    if not root.is_dir() or root.is_symlink():
        return
    for child in sorted(root.iterdir(), key=lambda value: value.name):
        yield from _walk(child)


def compare_tree(expected: Path, actual: Path, label: str, *, ignored: set[Path] | None = None) -> dict:
    """Compare a reconstructed tree without following links in either tree."""
    if not expected.exists() and not expected.is_symlink():
        raise VerificationError(f"missing reconstructed {label}: {expected}")
    if not actual.exists() and not actual.is_symlink():
        raise VerificationError(f"missing cached {label}: {actual}")
    ignored = ignored or set()
    expected_rows = {path.relative_to(expected): path for path in _walk(expected)
                     if path.relative_to(expected) not in ignored}
    actual_rows = {path.relative_to(actual): path for path in _walk(actual)
                   if path.relative_to(actual) not in ignored}
    if set(expected_rows) != set(actual_rows):
        missing = sorted(str(path) for path in set(expected_rows) - set(actual_rows))[:8]
        extra = sorted(str(path) for path in set(actual_rows) - set(expected_rows))[:8]
        raise VerificationError(f"{label} entries differ; missing={missing}, extra={extra}")
    files = directories = symlinks = 0
    for relative in sorted(expected_rows):
        source, candidate = expected_rows[relative], actual_rows[relative]
        source_kind, candidate_kind = _kind(source), _kind(candidate)
        if source_kind != candidate_kind:
            raise VerificationError(
                f"{label}/{relative}: type differs ({source_kind} != {candidate_kind})"
            )
        source_mode = stat.S_IMODE(source.lstat().st_mode)
        candidate_mode = stat.S_IMODE(candidate.lstat().st_mode)
        if source_mode != candidate_mode:
            raise VerificationError(
                f"{label}/{relative}: mode differs ({source_mode:o} != {candidate_mode:o})"
            )
        if source_kind == "symlink":
            symlinks += 1
            if os.readlink(source) != os.readlink(candidate):
                raise VerificationError(f"{label}/{relative}: link target differs")
        elif source_kind == "file":
            files += 1
            if source.stat().st_size != candidate.stat().st_size:
                raise VerificationError(f"{label}/{relative}: size differs")
            if _regular_digest(source) != _regular_digest(candidate):
                raise VerificationError(f"{label}/{relative}: content differs")
        elif source_kind == "directory":
            directories += 1
        else:
            raise VerificationError(f"{label}/{relative}: unsupported filesystem type")
    return {"files": files, "directories": directories, "symlinks": symlinks}


def _tool_rows(value: dict) -> dict[str, dict]:
    names = [row.get("name") for row in value["tools"]]
    if any(not isinstance(name, str) for name in names) or len(set(names)) != len(names):
        raise VerificationError("recipe tool rows have missing or duplicate names")
    rows = dict(zip(names, value["tools"]))
    required = {
        "third_party-llvm-build-Release-Asserts",
        "third_party-rust-toolchain",
        "host-glibc-sysroot",
        "gn",
        "ninja",
    }
    if not required.issubset(rows):
        raise VerificationError(f"recipe is missing tool rows: {sorted(required - set(rows))}")
    return rows


def _reconstruct(inputs: Path, vendor_inputs: Path, staging: Path) -> dict:
    value = recipe()
    rows = _tool_rows(value)
    native = staging / "native"
    prepared = prepare_native(inputs, native, vendor_inputs)
    tools = staging / "tools"
    tools.mkdir()
    for name, destination in [
        ("third_party-llvm-build-Release-Asserts", "clang"),
        ("third_party-rust-toolchain", "chromium-rust"),
        ("host-glibc-sysroot", "host-sysroot"),
        ("gn", "gn"),
        ("ninja", "ninja"),
    ]:
        unpack(inputs / rows[name]["file"], tools / destination)
    bindgen = tools / "bindgen"
    bindgen.mkdir()
    for row in value["tools"]:
        if row["file"].endswith(".deb"):
            # The source pilot uses dpkg-deb, whose extraction is deterministic.
            import subprocess

            subprocess.run(
                ["dpkg-deb", "-x", str(inputs / row["file"]), str(bindgen)],
                check=True,
            )
    for row in value["tools"]:
        if row["name"].startswith(("rustc-", "cargo-", "rust-std-")):
            # Match pilot.py: these unpacked component trees live below
            # /work/tools, and the installer prefix is /work/tools/rust.
            target = tools / ("unpacked-" + row["name"])
            unpack(inputs / row["file"], target)
            installers = list(target.glob("*/install.sh"))
            if len(installers) != 1:
                raise VerificationError(f"unexpected Rust component layout: {row['name']}")
            import subprocess

            subprocess.run(
                ["sh", str(installers[0]), "--prefix=" + str(tools / "rust"), "--disable-ldconfig"],
                check=True,
            )
    native_root = native / ("v8-" + value["source"]["crateVersion"])
    rust_native = native_root / "third_party/rust-toolchain"
    if rust_native.exists() or rust_native.is_symlink():
        raise VerificationError("reconstructed native Rust toolchain unexpectedly exists")
    os.replace(tools / "chromium-rust", rust_native)
    (rust_native / ".rusty_v8_version").write_text(rows["third_party-rust-toolchain"]["url"])
    host_sysroot = native_root / "build/linux/debian_bullseye_amd64-sysroot"
    if host_sysroot.exists() or host_sysroot.is_symlink():
        raise VerificationError("reconstructed host sysroot unexpectedly exists")
    os.replace(tools / "host-sysroot", host_sysroot)
    (host_sysroot / ".stamp").write_text(rows["host-glibc-sysroot"]["url"])
    cargo_vendor = staging / "vendor"
    vendor(inputs, cargo_vendor)
    return {
        "sourcePreparation": prepared,
        "native": native,
        "tools": tools,
        "vendor": cargo_vendor,
    }


def _normalise_mount(value: str) -> tuple[str, str, str] | None:
    match = re.fullmatch(r"type=bind,src=(.+),dst=(/[^,]+),(ro|rw)", value)
    return match.groups() if match else None


def _verify_outer_command(cached_run: Path, expected_image: str, inputs: Path,
                          vendor_inputs: Path, *, historical_runner: Path | None = None) -> dict:
    # These helpers exist on the coordinator, not in the original pinned builder.
    # Inner correspondence reconstruction must retain the original pilot API.
    from pilot import _read_resume_json, validate_resume_admission

    path = cached_run / "command.json"
    try:
        command_receipt = _read_resume_json(path)
        command = command_receipt["command"]
    except (OSError, KeyError, ValueError) as error:
        raise VerificationError(f"invalid outer command receipt: {path}") from error
    if (not isinstance(command, list) or len(command) < 5
            or any(not isinstance(item, str) for item in command)):
        raise VerificationError("outer command is not a usable argv list")
    # Match the complete booked_pilot argv, allowing only the reviewed roots,
    # image, timeout and run-specific cidfile to vary. Presence checks would
    # accept contradictory additions such as --privileged or --network=host.
    prefix = ['/usr/bin/podman', '--cgroup-manager=cgroupfs', 'run', '--pull=never']
    cgroup_arguments = ['--cgroups=split']
    if command[:5] == prefix + ['--cgroups=no-conmon']:
        parent = command_receipt.get('governorCgroup')
        if (not isinstance(parent, str) or not re.fullmatch(
                r'/user\.slice/user-(?P<uid>[0-9]+)\.slice/user@(?P=uid)\.service/'
                r'stateport\.slice/stateport-heavy\.slice/stateport-heavy-[0-9]+-[0-9]+\.service',
                parent)):
            raise VerificationError('current runner lacks an exact governor scope')
        try:
            proof = _read_resume_json(cached_run / 'work/containment-approved.json')
            observed = _read_resume_json(cached_run / 'containment.json')
            cid = observed.get('containerId')
            if (proof.get('status') != 'passed' or proof.get('bookedScope') != parent
                    or not isinstance(cid, str) or not re.fullmatch(r'[0-9a-f]{64}', cid)
                    or proof != observed):
                raise ValueError('containment identity differs')
            for name in ('init', 'conmon'):
                membership = proof['processes'][name]['cgroup']
                if (not isinstance(membership, str) or '..' in Path(membership).parts
                        or str(Path(membership)) != membership
                        or not (membership == parent or membership.startswith(parent + '/'))):
                    raise ValueError('process is outside the recorded governor scope')
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise VerificationError('current runner containment does not match its command') from error
        cgroup_arguments = ['--cgroups=no-conmon', '--cgroup-parent', parent]
    elif command[:5] != prefix + ['--cgroups=split']:
        raise VerificationError("outer command does not use the booked native runner")
    if '--network=none' not in command or '--network=host' in command or '--privileged' in command:
        raise VerificationError("outer command has unsafe network/privilege options")
    timeout = next((item for item in command if isinstance(item, str) and item.startswith("--timeout-seconds=")), None)
    if (timeout is None or not re.fullmatch(r"--timeout-seconds=[0-9]+", timeout)
            or not 1 <= int(timeout.split("=", 1)[1]) <= 21600):
        raise VerificationError("outer command has an invalid native timeout")
    fixed = {'--network=none', '--read-only', '--cap-drop=ALL',
             '--security-opt=no-new-privileges', '--pids-limit=256', '--cpus=1',
             '--memory=3g', '--memory-swap=3g',
             '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--require-containment'}
    if not fixed.issubset(command):
        raise VerificationError("outer command lost a required isolation option")
    # The destination/mode check alone is insufficient: a receipt could point
    # at a different (possibly mutable) directory that happens to have the
    # same reconstructed contents.  Require the exact roots supplied to this
    # invocation, and reject unparsed/duplicate mount options.
    mount_values: list[str] = []
    for index, item in enumerate(command):
        if item == "--mount":
            if index + 1 >= len(command) or not isinstance(command[index + 1], str):
                raise VerificationError("outer command has an incomplete mount option")
            mount_values.append(command[index + 1])
    resumed = '--resume-admission' in command
    expected_mount_count = 8 if resumed else 3
    if len(mount_values) != expected_mount_count:
        raise VerificationError(f"outer command must contain exactly {expected_mount_count} bind mounts")
    mounts = []
    for item in mount_values:
        parsed = _normalise_mount(item)
        if parsed is None:
            raise VerificationError("outer command has an unexpected mount option")
        mounts.append(parsed)
    expected = {
        "/inputs": (str(inputs.resolve()), "ro"),
        "/vendor-inputs": (str(vendor_inputs.resolve()), "ro"),
        "/work": (str((cached_run / "work").resolve()), "rw"),
    }
    if resumed:
        admission_path = cached_run / 'resume-admission.json'
        try:
            admission = _read_resume_json(admission_path)
            binding = admission.get('bindings')
            if not isinstance(binding, dict):
                raise VerificationError("resumed admission bindings are incomplete")
            cached_identity = binding.get('cachedRun')
            verifier_identity = binding.get('verifierSha256')
            if not isinstance(cached_identity, str) or not isinstance(verifier_identity, str):
                raise VerificationError("resumed admission identities are malformed")
            cached_source = Path(cached_identity)
            if not cached_source.is_absolute():
                raise VerificationError("resumed cache identity must be absolute")
            receipt_source = next(
                Path(source) for source, destination, mode in mounts
                if destination == '/correspondence-receipt.json'
            )
            if not receipt_source.is_absolute():
                raise VerificationError("resumed receipt identity must be absolute")
            # Revalidate the historical receipt against every admitted field.
            # Its verifier hash belongs to the earlier run; the current verifier
            # independently reconstructs source/tools before accepting any cache.
            validated = validate_resume_admission(
                receipt_source, cached_source, inputs.resolve(), vendor_inputs.resolve(),
                verifier_identity, sha256(HERE / 'recipe.json'), expected_image,
            )
            if (admission != validated
                    or command_receipt.get('resumeAdmission') != validated):
                raise VerificationError("resumed command and admission bindings differ")
            if (command_receipt.get('pilotSha256') != sha256(HERE / 'pilot.py')
                    or command_receipt.get('runnerSha256') != _regular_digest(
                        historical_runner if historical_runner is not None else HERE / 'booked_pilot.py')):
                raise VerificationError("resumed pilot or runner identity differs")
        except (OSError, KeyError, TypeError, ValueError, StopIteration) as error:
            raise VerificationError("resumed outer command lacks a valid bound admission receipt") from error
        expected.update({
            '/cached-run': (str(cached_source), 'ro'),
            '/correspondence-receipt.json': (str(receipt_source), 'ro'),
            '/resume-admission.json': (str(admission_path.resolve()), 'ro'),
            '/opt/stateport-v8-repair/pilot.py': (str((HERE / 'pilot.py').resolve()), 'ro'),
            '/opt/stateport-v8-repair/verify_cached_work.py': (str(Path(__file__).resolve()), 'ro'),
        })
    seen: set[str] = set()
    for source, destination, mode in mounts:
        if destination in seen:
            raise VerificationError(f"outer command duplicates mount destination: {destination}")
        seen.add(destination)
        if destination not in expected or (source, mode) != expected[destination]:
            raise VerificationError(f"outer command mount does not match reviewed root: {destination}")
    if seen != set(expected):
        raise VerificationError("outer command bind mounts are incomplete")
    expected_command = [
        *prefix, *cgroup_arguments, '--network=none', '--cidfile',
        str((cached_run / 'container-id').resolve()), '--read-only', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--pids-limit=256', '--cpus=1',
        '--memory=3g', '--memory-swap=3g', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
        '--mount', f'type=bind,src={inputs.resolve()},dst=/inputs,ro', '--mount',
        f'type=bind,src={vendor_inputs.resolve()},dst=/vendor-inputs,ro', '--mount',
        f'type=bind,src={(cached_run / "work").resolve()},dst=/work,rw']
    if resumed:
        expected_command += [
            '--mount', f'type=bind,src={expected["/cached-run"][0]},dst=/cached-run,ro',
            '--mount', f'type=bind,src={expected["/correspondence-receipt.json"][0]},dst=/correspondence-receipt.json,ro',
            '--mount', f'type=bind,src={expected["/resume-admission.json"][0]},dst=/resume-admission.json,ro',
            '--mount', f'type=bind,src={expected["/opt/stateport-v8-repair/pilot.py"][0]},dst=/opt/stateport-v8-repair/pilot.py,ro',
            '--mount', f'type=bind,src={expected["/opt/stateport-v8-repair/verify_cached_work.py"][0]},dst=/opt/stateport-v8-repair/verify_cached_work.py,ro',
        ]
    expected_command += [expected_image, timeout, '--require-containment']
    if resumed:
        expected_command += ['--resume-admission', '/resume-admission.json']
    if command != expected_command:
        raise VerificationError("outer command differs from exact booked_pilot native argv")
    return {"timeoutArgument": timeout, "mounts": sorted(seen)}


def _verify_receipts(cached_run: Path, expected_image: str, value: dict) -> dict:
    work = cached_run / "work"
    try:
        build = json.loads((work / "native-build-receipt.json").read_text())
        preparation = json.loads((work / "native/source-preparation.json").read_text())
        containment = json.loads((work / "containment-approved.json").read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError("cached work is missing a valid preparation/build/containment receipt") from error
    recipe_hash = sha256(HERE / "recipe.json")
    source = value["source"]
    if build.get("recipeSha256") != recipe_hash or preparation.get("recipeSha256") != recipe_hash:
        raise VerificationError("cached recipe identity differs from this verifier")
    if build.get("fixedV8Commit") != source["fixedV8Commit"] or build.get("fixedV8Version") != source["fixedV8Version"]:
        raise VerificationError("cached V8 identity differs from this verifier")
    if preparation.get("chromiumVendorManifestSha256") != value["chromiumVendorManifestSha256"]:
        raise VerificationError("cached Chromium vendor manifest identity differs")
    if preparation.get("restoredIcuDataSha256") != source["missingIcuData"]["sha256"]:
        raise VerificationError("cached ICU data identity differs")
    if build.get("status") != "failed" or build.get("error") != "bounded native pilot timed out":
        raise VerificationError("cached work is not the explicitly resumable timeout state")
    if build.get("nativeTests") != "not_run" or build.get("releaseQualification") != "not_run":
        raise VerificationError("cached work already claims qualification")
    expected_command = ["/work/tools/rust/bin/cargo", "build", "--offline", "--locked", "--release", "--target", value["pilot"]["target"], "--lib"]
    if build.get("command") != expected_command:
        raise VerificationError("cached Cargo command differs from this recipe")
    if containment.get("status") != "passed":
        raise VerificationError("cached work lacks a passed containment admission")
    return {"recipeSha256": recipe_hash, "builderImage": expected_image, "cachedBuildStatus": build["status"]}


def verify(cached_run: Path, inputs: Path, vendor_inputs: Path, image_id_file: Path, staging: Path, *, historical_runner: Path | None = None) -> dict:
    # Host-only governor integration; the inner image startup must depend only
    # on the recipe/pilot modules available in the pinned image.
    from booked_pilot import observed_native, governor_cgroup_parent
    value = recipe()
    if not cached_run.is_dir() or not inputs.is_dir() or not vendor_inputs.is_dir():
        raise VerificationError("cached run, inputs, and vendor inputs must be directories")
    image = image_id_file.read_text().strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise VerificationError("builder image identity is not an exact SHA-256")
    verify_inputs(inputs)
    outer = _verify_outer_command(cached_run, image, inputs, vendor_inputs, historical_runner=historical_runner)
    receipt = _verify_receipts(cached_run, image, value)
    staging.mkdir(parents=False, exist_ok=False)
    # Archive installers (and dpkg) are executable only in the pinned builder
    # image.  Never perform that correspondence reconstruction on the host.
    parent = governor_cgroup_parent()
    command = ["/usr/bin/podman", "--cgroup-manager=cgroupfs", "run", "--pull=never",
               "--cgroups=no-conmon", "--cgroup-parent", parent,
               "--network=none", "--cidfile", str(staging / "container-id"),
               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--pids-limit=256", "--cpus=1", "--memory=3g", "--memory-swap=3g",
               "--tmpfs=/tmp:rw,nosuid,nodev,size=64m",
               "--mount", f"type=bind,src={inputs},dst=/inputs,ro",
               "--mount", f"type=bind,src={vendor_inputs},dst=/vendor-inputs,ro",
               "--mount", f"type=bind,src={cached_run / 'work'},dst=/cached/work,ro",
               "--mount", f"type=bind,src={Path(__file__).resolve()},dst=/opt/stateport-v8-repair/verify_cached_work.py,ro",
               "--mount", f"type=bind,src={staging / 'work'},dst=/work,rw", "--entrypoint", "/usr/bin/python3", image,
               "/opt/stateport-v8-repair/verify_cached_work.py",
               "--inside", "--cached", "/cached/work", "--expected-recipe-sha", receipt["recipeSha256"]]
    (staging / 'work').mkdir()
    (staging / 'command.json').write_text(json.dumps({
        'command': command, 'verifierSha256': sha256(Path(__file__).resolve()),
        'recipeSha256': receipt['recipeSha256'], 'governorCgroup': parent}, indent=2) + '\n')
    with (staging / "run.log").open("xb") as log:
        code = observed_native(command, staging, parent, log)
    if code != 0:
        raise VerificationError("pinned-builder correspondence failed; see retained run.log")
    try:
        compared = json.loads((staging / "work/correspondence-result.json").read_text())
    except json.JSONDecodeError as error:
        raise VerificationError("pinned-builder correspondence returned invalid JSON") from error
    if compared.get("status") != "cached-work-verified":
        raise VerificationError("pinned-builder correspondence did not verify cached work")
    return {
        "status": "cached-work-verified",
        "recipeSha256": receipt["recipeSha256"],
        "builderImage": image,
        "cachedRun": str(cached_run),
        "inputs": str(inputs),
        "vendorInputs": str(vendor_inputs),
        "verifierSha256": sha256(Path(__file__).resolve()),
        "outerCommand": outer,
        "historicalRunner": ({"path": str(historical_runner.absolute()),
                              "sha256": _regular_digest(historical_runner)}
                             if historical_runner is not None else None),
        "trees": compared["trees"],
        "generatedState": "excluded; target, cargo, home, tmp, artifacts are not provenance inputs",
        "qualification": "not_run; final reproducibility and release scan remain required",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cached-run", type=Path)
    parser.add_argument("--historical-runner", type=Path,
                        help="reviewed historical runner source; hash checked, never executed")
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--vendor-inputs", type=Path)
    parser.add_argument("--image-id-file", type=Path)
    parser.add_argument("--staging", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--cached", type=Path)
    parser.add_argument("--expected-recipe-sha")
    args = parser.parse_args()
    try:
        if args.inside:
            if args.cached is None:
                raise VerificationError("--inside requires --cached")
            value = recipe()
            if args.expected_recipe_sha and sha256(HERE / 'recipe.json') != args.expected_recipe_sha:
                raise VerificationError('image recipe differs from reviewed recipe')
            gate = Path('/work/containment-approved.json')
            import time
            deadline = time.monotonic() + 30
            while not gate.is_file() and time.monotonic() < deadline:
                time.sleep(0.1)
            if not gate.is_file() or json.loads(gate.read_text()).get('status') != 'passed':
                raise VerificationError('correspondence lacked measured containment admission')
            _reconstruct(Path('/inputs'), Path('/vendor-inputs'), Path('/work'))
            work = args.cached
            result = {"status": "cached-work-verified", "trees": {
                "native": compare_tree(Path('/work/native'), work / 'native', 'native', ignored={Path('source-preparation.json')}),
                "tools": compare_tree(Path('/work/tools'), work / 'tools', 'tools'),
                "vendor": compare_tree(Path('/work/vendor'), work / 'vendor', 'vendor'),
            }, "generatedState": "excluded; target, cargo, home, tmp, artifacts are not provenance inputs"}
            expected_config = ('[source.crates-io]\nreplace-with = "vendored-sources"\n'
                               '[source.vendored-sources]\n'
                               'directory = "/work/vendor"\n')
            config = work / 'cargo/config.toml'
            if config.is_symlink() or not config.is_file() or config.read_text() != expected_config:
                raise VerificationError("cached Cargo source configuration differs from pilot")
            result["influentialConfig"] = {"cargoConfig": "exact pilot config verified"}
            with (Path('/work') / 'correspondence-result.json').open('x') as output:
                output.write(json.dumps(result) + '\n')
            return 0
        if not all((args.cached_run, args.inputs, args.vendor_inputs, args.image_id_file, args.staging)):
            raise VerificationError("host verification requires cached-run, inputs, vendor-inputs, image-id-file and staging")
        result = verify(args.cached_run.resolve(), args.inputs.resolve(strict=True), args.vendor_inputs.resolve(strict=True), args.image_id_file.resolve(strict=True), args.staging.resolve(), historical_runner=args.historical_runner)
    except (OSError, VerificationError, ValueError, RuntimeError) as error:
        print(json.dumps({"status": "cached-work-refused", "error": str(error)}, indent=2))
        return 1
    encoded = json.dumps(result, indent=2) + "\n"
    if args.receipt is not None:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        with args.receipt.open('x') as output:
            output.write(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
