#!/usr/bin/env python3
"""Offline native pilot inside the dedicated image; coordinator books resources."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import tomllib
import zipfile

from fetch import verify_inputs
from prepare import HERE, prepare_native, recipe, sha256


def _read_resume_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 524288:
        raise ValueError('correspondence must be a bounded regular JSON file')
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise ValueError('invalid correspondence JSON') from error
    if not isinstance(value, dict):
        raise ValueError('correspondence JSON must be an object')
    return value


def _resume_bindings(cached_run: Path, inputs: Path, vendor_inputs: Path,
                     verifier_sha: str, recipe_sha: str, image: str) -> dict:
    if (not re.fullmatch(r'[0-9a-f]{64}', verifier_sha)
            or not re.fullmatch(r'[0-9a-f]{64}', recipe_sha)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', image)):
        raise ValueError('correspondence identity must use exact SHA-256 values')
    return {'status': 'cached-work-verified', 'cachedRun': str(cached_run),
            'inputs': str(inputs), 'vendorInputs': str(vendor_inputs),
            'verifierSha256': verifier_sha, 'recipeSha256': recipe_sha,
            'builderImage': image}


def validate_resume_admission(receipt_path: Path, cached_run: Path, inputs: Path,
                              vendor_inputs: Path, verifier_sha: str,
                              recipe_sha: str, image: str) -> dict:
    """Bind the actual external correspondence receipt before mounting a cache.

    This is a local build admission, not signed release or binary provenance.
    The container repeats full source/tool comparison before importing targets.
    """
    for path in (cached_run, cached_run / 'work', inputs, vendor_inputs):
        if not path.is_dir() or path.absolute() != path.resolve():
            raise ValueError('cached/input path must be a real canonical directory without symlinks')
    expected = _resume_bindings(cached_run, inputs, vendor_inputs, verifier_sha, recipe_sha, image)
    receipt = _read_resume_json(receipt_path)
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError('correspondence identity or path differs from the admitted build')
    return {'schemaVersion': 1, 'receiptSha256': sha256(receipt_path), 'bindings': expected}


def validate_inner_resume(admission_path: Path, receipt_path: Path) -> dict:
    admission = _read_resume_json(admission_path)
    if set(admission) != {'schemaVersion', 'receiptSha256', 'bindings'} or admission['schemaVersion'] != 1:
        raise ValueError('unsupported correspondence admission schema')
    if admission['receiptSha256'] != sha256(receipt_path):
        raise ValueError('correspondence receipt changed since outer admission')
    binding = admission['bindings']
    if not isinstance(binding, dict):
        raise ValueError('correspondence bindings are missing')
    for key in ('cachedRun', 'inputs', 'vendorInputs'):
        value = binding.get(key)
        if not isinstance(value, str) or not value.startswith('/') or '..' in Path(value).parts:
            raise ValueError('correspondence host identity path is malformed')
    expected = _resume_bindings(Path(binding['cachedRun']), Path(binding['inputs']),
        Path(binding['vendorInputs']), sha256(HERE / 'verify_cached_work.py'),
        sha256(HERE / 'recipe.json'), binding.get('builderImage', ''))
    if binding != expected:
        raise ValueError('correspondence recipe/verifier identity changed')
    receipt = _read_resume_json(receipt_path)
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError('correspondence receipt bindings changed')
    return admission


def _target_inventory(root: Path) -> dict:
    """Identify unqualified target bytes, refusing every link and special file."""
    rows = []
    total_bytes = 0
    def visit(path: Path) -> None:
        nonlocal total_bytes
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            rows.append([relative, 'directory', stat.S_IMODE(info.st_mode)])
            for child in sorted(path.iterdir()):
                visit(child)
        elif stat.S_ISREG(info.st_mode):
            rows.append([relative, 'file', stat.S_IMODE(info.st_mode), info.st_size,
                         info.st_mtime_ns, sha256(path)])
            total_bytes += info.st_size
        else:
            raise ValueError('target cache contains a symlink or special file: ' + relative)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('target cache must be a real directory')
    visit(root)
    return {'sha256': hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest(),
            'files': sum(row[1] == 'file' for row in rows), 'bytes': total_bytes,
            'qualification': 'unqualified generated cache identity only'}


def import_target_cache(source: Path, destination: Path) -> dict:
    before = _target_inventory(source)
    # Keep symlinks as links should the read-only input change underneath us;
    # the second inventory refuses them before any build is started.
    shutil.copytree(source, destination, symlinks=True)
    if _target_inventory(destination) != before:
        raise ValueError('target cache changed while copying')
    return before


def compare_and_preserve_cache_times(fresh: Path, cached: Path, label: str,
                                      ignored: set[Path] | None = None) -> dict:
    from verify_cached_work import compare_tree
    proof = compare_tree(fresh, cached, label, ignored=ignored)
    # Only after complete byte/type/mode/link equality: retain cache timestamps
    # so rewritten-but-identical source does not invalidate all Ninja outputs.
    # These timestamps are cache metadata, never original-input provenance.
    def preserve(path: Path) -> None:
        relative = path.relative_to(fresh)
        if relative in (ignored or set()):
            return
        old = (cached / relative).lstat()
        if path.is_dir() and not path.is_symlink():
            for child in path.iterdir():
                preserve(child)
        os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns), follow_symlinks=False)
    preserve(fresh)
    return {**proof, 'timestamps': 'retained cache metadata after complete correspondence'}


def unpack(archive: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                target = output / item.filename
                if not target.resolve().is_relative_to(output.resolve()):
                    raise ValueError('tool archive escapes its output')
            bundle.extractall(output)
            for item in bundle.infolist():
                if not item.is_dir() and item.external_attr >> 16 & 0o111:
                    (output / item.filename).chmod(0o755)
    else:
        with tarfile.open(archive) as bundle:
            bundle.extractall(output, filter='data')


def vendor(inputs: Path, output: Path) -> None:
    output.mkdir()
    for package in tomllib.loads((HERE / 'native-Cargo.lock').read_text())['package']:
        if 'source' not in package:
            continue
        name = f"{package['name']}-{package['version']}"
        # These archives were verified against the exact Cargo lock before extraction.
        with tarfile.open(inputs / (name + '.crate')) as bundle:
            if any(not (member.name.startswith(name + '/') or (member.name == name and member.isdir()))
                   for member in bundle.getmembers()):
                raise ValueError('crate archive root differs from its package identity')
            bundle.extractall(output, filter='data')
        root = output / name
        files = {path.relative_to(root).as_posix(): sha256(path)
                 for path in sorted(root.rglob('*')) if path.is_file()}
        (root / '.cargo-checksum.json').write_text(json.dumps({'files': files, 'package': package['checksum']}, sort_keys=True))


def run(inputs: Path, timeout_seconds: int, require_containment: bool = False,
        vendor_inputs: Path = Path('/vendor-inputs'), resume_admission: Path | None = None) -> dict:
    if HERE != Path('/opt/stateport-v8-repair'):
        raise ValueError('native pilot must run inside its dedicated recipe image')
    work = Path('/work')
    gate = work / 'containment-approved.json'
    if require_containment:
        deadline = time.monotonic() + 30
        while not gate.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        if not gate.is_file() or json.loads(gate.read_text()).get('status') != 'passed':
            raise ValueError('actual process containment was not approved')
    if not work.is_dir() or any(not require_containment or path != gate for path in work.iterdir()):
        raise ValueError('native pilot requires a new empty /work directory')
    value = recipe()
    verified = verify_inputs(inputs)
    started = time.monotonic()
    result = {'status': 'preparing', 'recipeSha256': sha256(HERE / 'recipe.json'),
              'fixedV8Commit': value['source']['fixedV8Commit'],
              'fixedV8Version': value['source']['fixedV8Version'],
              'inputFiles': verified, 'nativeTests': 'not_run',
              'codexCompilation': 'not_run', 'releaseQualification': 'not_run',
              'timeoutSeconds': timeout_seconds, 'memoryPeak': 'coordinator governor receipt required'}
    try:
        if resume_admission is not None:
            result['resumeAdmission'] = validate_inner_resume(
                resume_admission, Path('/correspondence-receipt.json'))
        prepared = prepare_native(inputs, work / 'native', vendor_inputs)
        native = Path(prepared['sourceRoot'])
        tools = work / 'tools'
        tools.mkdir()
        tool_rows = {row['name']: row for row in value['tools']}
        for name, destination in [('third_party-llvm-build-Release-Asserts', 'clang'),
                                  ('third_party-rust-toolchain', 'chromium-rust'),
                                  ('host-glibc-sysroot', 'host-sysroot'), ('gn', 'gn'), ('ninja', 'ninja')]:
            unpack(inputs / tool_rows[name]['file'], tools / destination)
        bindgen = tools / 'bindgen'
        bindgen.mkdir()
        for row in value['tools']:
            if row['file'].endswith('.deb'):
                subprocess.run(['dpkg-deb', '-x', str(inputs / row['file']), str(bindgen)], check=True)
        for row in value['tools']:
            if row['name'].startswith(('rustc-', 'cargo-', 'rust-std-')):
                target = tools / ('unpacked-' + row['name'])
                unpack(inputs / row['file'], target)
                installers = list(target.glob('*/install.sh'))
                if len(installers) != 1:
                    raise ValueError('Rust component has an unexpected layout')
                subprocess.run(['sh', str(installers[0]), '--prefix=' + str(tools / 'rust'), '--disable-ldconfig'], check=True)
        rust_native = native / 'third_party/rust-toolchain'
        if rust_native.exists():
            raise ValueError('native Rust toolchain was unexpectedly present')
        shutil.move(str(tools / 'chromium-rust'), rust_native)
        (rust_native / '.rusty_v8_version').write_text(tool_rows['third_party-rust-toolchain']['url'])
        host_sysroot = native / 'build/linux/debian_bullseye_amd64-sysroot'
        if host_sysroot.exists():
            raise ValueError('host sysroot was unexpectedly present')
        shutil.move(str(tools / 'host-sysroot'), host_sysroot)
        (host_sysroot / '.stamp').write_text(tool_rows['host-glibc-sysroot']['url'])
        vendor(inputs, work / 'vendor')
        if resume_admission is not None:
            result['resumeCorrespondence'] = {
                name: compare_and_preserve_cache_times(work / name, Path('/cached-run/work') / name,
                    name, ignored={Path('source-preparation.json')} if name == 'native' else set())
                for name in ('native', 'tools', 'vendor')}
            result['targetCache'] = import_target_cache(Path('/cached-run/work/target'), work / 'target')
        for name in ('cargo', 'home', 'tmp', 'artifacts'):
            (work / name).mkdir()
        (work / 'cargo/config.toml').write_text('[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "/work/vendor"\n')
        environment = {
            'PATH': '/work/tools/rust/bin:/usr/bin:/bin', 'HOME': '/work/home',
            'LANG': 'C.UTF-8', 'TMPDIR': '/work/tmp', 'CARGO_HOME': '/work/cargo',
            'CARGO_TARGET_DIR': '/work/target', 'CARGO_BUILD_JOBS': '1',
            'V8_FROM_SOURCE': 'true', 'RUSTY_V8_SKIP_DOWNLOAD': 'true',
            'CLANG_BASE_PATH': '/work/tools/clang',
            'LIBCLANG_PATH': '/work/tools/bindgen/usr/lib/llvm-21/lib',
            'LD_LIBRARY_PATH': '/work/tools/bindgen/usr/lib/x86_64-linux-gnu',
            'RUSTY_V8_BINDGEN_RESOURCE_DIR': '/work/tools/bindgen/usr/lib/llvm-21/lib/clang/21',
            'RUSTY_V8_MUSL_SYSROOT': '/opt/stateport-musl-sysroot',
            'GN': '/work/tools/gn/gn', 'NINJA': '/work/tools/ninja/ninja',
            'SOURCE_DATE_EPOCH': str(value['pilot']['sourceDateEpoch']),
        }
        command = ['/work/tools/rust/bin/cargo', 'build', '--offline', '--locked',
                   '--release', '--target', value['pilot']['target'], '--lib']
        result.update(status='building', command=command, environment=environment)
        with (work / 'build.log').open('xb') as log:
            process = subprocess.Popen(command, cwd=native, env=environment,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=max(1, timeout_seconds - (time.monotonic() - started)))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise RuntimeError('bounded native pilot timed out') from None
        result['exitCode'] = code
        if code != 0:
            raise RuntimeError(f'native Cargo build failed with exit {code}; see build.log')
        gn = work / 'target' / value['pilot']['target'] / 'release/gn_out'
        library = gn / 'obj/librusty_v8.a'
        bindings = gn / 'src_binding.rs'
        artifacts = work / 'artifacts'
        compressed = artifacts / 'librusty_v8_release_x86_64-unknown-linux-musl.a.gz'
        with library.open('rb') as source, compressed.open('xb') as destination:
            with gzip.GzipFile(filename='', mode='wb', fileobj=destination, mtime=0) as compressor:
                shutil.copyfileobj(source, compressor)
        shutil.copyfile(bindings, artifacts / 'src_binding_release_x86_64-unknown-linux-musl.rs')
        shutil.copyfile(gn / 'args.gn', artifacts / 'args.gn')
        shutil.copyfile(native / 'Cargo.lock', artifacts / 'native-Cargo.lock')
        shutil.copyfile(work / 'native/source-preparation.json', artifacts / 'source-preparation.json')
        result.update(status='native-compiled-unqualified', artifacts=[
            {'file': path.name, 'bytes': path.stat().st_size, 'sha256': sha256(path)}
            for path in sorted(artifacts.iterdir())])
    except Exception as error:
        result.update(status='failed', error=str(error))
    result['elapsedSeconds'] = round(time.monotonic() - started, 3)
    (work / 'native-build-receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, default=Path('/inputs'))
    parser.add_argument('--vendor-inputs', type=Path, default=Path('/vendor-inputs'))
    parser.add_argument('--timeout-seconds', type=int, required=True)
    parser.add_argument('--require-containment', action='store_true')
    parser.add_argument('--resume-admission', type=Path)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 21600:
        parser.error('pilot timeout must be between 1 and 21600 seconds')
    result = run(args.inputs, args.timeout_seconds, args.require_containment, args.vendor_inputs, args.resume_admission)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'native-compiled-unqualified' else 1)
