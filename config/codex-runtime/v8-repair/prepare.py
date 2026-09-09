#!/usr/bin/env python3
"""Prepare new, verified native/consumer source trees without building anything."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile

from chromium_vendor import restore as restore_chromium_vendor

HERE = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular input: {path.name}")
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require_hash(path: Path, expected: str) -> None:
    if sha256(path) != expected:
        raise ValueError(f"input integrity mismatch: {path.name}")


def recipe() -> dict:
    value = json.loads((HERE / 'recipe.json').read_text())
    for name, key in [('source-submodules.json', 'sourceSubmodulesSha256'),
                      ('upstream-deps.json', 'upstreamDepsSha256'),
                      ('native-Cargo.lock', 'nativeCargoLockSha256')]:
        require_hash(HERE / name, value[key])
    for section in ('source', 'consumer'):
        require_hash(HERE / value[section]['patchFile'], value[section]['patchSha256'])
    icu = value['icuCorrections']
    require_hash(HERE / icu['patchFile'], icu['patchSha256'])
    require_hash(HERE / icu['licenseFile'], icu['licenseSha256'])
    for item in icu['files']:
        require_hash(HERE / item['upstreamPatchFile'], item['upstreamPatchSha256'])
    require_hash(HERE / 'licenses/sources.json', value['licenseNoticesSha256'])
    for item in json.loads((HERE / 'licenses/sources.json').read_text()):
        require_hash(HERE / 'licenses' / item['file'], item['sha256'])
    require_hash(HERE / 'chromium-vendor.json', value['chromiumVendorManifestSha256'])
    return value


def apply_patch(root: Path, patch: Path) -> None:
    subprocess.run(['patch', '--batch', '--fuzz=0', '--no-backup-if-mismatch',
                    '-p1', '-i', str(patch)], cwd=root, check=True)


def apply_icu_corrections(root: Path, value: dict) -> None:
    icu = value['icuCorrections']
    for item in icu['files']:
        require_hash(root / item['path'], item['beforeSha256'])
    apply_patch(root / 'third_party/icu', HERE / icu['patchFile'])
    for item in icu['files']:
        require_hash(root / item['path'], item['afterSha256'])
    # The registry crate omits this notice; retain the exact base-source license.
    destination = root / 'third_party/icu/LICENSE'
    if destination.exists() or destination.is_symlink():
        raise ValueError('ICU license was unexpectedly present')
    shutil.copyfile(HERE / icu['licenseFile'], destination)


def load_icu_data(inputs: Path, source: dict) -> bytes:
    item = source['missingIcuData']
    archive = inputs / item['archiveFile']
    require_hash(archive, item['archiveSha256'])
    with tarfile.open(archive, 'r:gz') as bundle:
        member = bundle.getmember(item['member'])
        if not member.isfile() or member.size != item['bytes']:
            raise ValueError('ICU data member has an unexpected type or size')
        with bundle.extractfile(member) as stream:
            data = stream.read(item['bytes'] + 1)
    if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('ICU data content integrity mismatch')
    git_blob = b'blob ' + str(len(data)).encode('ascii') + b'\0' + data
    if hashlib.sha1(git_blob).hexdigest() != item['gitBlobSha1']:
        raise ValueError('ICU data differs from the pinned upstream Git blob')
    return data


def restore_icu_data(root: Path, source: dict, data: bytes) -> None:
    destination = root / source['missingIcuData']['path']
    if destination.exists() or destination.is_symlink():
        raise ValueError('ICU data was unexpectedly present')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as stream:
        stream.write(data)
    require_hash(destination, source['missingIcuData']['sha256'])


def prepare_native(inputs: Path, output: Path, vendor_inputs: Path | None = None) -> dict:
    value = recipe()
    source = value['source']
    archive = inputs / source['crateFile']
    require_hash(archive, source['crateSha256'])
    for item in source['missingTestPreimages']:
        require_hash(inputs / item['file'], item['sha256'])
    icu_data = load_icu_data(inputs, source)
    output.mkdir(parents=False, exist_ok=False)
    prefix = 'v8-' + source['crateVersion']
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or path.parts[0] != prefix:
                raise ValueError('native source archive has an unexpected path')
        bundle.extractall(output, filter='data')
    root = output / prefix
    require_hash(root / 'Cargo.lock', value['nativeCargoLockSha256'])
    require_hash(root / 'v8/DEPS', source['depsSha256'])
    for item in source['missingTestPreimages']:
        destination = root / 'v8' / item['path']
        if destination.exists() or destination.is_symlink():
            raise ValueError('test preimage was unexpectedly present')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(inputs / item['file'], destination)
    apply_patch(root / 'v8', HERE / source['patchFile'])
    for item in source['expectedPatchedFiles']:
        require_hash(root / 'v8' / item['path'], item['sha256'])
    require_hash(root / 'v8/DEPS', source['depsSha256'])
    apply_icu_corrections(root, value)
    restore_icu_data(root, source, icu_data)
    chromium = restore_chromium_vendor(vendor_inputs if vendor_inputs is not None else inputs,
                                      root, json.loads((HERE / 'chromium-vendor.json').read_text()))
    result = {'status': 'source-prepared', 'nativeCompilation': 'not_run',
              'recipeSha256': sha256(HERE / 'recipe.json'),
              'crateSha256': source['crateSha256'],
              'fixedV8Commit': source['fixedV8Commit'],
              'fixedV8Version': source['fixedV8Version'],
              'sourceRoot': str(root.resolve()),
              'verifiedChangedFiles': len(source['expectedPatchedFiles']),
              'restoredUpstreamTestFiles': len(source['missingTestPreimages']),
              'restoredIcuDataSha256': source['missingIcuData']['sha256'],
              'restoredIcuDataGitBlob': source['missingIcuData']['gitBlobSha1'],
              'restoredChromiumVendorPackages': len(chromium['archives']),
              'chromiumVendorManifestSha256': value['chromiumVendorManifestSha256'],
              'nativeDepsUnchanged': False,
              'nativeDependencyPinsUnchanged': True,
              'verifiedIcuCorrectedFiles': len(value['icuCorrections']['files']),
              'icuSourcePatchSha256': value['icuCorrections']['patchSha256'],
              'icuRegressions': 'not_run; exact upstream regression patches retained in recipe',
              'qualification': 'not qualified; native build, API/ICU smoke, advisory accounting and reproducibility required'}
    (output / 'source-preparation.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def prepare_consumer(source_root: Path, output: Path) -> dict:
    value = recipe()
    source = value['consumer']
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError('consumer source must be an existing non-symlink directory')
    for item in source['files']:
        require_hash(source_root / item['path'], item['beforeSha256'])
    # Copy only to a new tree; retained r6/r7 sources and receipts are immutable.
    shutil.copytree(source_root, output, symlinks=True)
    apply_patch(output, HERE / source['patchFile'])
    for item in source['files']:
        require_hash(output / item['path'], item['afterSha256'])
    result = {'status': 'source-prepared', 'version': source['version'],
              'recipeSha256': sha256(HERE / 'recipe.json'),
              'sourceRoot': str(output.resolve()),
              'v8Crate': source['v8'], 'icuDataCrate': source['icuData'],
              'nativeCompilation': 'not_run', 'cargoLockedResolution': 'not_run',
              'qualification': 'requires the repaired native archive and its matching generated bindings; never reuse old V8 archive'}
    (output.parent / (output.name + '-consumer-preparation.json')).write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    native = commands.add_parser('native')
    native.add_argument('--inputs', type=Path, required=True)
    native.add_argument('--output', type=Path, required=True)
    native.add_argument('--vendor-inputs', type=Path)
    consumer = commands.add_parser('consumer')
    consumer.add_argument('--source', type=Path, required=True)
    consumer.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = (prepare_native(args.inputs, args.output, args.vendor_inputs) if args.command == 'native'
              else prepare_consumer(args.source, args.output))
    print(json.dumps(result, indent=2))
