#!/usr/bin/env python3
"""Copy an exact new Codex .3 tree and stage two checksum-bound native backports."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tomllib

HERE = Path(__file__).resolve().parent


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError('expected regular file: ' + str(path))
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(path: Path, expected: str) -> None:
    if digest(path) != expected:
        raise ValueError('source integrity differs: ' + str(path))


def prepare(source: Path, inputs: Path, output: Path) -> dict:
    pins = json.loads((HERE / 'pins.json').read_text())
    if source.is_symlink() or not source.is_dir() or output.resolve().is_relative_to(source.resolve()):
        raise ValueError('source and new output must be separate directories')
    for path, expected in pins['consumerInputs'].items():
        require(source / path, expected)
    for row in pins['packages']:
        require(inputs / row['crateFile'], row['crateSha256'])
        require(HERE / row['patchFile'], row['patchSha256'])
    for row in pins['regressionInputs']:
        require(HERE / row['file'], row['sha256'])
    shutil.copytree(source, output, symlinks=True)
    workspace = output / 'codex-rs'
    overrides = workspace / 'stateport-native-overrides'
    overrides.mkdir(exist_ok=False)
    receipts = []
    for row in pins['packages']:
        prefix = row['name'] + '-' + row['version']
        with tarfile.open(inputs / row['crateFile']) as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or path.parts[0] != prefix:
                    raise ValueError('crate archive root differs')
            archive.extractall(overrides, filter='data')
        root = overrides / prefix
        require(root / row['sourcePath'], row['beforeSha256'])
        subprocess.run(['patch', '--batch', '--fuzz=0', '--no-backup-if-mismatch',
                        '-p1', '-i', str(HERE / row['patchFile'])],
                       cwd=root / row['patchWorkingDirectory'], check=True)
        require(root / row['sourcePath'], row['afterSha256'])
        receipts.append({'name': row['name'], 'path': str(root.relative_to(workspace)),
                         'crateSha256': row['crateSha256'], 'patchedSourceSha256': row['afterSha256']})
    manifest = workspace / 'Cargo.toml'
    text = manifest.read_text()
    if text.count('[patch.crates-io]') != 1:
        raise ValueError('expected one existing Cargo patch table')
    additions = ''.join(f'{r["name"]} = {{ path = "{r["path"]}" }}\n' for r in receipts)
    manifest.write_text(text.replace('[patch.crates-io]\n', '[patch.crates-io]\n' + additions, 1))
    lock = workspace / 'Cargo.lock'
    text = lock.read_text()
    old_packages = tomllib.loads(text)['package']
    for row in pins['packages']:
        pattern = r'(\[\[package\]\]\nname = "' + re.escape(row['name']) + r'"\nversion = "' + re.escape(row['version']) + r'"\n)source = "registry\+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + row['crateSha256'] + r'"\n'
        text, count = re.subn(pattern, r'\1', text)
        if count != 1:
            raise ValueError('expected exact locked registry package')
    new_packages = tomllib.loads(text)['package']
    assert len(new_packages) == len(old_packages)
    changed = [a['name'] for a, b in zip(old_packages, new_packages, strict=True) if a != b]
    if sorted(changed) != sorted(row['name'] for row in pins['packages']):
        raise ValueError('unexpected changed Cargo lock nodes')
    lock.write_text(text)
    result = {'status': 'source-prepared', 'pinsSha256': digest(HERE / 'pins.json'),
              'consumerVersion': '0.146.0+stateport.3', 'packages': receipts,
              'changedCargoLockNodes': changed,
              'manifestSha256': digest(manifest), 'lockSha256': digest(lock),
              'lockedResolution': 'not_run', 'nativeRegressionTests': 'not_run',
              'nativeCompilation': 'not_run', 'finalLinkCorrespondence': 'not_run',
              'releaseQualification': 'not_run'}
    (overrides / 'backport-preparation.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.inputs, args.output), indent=2))
