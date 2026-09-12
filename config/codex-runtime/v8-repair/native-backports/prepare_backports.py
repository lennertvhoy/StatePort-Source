#!/usr/bin/env python3
"""Copy an exact new Codex .3 tree and stage checksum-bound dependency patches."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tomllib
import zipfile

HERE = Path(__file__).resolve().parent


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError('expected regular file: ' + str(path))
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(path: Path, expected: str) -> None:
    if digest(path) != expected:
        raise ValueError('source integrity differs: ' + str(path))


def _digest_bytes(data: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def _maintained_sqlite(archive_path: Path) -> tuple[dict, dict[str, bytes]]:
    """Authenticate the one pinned SQLite amalgamation without extracting it."""
    manifest_path = HERE / 'maintained-sqlite.json'
    manifest = json.loads(manifest_path.read_text())
    archive = manifest['archive']
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ValueError('maintained SQLite archive must be a regular file')
    if archive_path.stat().st_size != archive['bytes'] or digest(archive_path) != archive['sha256']:
        raise ValueError('maintained SQLite archive integrity differs')
    root = archive['root']
    expected = {f'{root}/{name}': row for name, row in manifest['members'].items()}
    permitted = {f'{root}/', *expected, f'{root}/shell.c'}
    members: dict[str, zipfile.ZipInfo] = {}
    try:
        with zipfile.ZipFile(archive_path) as stream:
            for member in stream.infolist():
                path = PurePosixPath(member.filename)
                mode_type = stat.S_IFMT(member.external_attr >> 16)
                if (path.is_absolute() or '..' in path.parts or not member.filename
                        or member.filename not in permitted or member.filename in members
                        or member.flag_bits & 0x1 or stat.S_ISLNK(member.external_attr >> 16)
                        or (member.is_dir() and mode_type not in (0, stat.S_IFDIR))
                        or (not member.is_dir() and mode_type not in (0, stat.S_IFREG))):
                    raise ValueError('maintained SQLite archive contains unsafe member')
                if member.is_dir() != member.filename.endswith('/'):
                    raise ValueError('maintained SQLite archive has malformed member')
                members[member.filename] = member
            if set(members) != permitted:
                raise ValueError('maintained SQLite archive member set differs')
            selected = {}
            for name, row in expected.items():
                member = members[name]
                if member.is_dir() or member.file_size != row['bytes']:
                    raise ValueError('maintained SQLite member size differs: ' + name)
                data = stream.read(member)
                if (len(data) != row['bytes'] or _digest_bytes(data, 'sha256') != row['sha256']
                        or _digest_bytes(data, 'sha3_256') != row['sha3_256']):
                    raise ValueError('maintained SQLite member integrity differs: ' + name)
                selected[PurePosixPath(name).name] = data
    except zipfile.BadZipFile as exc:
        raise ValueError('maintained SQLite archive is not a safe ZIP') from exc
    source_id = ('#define SQLITE_SOURCE_ID      "' + manifest['sourceId'] + '"').encode()
    if source_id not in selected['sqlite3.c'] or source_id not in selected['sqlite3.h']:
        raise ValueError('maintained SQLite source identity differs')
    return manifest, selected


def prepare(source: Path, inputs: Path, output: Path,
            maintained_sqlite_archive: Path | None = None) -> dict:
    pins = json.loads((HERE / 'pins.json').read_text())
    if source.is_symlink() or not source.is_dir() or output.resolve().is_relative_to(source.resolve()):
        raise ValueError('source and new output must be separate directories')
    maintained = (_maintained_sqlite(maintained_sqlite_archive)
                  if maintained_sqlite_archive is not None else None)
    for path, expected in pins['consumerInputs'].items():
        require(source / path, expected)
    for row in pins['packages']:
        require(inputs / row['crateFile'], row['crateSha256'])
        if not (maintained is not None and row['name'] == 'libsqlite3-sys'):
            require(HERE / row['patchFile'], row['patchSha256'])
    for row in pins['regressionInputs']:
        if maintained is not None and row['file'] == 'sqlite-upstream-regression.test':
            continue
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
        sources = [row, *row.get('additionalSources', [])]
        if maintained is not None and row['name'] == 'libsqlite3-sys':
            sqlite_manifest, sqlite_members = maintained
            sqlite_root = root / 'sqlite3'
            for name, data in sqlite_members.items():
                destination = sqlite_root / name
                if destination.is_symlink() or not destination.is_file():
                    raise ValueError('bundled SQLite destination is unsafe: ' + str(destination))
                destination.write_bytes(data)
                if digest(destination) != sqlite_manifest['members'][name]['sha256']:
                    raise ValueError('maintained SQLite copy integrity differs: ' + name)
            receipts.append({'name': row['name'], 'path': str(root.relative_to(workspace)),
                             'crateSha256': row['crateSha256'],
                             'maintainedSqlite': {'version': sqlite_manifest['version'],
                                                 'sourceId': sqlite_manifest['sourceId'],
                                                 'members': sqlite_manifest['members']}})
        else:
            for source_row in sources:
                require(root / source_row['sourcePath'], source_row['beforeSha256'])
            subprocess.run(['patch', '--batch', '--fuzz=0', '--no-backup-if-mismatch',
                            '-p1', '-i', str(HERE / row['patchFile'])],
                           cwd=root / row['patchWorkingDirectory'], check=True)
            for source_row in sources:
                require(root / source_row['sourcePath'], source_row['afterSha256'])
            receipts.append({'name': row['name'], 'path': str(root.relative_to(workspace)),
                             'crateSha256': row['crateSha256'], 'patchedSourceSha256': row['afterSha256'],
                             'patchedSources': {s['sourcePath']: s['afterSha256'] for s in sources}})
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
    result = {'status': ('source-prepared-maintained-sqlite-3.53.4'
                         if maintained is not None else 'source-prepared'),
              'pinsSha256': digest(HERE / 'pins.json'),
              'consumerVersion': '0.146.0+stateport.3', 'packages': receipts,
              'changedCargoLockNodes': changed,
              'manifestSha256': digest(manifest), 'lockSha256': digest(lock),
              'lockedResolution': 'not_run', 'nativeRegressionTests': 'not_run',
              'nativeCompilation': 'not_run', 'finalLinkCorrespondence': 'not_run',
              'releaseQualification': 'not_run'}
    if maintained is not None:
        sqlite_manifest, _ = maintained
        result['maintainedSqlite'] = {
            'version': sqlite_manifest['version'], 'apiVersionNumber': sqlite_manifest['apiVersionNumber'],
            'sourceId': sqlite_manifest['sourceId'],
            'archive': sqlite_manifest['archive'], 'members': sqlite_manifest['members'],
            'bindingConstants': sqlite_manifest['bindingConstants'],
            'standardUpstreamSuites': 'not_run', 'nativeCompilation': 'not_run',
            'releaseQualification': 'not_run'}
    (overrides / 'backport-preparation.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--maintained-sqlite-archive', type=Path,
                        help='optional verified SQLite 3.53.4 amalgamation archive')
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.inputs, args.output,
                             args.maintained_sqlite_archive), indent=2))
