#!/usr/bin/env python3
"""Fetch/verify pinned Chromium vendor trees; payload retrieval is governor-only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


def verify_archive(archive: Path, package: dict) -> dict:
    expected = {row['path']: row for row in package['files']}
    directories = {str(parent) for name in expected for parent in PurePosixPath(name).parents}
    seen = set()
    total = 0
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('vendor archive path escapes')
            name = path.as_posix()
            if member.isdir() and name in directories:
                continue
            if name not in expected or name in seen or not member.isfile():
                raise ValueError('vendor archive has an unexpected, duplicate or non-file member: ' + name)
            if not 0 <= member.size <= MAX_FILE_BYTES:
                raise ValueError('vendor member exceeds bound')
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise ValueError('vendor expanded archive exceeds bound')
            with bundle.extractfile(member) as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
            digest = hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()
            if len(data) != member.size or digest != expected[name]['gitBlobSha1']:
                raise ValueError('vendor blob differs from pinned upstream source: ' + name)
            expected_exec = expected[name]['mode'] == 0o100755
            if bool(member.mode & 0o111) != expected_exec:
                raise ValueError('vendor mode differs from pinned upstream source')
            seen.add(name)
    if seen != set(expected):
        raise ValueError('vendor archive omits pinned files')
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'directory': package['directory'], 'file': package['archiveFile'],
            'sha256': digest, 'bytes': archive.stat().st_size,
            'verifiedFiles': len(seen), 'expandedBytes': total,
            'upstreamTreeGitSha1': package['treeGitSha1']}


def fetch(output: Path) -> dict:
    manifest_path = HERE / 'chromium-vendor.json'
    manifest = json.loads(manifest_path.read_text())
    output.mkdir(parents=False, exist_ok=False)
    rows = []
    total = 0
    for package in manifest['packages']:
        temporary = output / (package['archiveFile'] + '.partial')
        with urllib.request.urlopen(package['archiveUrl'], timeout=60) as response, temporary.open('xb') as target:
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                total += len(chunk)
                if size > MAX_ARCHIVE_BYTES or total > MAX_TOTAL_BYTES:
                    raise ValueError('vendor download exceeds bounded fetch')
                target.write(chunk)
        row = verify_archive(temporary, package)
        if package.get('archiveSha256') is not None and (
            row['sha256'] != package['archiveSha256'] or row['bytes'] != package['archiveBytes']
        ):
            raise ValueError('download differs from reviewed vendor transport identity')
        temporary.rename(output / package['archiveFile'])
        rows.append(row)
        print(json.dumps(row), flush=True)
    result = {'status': 'upstream-vendor-trees-verified', 'nativeCompilation': 'not_run',
              'manifestSha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
              'files': rows, 'totalBytes': total}
    (output / 'fetch-receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def verify_inputs(inputs: Path, manifest: dict) -> list[dict]:
    rows = []
    for package in manifest['packages']:
        expected = package.get('archiveSha256')
        if not isinstance(expected, str) or len(expected) != 64:
            raise ValueError('vendor transport inputs require reviewed SHA-256 pins')
        archive = inputs / package['archiveFile']
        if archive.is_symlink() or not archive.is_file():
            raise ValueError('vendor input must be a regular file')
        with archive.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected or archive.stat().st_size != package['archiveBytes']:
            raise ValueError('vendor transport integrity mismatch: ' + archive.name)
        rows.append(verify_archive(archive, package))
    return rows


def restore(inputs: Path, source_root: Path, manifest: dict) -> dict:
    verified = verify_inputs(inputs, manifest)
    destination = source_root / 'third_party/rust/chromium_crates_io'
    if destination.exists() or destination.is_symlink():
        raise ValueError('Chromium vendor source was unexpectedly present')
    destination.mkdir(parents=False)
    for package in manifest['packages']:
        target = destination / 'vendor' / package['directory']
        target.mkdir(parents=True, exist_ok=False)
        with tarfile.open(inputs / package['archiveFile'], 'r:gz') as bundle:
            bundle.extractall(target, filter='data')
    return {'status': 'source-restored', 'upstreamCommit': manifest['commit'],
            'archives': verified, 'nativeCompilation': 'not_run'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(fetch(arguments.output), indent=2))
