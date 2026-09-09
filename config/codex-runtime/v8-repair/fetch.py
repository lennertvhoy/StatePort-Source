#!/usr/bin/env python3
"""Fetch only immutable repair inputs; run this through the workstation governor."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tomllib
import urllib.request

from prepare import HERE, recipe, sha256


def inputs() -> list[dict]:
    value = recipe()
    rows = list(value['tools'])
    for item in tomllib.loads((HERE / 'native-Cargo.lock').read_text())['package']:
        if 'source' not in item:
            continue
        if item['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
            raise ValueError('unexpected native Cargo source')
        name = f"{item['name']}-{item['version']}.crate"
        rows.append({'name': name, 'file': name, 'sha256': item['checksum'],
                     'url': f"https://static.crates.io/crates/{item['name']}/{name}"})
    rows.append({'name': 'ICU78-data', 'file': 'deno_core_icudata-0.78.0.crate',
                 'url': 'https://static.crates.io/crates/deno_core_icudata/deno_core_icudata-0.78.0.crate',
                 'bytes': 4619641, 'sha256': value['consumer']['icuDataSha256']})
    if len({row['file'] for row in rows}) != len(rows):
        raise ValueError('duplicate input filenames')
    return rows


def verify_inputs(directory: Path) -> list[dict]:
    result = []
    for row in inputs():
        path = directory / row['file']
        if sha256(path) != row['sha256']:
            raise ValueError(f"input digest differs: {row['file']}")
        if row.get('bytes') and path.stat().st_size != row['bytes']:
            raise ValueError(f"input size differs: {row['file']}")
        result.append({'file': row['file'], 'sha256': row['sha256'], 'bytes': path.stat().st_size})
    return result


def fetch(output: Path, caches: list[Path]) -> dict:
    output.mkdir(parents=False, exist_ok=False)
    receipts = []
    for row in inputs():
        destination = output / row['file']
        cached = next((root / row['file'] for root in caches
                       if (root / row['file']).is_file()
                       and not (root / row['file']).is_symlink()
                       and sha256(root / row['file']) == row['sha256']), None)
        print(f"input {row['file']} ({'verified cache' if cached else 'download'})", flush=True)
        temporary = destination.with_name(destination.name + '.partial')
        if cached is not None:
            with cached.open('rb') as source, temporary.open('xb') as target:
                shutil.copyfileobj(source, target)
        else:
            request = urllib.request.Request(row['url'], headers={'User-Agent': 'StatePort-native-input-preparation'})
            with urllib.request.urlopen(request, timeout=60) as source, temporary.open('xb') as target:
                received = 0
                maximum = row.get('bytes') or 512 * 1024 * 1024
                while data := source.read(1024 * 1024):
                    received += len(data)
                    if received > maximum:
                        raise ValueError(f"input exceeds expected bound: {row['file']}")
                    target.write(data)
        if sha256(temporary) != row['sha256']:
            raise ValueError(f"downloaded input digest differs: {row['file']}")
        if row.get('bytes') and temporary.stat().st_size != row['bytes']:
            raise ValueError(f"downloaded input size differs: {row['file']}")
        temporary.rename(destination)
        receipts.append({'file': row['file'], 'sha256': row['sha256'],
                         'bytes': destination.stat().st_size, 'fromVerifiedCache': cached is not None})
    result = {'result': 'inputs-verified', 'nativeBuild': 'not_run',
              'recipeSha256': hashlib.sha256((HERE / 'recipe.json').read_bytes()).hexdigest(),
              'files': receipts}
    (output / 'input-receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', action='append', type=Path, default=[])
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    result = verify_inputs(args.output) if args.verify_only else fetch(args.output, args.cache)
    print(json.dumps(result, indent=2))
