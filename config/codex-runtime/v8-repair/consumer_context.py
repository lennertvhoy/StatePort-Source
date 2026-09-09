#!/usr/bin/env python3
"""Prepare a consumer .3 context bound to one unqualified native build."""
from __future__ import annotations
import hashlib, json, shutil
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'native-backports'))
from prepare_backports import prepare as prepare_backports
from prepare import prepare_consumer
from context_verify import inventory
import importlib.util
_spec = importlib.util.spec_from_file_location('stateport_prepare_source', Path(__file__).resolve().parents[1] / 'prepare-source.py')
_source_mod = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_source_mod)

ARCHIVE = 'librusty_v8_release_x86_64-unknown-linux-musl.a.gz'
BINDINGS = 'src_binding_release_x86_64-unknown-linux-musl.rs'
REQUIRED_ARTIFACTS = (ARCHIVE, BINDINGS, 'args.gn', 'native-Cargo.lock', 'source-preparation.json')

def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file(): raise ValueError('native artifact must be a regular file')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def prepare_context(source_archive: Path, backport_inputs: Path, native_artifacts: Path,
                    native_receipt: Path, output: Path) -> dict:
    if output.exists() or source_archive.is_symlink() or not source_archive.is_file(): raise ValueError('source archive/output unsafe')
    if native_artifacts.is_symlink() or not native_artifacts.is_dir(): raise ValueError('native artifacts directory unsafe')
    if native_receipt.is_symlink() or not native_receipt.is_file() or native_receipt.stat().st_size > 524288:
        raise ValueError('native receipt must be a bounded regular file')
    receipt_bytes = native_receipt.read_bytes()
    receipt = json.loads(receipt_bytes)
    if not isinstance(receipt, dict) or receipt.get('status') != 'native-compiled-unqualified':
        raise ValueError('native receipt is not an unqualified completed build')
    if (receipt.get('recipeSha256') != 'f5d24380b83ad03e7596b0f472711c6ecd662c09d4404c962d0ceb07f63d9465'
            or receipt.get('fixedV8Commit') != '4323497a6a73839e6d5260f6acd7ec0212cb3321'
            or receipt.get('fixedV8Version') != '15.2.124.21'):
        raise ValueError('native recipe or V8 identity mismatch')
    rows_list = receipt.get('artifacts')
    if not isinstance(rows_list, list) or any(not isinstance(r, dict) for r in rows_list):
        raise ValueError('native receipt artifact set is malformed')
    for row in rows_list:
        if (not isinstance(row.get('file'), str) or '/' in row['file'] or '\\' in row['file']
                or not isinstance(row.get('sha256'), str) or len(row['sha256']) != 64
                or any(c not in '0123456789abcdef' for c in row['sha256'])
                or type(row.get('bytes')) is not int or row['bytes'] < 0):
            raise ValueError('native receipt artifact row is malformed')
    if len({r['file'] for r in rows_list}) != len(rows_list):
        raise ValueError('native receipt contains duplicate artifacts')
    if {r['file'] for r in rows_list} != set(REQUIRED_ARTIFACTS):
        raise ValueError('native receipt artifact set is not exact')
    rows = {r.get('file'): r for r in rows_list}
    for name in REQUIRED_ARTIFACTS:
        path = native_artifacts / name
        row = rows.get(name)
        if row is None or row.get('sha256') != digest(path) or row.get('bytes') != path.stat().st_size:
            raise ValueError('native artifact receipt mismatch: ' + name)
    base = output.parent / (output.name + '.base-source')
    base_receipt = _source_mod.prepare(source_archive, base)
    prepared = output.parent / (output.name + '.consumer-source')
    prepare_consumer(Path(base_receipt['sourceRoot']), prepared)
    target = output
    prepare_backports(prepared, backport_inputs, target)
    native_dir = target / 'native-v8-inputs'; native_dir.mkdir()
    for name in REQUIRED_ARTIFACTS:
        copied = native_dir / name
        shutil.copyfile(native_artifacts / name, copied)
        if digest(copied) != rows[name]['sha256'] or copied.stat().st_size != rows[name]['bytes']:
            raise ValueError('native artifact changed during preparation: ' + name)
    (native_dir / 'native-build-receipt.json').write_bytes(receipt_bytes)
    result = {'status': 'consumer-context-prepared', 'consumerVersion': '0.146.0+stateport.3',
              'sourceArchiveSha256': digest(source_archive), 'baseSourcePreparation': base_receipt,
              'recipeSha256': receipt['recipeSha256'], 'fixedV8Commit': receipt['fixedV8Commit'],
              'nativeBuildStatus': receipt['status'],
              'nativeBuildReceiptSha256': hashlib.sha256(receipt_bytes).hexdigest(),
              'nativeArtifacts': {
                  name: {'sha256': digest(native_dir / name), 'bytes': (native_dir / name).stat().st_size}
                  for name in REQUIRED_ARTIFACTS}, 'backportPreparation': str(target / 'codex-rs/stateport-native-overrides/backport-preparation.json'),
              'lockedResolution': 'not_run', 'nativeRegressions': 'not_run', 'releaseQualification': 'not_run'}
    shutil.copyfile(Path(__file__).with_name('context_verify.py'), target / 'context_verify.py')
    rows, inv = inventory(target)
    result['inventoryDigest'] = inv; result['inventoryEntries'] = len(rows)
    result['manifestSha256'] = digest(target / 'codex-rs/Cargo.toml')
    result['lockSha256'] = digest(target / 'codex-rs/Cargo.lock')
    result['backportReceiptSha256'] = digest(target / 'codex-rs/stateport-native-overrides/backport-preparation.json')
    result['contextVerifierSha256'] = digest(target / 'context_verify.py')
    (target / 'consumer-context.json').write_text(json.dumps(result, indent=2) + '\n')
    return result

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-archive', type=Path, required=True)
    p.add_argument('--backport-inputs', type=Path, required=True)
    p.add_argument('--native-artifacts', type=Path, required=True)
    p.add_argument('--native-receipt', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(prepare_context(args.source_archive, args.backport_inputs,
        args.native_artifacts, args.native_receipt, args.output), indent=2))
