from pathlib import Path
import ast
import json
import importlib.util
import sys
import subprocess
ROOT=Path(__file__).resolve().parents[1]
def test_xz_prep_is_source_only_and_exact_api_sequence():
 p=ROOT/'config/codex-runtime/v8-repair/native-backports/prepare_xz_regression.py'
 ast.parse(p.read_text()); text=p.read_text()
 for call in ('lzma_index_buffer_encode','lzma_index_buffer_decode','lzma_index_append','ASan'):
  assert call in text
 assert 'not compiled' in text

def test_xz_runner_uses_upstream_manifest_and_both_controls():
 p=ROOT/'config/codex-runtime/v8-repair/native-backports/run_xz_asan.py'
 ast.parse(p.read_text()); text=p.read_text()
 for marker in ('autogen.sh','configure','make -C src/liblzma','Makefile.am',
                'heap-buffer-overflow','vulnerable','repaired','-fsanitize=address',
                'config.h'):
  assert marker in text
 assert '.glob(' not in text
 assert 'source_manifest' in text

def test_xz_stage_refuses_changed_crate_patch_and_regression(tmp_path):
 module_path=ROOT/'config/codex-runtime/v8-repair/native-backports/run_xz_asan.py'
 sys.path.insert(0, str(module_path.parent))
 spec=importlib.util.spec_from_file_location('run_xz_asan', module_path)
 run_xz_asan=importlib.util.module_from_spec(spec); spec.loader.exec_module(run_xz_asan)
 pins=json.loads((ROOT/'config/codex-runtime/v8-repair/native-backports/pins.json').read_text())
 row=next(x for x in pins['packages'] if x['name']=='lzma-sys')
 regression=next(x for x in pins['regressionInputs'] if x['file']=='xz-upstream-regression.patch')
 crate=tmp_path/'input.crate'; crate.write_bytes(b'bounded synthetic crate identity fixture')
 row=dict(row, crateSha256=run_xz_asan.sha(crate), crateBytes=crate.stat().st_size)
 patch=ROOT/'config/codex-runtime/v8-repair/native-backports/lzma-sys.patch'
 test=ROOT/'config/codex-runtime/v8-repair/native-backports/xz-upstream-regression.patch'
 for source, name in ((crate,'crate'),(patch,'patch'),(test,'regression')):
  changed=tmp_path/name; changed.write_bytes(source.read_bytes()+b'changed')
  try:
   run_xz_asan.validate_inputs(changed if name == 'crate' else crate,
                               changed if name == 'patch' else patch,
                               changed if name == 'regression' else test,
                               row, regression)
  except ValueError as exc:
   assert name in str(exc)
  else:
   raise AssertionError(f'{name} mutation was accepted')

def test_xz_shell_classification_rejects_unrelated_asan(tmp_path):
 runner=tmp_path/'run-xz-asan.sh'
 source=(ROOT/'config/codex-runtime/v8-repair/native-backports/run_xz_asan.py').read_text()
 marker="SCRIPT = r'''"
 body=source.split(marker,1)[1].split("'''",1)[0]
 runner.write_text(body); runner.chmod(0o700)
 good=tmp_path/'good.log'; good.write_text('ERROR: AddressSanitizer: heap-buffer-overflow in lzma_index_append\n')
 bad=tmp_path/'bad.log'; bad.write_text('ERROR: AddressSanitizer: stack-overflow\n')
 assert subprocess.run([str(runner),'--classify-vulnerable',str(good)]).returncode == 0
 assert subprocess.run([str(runner),'--classify-vulnerable',str(bad)]).returncode != 0
