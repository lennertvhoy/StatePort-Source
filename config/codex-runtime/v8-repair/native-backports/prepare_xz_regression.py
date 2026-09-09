#!/usr/bin/env python3
"""Stage the pinned XZ empty-index regression without compiling it."""
import argparse, hashlib, json, tarfile
from pathlib import Path

TEST = r'''#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <lzma.h>
int main(void) {
  uint8_t buf[256]; size_t n = 0, pos = 0; uint64_t limit = UINT64_MAX;
  lzma_index *idx = lzma_index_init(NULL); assert(idx != NULL);
  assert(lzma_index_buffer_encode(idx, buf, &n, sizeof(buf)) == LZMA_OK);
  assert(n > 0); lzma_index_end(idx, NULL); idx = NULL;
  assert(lzma_index_buffer_decode(&idx, &limit, NULL, buf, &pos, n) == LZMA_OK);
  assert(pos == n); assert(lzma_index_append(idx, NULL, 55, 1) == LZMA_OK);
  lzma_index_end(idx, NULL); return 0;
}
'''
def sha(p): return hashlib.file_digest(p.open('rb'), 'sha256').hexdigest()
def main(crate, output):
    pins=json.loads((Path(__file__).parent/'pins.json').read_text())
    row=next(x for x in pins['packages'] if x['name']=='lzma-sys')
    if sha(crate)!=row['crateSha256'] or crate.stat().st_size != row['crateBytes']: raise ValueError('lzma crate identity mismatch')
    if sha(Path(__file__).with_name(row['patchFile'])) != row['patchSha256']: raise ValueError('XZ source patch identity mismatch')
    regression = next(x for x in pins['regressionInputs'] if x['file']=='xz-upstream-regression.patch')
    if sha(Path(__file__).with_name(regression['file'])) != regression['sha256']: raise ValueError('XZ regression patch identity mismatch')
    output.mkdir(parents=False, exist_ok=False)
    with tarfile.open(crate) as a: a.extractall(output, filter='data')
    root=output/(row['name']+'-'+row['version'])
    source=root/row['sourcePath']
    if sha(source)!=row['beforeSha256']: raise ValueError('XZ vulnerable source preimage mismatch')
    test=output/'xz-empty-index-regression.c'; test.write_text(TEST)
    (output/'regression-receipt.json').write_text(json.dumps({'status':'prepared; not compiled','crateSha256':row['crateSha256'],'crateBytes':row['crateBytes'],'sourceBeforeSha256':row['beforeSha256'],'sourceAfterSha256':row['afterSha256'],'patchSha256':row['patchSha256'],'regressionPatchSha256':regression['sha256'],'testSha256':sha(test),'sanitizer':'ASan required; repaired pass, vulnerable control must be retained separately'},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(); p.add_argument('--crate',type=Path,required=True); p.add_argument('--output',type=Path,required=True); a=p.parse_args(); main(a.crate,a.output)
