#!/usr/bin/env python3
"""Prepare (but do not execute) the governed XZ whole-library ASan run.

The generated runner uses XZ's own Autotools source manifest and configure
logic (including generated config.h).  Keeping source selection in upstream build files is important here:
the crate contains architecture-specific and conditional sources which a
directory glob can silently omit.
"""
import argparse, json, stat, subprocess, tarfile
from pathlib import Path
from prepare_xz_regression import sha, TEST

SCRIPT = r'''#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
jobs=${XZ_MAKE_JOBS:-2}
cc=${CC:-cc}
export CC="$cc"
for tool in "$cc" make autoreconf autopoint libtoolize aclocal autoconf autoheader automake; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required XZ build tool: $tool" >&2
        exit 2
    }
done

run_one() {
    label=$1
    tree=$root/$label/lzma-sys-0.1.20/xz-5.2
    test -f "$tree/configure.ac" || { echo "missing configure.ac for $label" >&2; exit 2; }
    test -f "$root/$label/xz-empty-index-regression.c" || { echo "missing regression source for $label" >&2; exit 2; }
    (
        cd "$tree"
        ./autogen.sh --no-po4a
        CFLAGS='-fsanitize=address -fno-omit-frame-pointer -O1 -g -UNDEBUG' \
        LDFLAGS='-fsanitize=address' \
        ./configure --disable-shared --enable-debug --disable-xz --disable-xzdec \
            --disable-lzmadec --disable-lzmainfo --disable-scripts --disable-doc \
            --disable-assembler
        make -C src/liblzma -j"$jobs" liblzma.la
        "$cc" -fsanitize=address -fno-omit-frame-pointer -O1 -g -UNDEBUG -std=c99 \
            -pthread -I"$tree/src/liblzma/api" -I"$tree/src/liblzma/common" \
            -I"$tree/src/common" -I"$tree" \
            "$root/$label/xz-empty-index-regression.c" \
            "$tree/src/liblzma/.libs/liblzma.a" -o "$root/$label/xz-regression"
    )
    if [ "$label" = vulnerable ]; then
        set +e
        ASAN_OPTIONS=detect_leaks=0 "$root/$label/xz-regression" >"$root/$label/stdout" 2>"$root/$label/stderr"
        status=$?
        set -e
        if [ "$status" -eq 0 ]; then
            echo 'vulnerable control unexpectedly exited 0' >&2
            exit 1
        fi
        classify_vulnerable "$root/$label/stderr" || {
            echo 'vulnerable control did not produce the intended ASan index-append report' >&2
            exit 1
        }
    else
        ASAN_OPTIONS=detect_leaks=0 "$root/$label/xz-regression" >"$root/$label/stdout" 2>"$root/$label/stderr"
        test ! -s "$root/$label/stderr" || {
            echo 'repaired control produced sanitizer diagnostics' >&2
            cat "$root/$label/stderr" >&2
            exit 1
        }
    fi
}

classify_vulnerable() {
    log=$1
    grep -q 'AddressSanitizer: heap-buffer-overflow' "$log" && grep -q 'lzma_index_append' "$log"
}

if [ "${1:-}" = --classify-vulnerable ]; then
    test "$#" -eq 2 || exit 2
    classify_vulnerable "$2"
    exit $?
fi

run_one vulnerable
run_one repaired
echo 'XZ whole-library ASan regression passed: vulnerable control reports, repaired control exits cleanly'
'''

def validate_inputs(crate, patch_path, regression_path, row, regression):
 if sha(crate)!=row['crateSha256'] or crate.stat().st_size!=row['crateBytes']: raise ValueError('crate identity mismatch')
 if sha(patch_path)!=row['patchSha256']: raise ValueError('XZ source patch identity mismatch')
 if sha(regression_path)!=regression['sha256'] or regression_path.stat().st_size!=regression['bytes']: raise ValueError('XZ regression input identity mismatch')

def stage(crate, out):
 pins=json.loads((Path(__file__).parent/'pins.json').read_text()); row=next(x for x in pins['packages'] if x['name']=='lzma-sys')
 regression=next(x for x in pins['regressionInputs'] if x['file']=='xz-upstream-regression.patch')
 patch_path=Path(__file__).with_name(row['patchFile'])
 regression_path=Path(__file__).with_name(regression['file'])
 validate_inputs(crate, patch_path, regression_path, row, regression)
 out.mkdir(parents=False,exist_ok=False); roots=[]
 for label in ('vulnerable','repaired'):
  d=out/label; d.mkdir()
  with tarfile.open(crate) as a:a.extractall(d,filter='data')
  root=d/'lzma-sys-0.1.20/xz-5.2'; roots.append(root)
  source=root/'src/liblzma/common/index.c'
  if sha(source)!=row['beforeSha256']: raise ValueError('source preimage mismatch')
  if label=='repaired': subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(Path(__file__).with_name(row['patchFile']))],cwd=root,check=True)
  if label=='repaired' and sha(source)!=row['afterSha256']: raise ValueError('source postimage mismatch')
  (d/'xz-empty-index-regression.c').write_text(TEST)
 return roots
def main():
 p=argparse.ArgumentParser();p.add_argument('--crate',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args(); roots=stage(a.crate,a.output)
 pins=json.loads((Path(__file__).parent/'pins.json').read_text()); row=next(x for x in pins['packages'] if x['name']=='lzma-sys')
 regression=next(x for x in pins['regressionInputs'] if x['file']=='xz-upstream-regression.patch')
 runner = a.output/'run-xz-asan.sh'
 runner.write_text(SCRIPT)
 runner.chmod(runner.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
 commands=[]
 for label in ('vulnerable','repaired'):
  root = a.output/label/'lzma-sys-0.1.20/xz-5.2'
  commands.append({'label':label,'build_system':'XZ Autotools (autogen.sh + configure + make)',
   'cwd':str(root),
   'runner_argv':['./run-xz-asan.sh'],
   'configure': ['--disable-shared','--enable-debug','--disable-xz','--disable-xzdec','--disable-lzmadec','--disable-lzmainfo','--disable-scripts','--disable-doc','--disable-assembler'],
   'source_manifest':'upstream src/liblzma/Makefile.am and */Makefile.inc',
   'include_dirs':[str(root/'src/liblzma/api'),str(root/'src/liblzma/common'),str(root/'src/common'),str(root)],
   'compiler_premises':['CC (or cc) supports C99 and -fsanitize=address','Autoconf/Automake/Libtool/Autopoint are installed','pthread support is available'],
   'status':'not_run','expected':'ASan heap-buffer-overflow report' if label=='vulnerable' else 'exit 0 with empty stderr'})
 (a.output/'run-plan.json').write_text(json.dumps({'status':'prepared; not run','crateSha256':row['crateSha256'],'crateBytes':row['crateBytes'],'patchSha256':row['patchSha256'],'regressionPatchSha256':regression['sha256'],'api_sequence':['lzma_index_init','lzma_index_buffer_encode','lzma_index_buffer_decode','lzma_index_append'],'runner':'run-xz-asan.sh','runnerSha256':sha(runner),'harnessSha256':sha(a.output/'vulnerable/xz-empty-index-regression.c'),'commands':commands},indent=2)+'\n')
if __name__=='__main__': main()
