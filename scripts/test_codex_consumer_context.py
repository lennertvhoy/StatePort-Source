from pathlib import Path
import hashlib
import os
import json, sys
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'config/codex-runtime/v8-repair'))
from consumer_context import prepare_context
import consumer_context
from context_verify import inventory
import subprocess

def test_context_refuses_missing_native_artifacts(tmp_path):
    source=tmp_path/'source.tar.gz'; source.write_bytes(b'x'); (tmp_path/'inputs').mkdir()
    (tmp_path/'native').mkdir(); receipt=tmp_path/'receipt.json'
    receipt.write_text(json.dumps({'status':'native-compiled-unqualified','artifacts':[]}))
    with pytest.raises((ValueError, FileNotFoundError)):
        prepare_context(source,tmp_path/'inputs',tmp_path/'native',receipt,tmp_path/'out')

def test_context_refuses_qualified_or_placeholder_receipt(tmp_path):
    source=tmp_path/'source.tar.gz'; source.write_bytes(b'x'); (tmp_path/'inputs').mkdir(); (tmp_path/'native').mkdir()
    receipt=tmp_path/'receipt.json'; receipt.write_text(json.dumps({'status':'passed','artifacts':[]}))
    with pytest.raises(ValueError, match='unqualified'):
        prepare_context(source,tmp_path/'inputs',tmp_path/'native',receipt,tmp_path/'out')

def test_context_positive_sequences_consumer_then_backports(tmp_path, monkeypatch):
    source=tmp_path/'source.tar.gz'; source.write_bytes(b'x'); inputs=tmp_path/'inputs'; inputs.mkdir()
    native=tmp_path/'native'; native.mkdir(); out=tmp_path/'out'
    archive=native/consumer_context.ARCHIVE; binding=native/consumer_context.BINDINGS
    archive.write_bytes(b'archive'); binding.write_bytes(b'binding')
    extras=[]
    for name,data in [('args.gn',b'gn'),('native-Cargo.lock',b'lock'),('source-preparation.json',b'prep')]:
        p=native/name; p.write_bytes(data); extras.append({'file':name,'sha256':__import__('hashlib').sha256(data).hexdigest(),'bytes':len(data)})
    digest=lambda p: __import__('hashlib').sha256(p.read_bytes()).hexdigest()
    receipt=tmp_path/'receipt.json'; receipt.write_text(json.dumps({'status':'native-compiled-unqualified','recipeSha256':'f5d24380b83ad03e7596b0f472711c6ecd662c09d4404c962d0ceb07f63d9465','fixedV8Commit':'4323497a6a73839e6d5260f6acd7ec0212cb3321','fixedV8Version':'15.2.124.21','artifacts':[{'file':consumer_context.ARCHIVE,'sha256':digest(archive),'bytes':7},{'file':consumer_context.BINDINGS,'sha256':digest(binding),'bytes':7}]+extras}))
    calls=[]
    def fake_consumer(src,dst): calls.append('consumer'); (dst/'codex-rs').mkdir(parents=True); (dst/'codex-rs/Cargo.toml').write_text('m'); (dst/'codex-rs/Cargo.lock').write_text('l')
    def fake_backports(src,inp,dst): calls.append('backports'); import shutil; shutil.copytree(src,dst); (dst/'codex-rs/stateport-native-overrides').mkdir(parents=True); (dst/'codex-rs/stateport-native-overrides/backport-preparation.json').write_text('{}')
    monkeypatch.setattr(consumer_context,'prepare_consumer',fake_consumer)
    monkeypatch.setattr(consumer_context,'prepare_backports',fake_backports)
    monkeypatch.setattr(consumer_context._source_mod,'prepare',lambda src,dst: (dst.mkdir(), {'sourceRoot':str(dst)})[1])
    result=prepare_context(source,inputs,native,receipt,out)
    assert calls == ['consumer','backports']
    assert result['consumerVersion']=='0.146.0+stateport.3'
    assert (out/'native-v8-inputs'/consumer_context.ARCHIVE).read_bytes()==b'archive'
    assert (out/'native-v8-inputs/native-build-receipt.json').read_bytes() == receipt.read_bytes()
    assert result['nativeBuildReceiptSha256'] == digest(receipt)
    assert set(result['nativeArtifacts']) == set(consumer_context.REQUIRED_ARTIFACTS)
    check = subprocess.run([sys.executable, '../context_verify.py', '..', '--sha',
                            result['inventoryDigest']], cwd=out/'codex-rs',
                           capture_output=True, text=True)
    assert check.returncode == 0, check.stderr

@pytest.mark.parametrize('mutate', ['recipe', 'duplicate', 'wrong', 'missing', 'symlink', 'extra', 'null', 'nondict', 'bool-size'])
def test_context_refuses_native_receipt_drift(tmp_path, mutate):
    source=tmp_path/'source.tar.gz'; source.write_bytes(b'x'); inputs=tmp_path/'inputs'; inputs.mkdir(); native=tmp_path/'native'; native.mkdir()
    a=native/consumer_context.ARCHIVE; b=native/consumer_context.BINDINGS; a.write_bytes(b'a'); b.write_bytes(b'b')
    h=lambda p: __import__('hashlib').sha256(p.read_bytes()).hexdigest()
    rows=[{'file':consumer_context.ARCHIVE,'sha256':h(a),'bytes':1},{'file':consumer_context.BINDINGS,'sha256':h(b),'bytes':1}]
    if mutate=='duplicate': rows.append(rows[0].copy())
    if mutate=='wrong': rows[0]['sha256']='0'*64
    if mutate=='missing': rows.pop()
    if mutate=='symlink': a.unlink(); a.symlink_to(b)
    if mutate=='extra': rows.append({'file':'extra','sha256':'0'*64,'bytes':0})
    if mutate=='null': rows[0]=None
    if mutate=='nondict': rows[0]='bad'
    if mutate=='bool-size': rows[0]['bytes']=True
    receipt=tmp_path/'r.json'; receipt.write_text(json.dumps({'status':'native-compiled-unqualified','recipeSha256':'f5d24380b83ad03e7596b0f472711c6ecd662c09d4404c962d0ceb07f63d9465','fixedV8Commit':'4323497a6a73839e6d5260f6acd7ec0212cb3321','fixedV8Version':'15.2.124.21','artifacts':rows}))
    if mutate=='recipe':
        value=json.loads(receipt.read_text()); value['recipeSha256']='0'*64; receipt.write_text(json.dumps(value))
    with pytest.raises(ValueError): prepare_context(source,inputs,native,receipt,tmp_path/'out')

def test_consumer_container_preserves_pinned_toolchain_and_repaired_inputs():
    text=(ROOT/'config/codex-runtime/v8-repair/Consumer.Containerfile').read_text()
    for pin in ('build-base=0.5-r3','clang21=21.1.2-r2','lld21=21.1.2-r1','openssl-dev=3.5.8-r0','xz-static=5.8.3-r0'):
        assert pin in text
    for setting in ('RUSTUP_TOOLCHAIN=1.95.0','AWS_LC_SYS_NO_JITTER_ENTROPY=1','LIBCLANG_PATH=/usr/lib/llvm21/lib','CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER'):
        assert setting in text
    assert 'cargo build --locked' in text and '--offline' not in text
    assert 'native-v8-inputs/librusty_v8_release' in text

def test_context_verify_cli_positive_after_receipt_written(tmp_path):
    root=tmp_path/'context'; root.mkdir(); (root/'codex-rs').mkdir(); (root/'codex-rs/Cargo.lock').write_text('lock'); (root/'consumer-context.json').write_text('{}')
    _, expected=inventory(root)
    p=subprocess.run([sys.executable,str(ROOT/'config/codex-runtime/v8-repair/context_verify.py'),str(root),'--sha',expected],capture_output=True,text=True)
    assert p.returncode==0

def test_container_trust_chain_binds_receipt_and_verifier_bytes(tmp_path):
    root=tmp_path/'context'; (root/'codex-rs').mkdir(parents=True)
    (root/'codex-rs/Cargo.lock').write_text('lock')
    receipt=root/'native-build-receipt.json'; receipt.write_text('{"status":"native-compiled-unqualified"}\n')
    verifier=root/'context_verify.py'; verifier.write_text((ROOT/'config/codex-runtime/v8-repair/context_verify.py').read_text())
    context=root/'consumer-context.json'; context.write_text(json.dumps({
        'nativeReceiptSha256': hashlib.sha256(receipt.read_bytes()).hexdigest(),
        'contextVerifierSha256': hashlib.sha256(verifier.read_bytes()).hexdigest(),
    })+'\n')
    # These are the same byte bindings the Containerfile verifies before invoking
    # the inventory checker from its codex-rs working directory.
    def check_sha(expected, name):
        return subprocess.run(['sha256sum','-c','-'], input=f'{expected}  {name}\n',
                              cwd=root, capture_output=True, text=True).returncode
    context_sha=hashlib.sha256(context.read_bytes()).hexdigest()
    receipt_sha=json.loads(context.read_text())['nativeReceiptSha256']
    assert check_sha(receipt_sha, receipt.name) == 0
    assert check_sha(context_sha, context.name) == 0
    verifier_sha=hashlib.sha256(verifier.read_bytes()).hexdigest()
    assert check_sha(verifier_sha, verifier.name) == 0
    _, inventory_sha=inventory(root)
    check=subprocess.run([sys.executable,'../context_verify.py','..','--sha',inventory_sha], cwd=root/'codex-rs', capture_output=True, text=True)
    assert check.returncode == 0

    context.write_text(context.read_text()+'tampered\n')
    assert check_sha(context_sha, context.name) != 0
    verifier.write_text('tampered\n')
    assert check_sha(verifier_sha, verifier.name) != 0

def test_context_verify_refuses_special_files(tmp_path):
    root=tmp_path/'context'; root.mkdir(); (root/'codex-rs').mkdir()
    (root/'codex-rs/Cargo.lock').write_text('lock'); (root/'consumer-context.json').write_text('{}')
    fifo=root/'codex-rs'/'unexpected-pipe'
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match='special file'):
        inventory(root)

@pytest.mark.parametrize('kind', ['file','lock','verifier','symlink'])
def test_context_verify_cli_refuses_context_mutation(tmp_path, kind):
    root=tmp_path/'context'; root.mkdir(); (root/'codex-rs').mkdir(); (root/'codex-rs/Cargo.lock').write_text('lock'); (root/'context_verify.py').write_text('trusted'); (root/'consumer-context.json').write_text('{}')
    _, expected=inventory(root)
    if kind=='file': (root/'codex-rs/Cargo.toml').write_text('changed')
    elif kind=='lock': (root/'codex-rs/Cargo.lock').write_text('changed')
    elif kind=='verifier': (root/'context_verify.py').write_text('tampered')
    else: (root/'escape').symlink_to('/tmp')
    p=subprocess.run([sys.executable,str(ROOT/'config/codex-runtime/v8-repair/context_verify.py'),str(root),'--sha',expected],capture_output=True,text=True)
    assert p.returncode != 0
