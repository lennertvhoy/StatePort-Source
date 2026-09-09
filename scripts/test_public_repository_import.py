"""Deterministic transport-boundary fixtures; real public network proof is separate."""
from __future__ import annotations

import fcntl
import json
import os
import socket
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from pathlib import Path
import subprocess

import pytest

from test_template_import_lifecycle import _statespec_repository, _git, _install, LocalLayout, PersistentApp
from stateport_persistent_app import repository_import as module

URL = 'https://example.com/template'
_SYNTHETIC_INVALID_CREDENTIAL_URL = (
    'https://' + 'user' + ':' + 'secret' + '@example.com/repo'
)


def fixture(tmp_path, monkeypatch):
    source = _statespec_repository(tmp_path / 'source')
    revision = _git(source, 'rev-parse', 'HEAD')
    layout = LocalLayout(tmp_path/'config', tmp_path/'data', tmp_path/'state')
    inspector = module.RepositoryInspector(module.RepositorySourcePolicy(layout))
    monkeypatch.setattr(module, '_public_target', lambda value: (URL, '1.1.1.1'))
    real_git = module._remote_git
    fetches = []
    def fixture_git(root, args, **kwargs):
        if args[0] == 'fetch':
            fetches.append(args)
            # Inject real Git objects from a synthetic independent template.
            # This is not a test of public network acquisition.
            subprocess.run(['git', 'fetch', '--quiet', str(source), args[-1]], cwd=root, check=True)
            return b''
        return real_git(root, args, **kwargs)
    monkeypatch.setattr(module, '_remote_git', fixture_git)
    return source, revision, layout, inspector, fetches


def test_remote_candidate_generic_template_install_receipt_retry_and_source_preservation(tmp_path, monkeypatch):
    source, revision, layout, inspector, fetches = fixture(tmp_path, monkeypatch)
    before = {p.relative_to(source).as_posix(): p.read_bytes() for p in source.rglob('*') if p.is_file()}
    inspected = inspector.inspect_public_url(URL, revision)
    assert inspected['template']['adapterId'] == 'statespec-template'
    assert inspector.inspect_public_url(URL, revision)['inspectionDigest'] == inspected['inspectionDigest']
    assert len(fetches) == 1
    app = PersistentApp(layout)
    app.setup_init()
    cached = inspector.policy.resolve_candidate(inspected['candidateId'])
    installed = _install(app, inspected, cached, 'public-template')
    assert installed['source']['sourceKind'] == 'public_git_snapshot'
    assert installed['source']['resolvedCommit'] == revision
    assert PersistentApp(layout).catalog.get('public-template')['observedSource']['resolvedCommit'] == revision
    assert {p.relative_to(source).as_posix(): p.read_bytes() for p in source.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('kind', ['symlink', 'submodule', 'oversized'])
def test_tree_refusal_removes_partial_candidate_and_allows_explicit_retry(tmp_path, monkeypatch, kind):
    source, revision, layout, inspector, fetches = fixture(tmp_path, monkeypatch)
    if kind == 'symlink':
        (source/'escape').symlink_to('/etc/passwd')
        _git(source, 'add', 'escape')
    elif kind == 'submodule':
        _git(source, 'update-index', '--add', '--cacheinfo', f'160000,{revision},nested')
    else:
        inspector.policy.limits = module.RepositoryResourceLimits(maximum_materialized_bytes=1)
    if kind != 'oversized':
        _git(source, 'commit', '-qm', 'unsafe fixture')
        revision = _git(source, 'rev-parse', 'HEAD')
    with pytest.raises(module.RepositoryImportError) as failed:
        inspector.inspect_public_url(URL, revision)
    assert failed.value.code == 'repository_tree_refused'
    cache = layout.data_root/'public-repositories'
    assert not list(cache.glob('repo-*')) and not list(cache.glob('.acquiring-*'))
    inspector.policy.limits = module.RepositoryResourceLimits()
    if kind != 'oversized':
        revision = _git(source, 'rev-parse', 'HEAD^')
    assert inspector.inspect_public_url(URL, revision)['sourceIdentity']['headCommit'] == revision


def test_concurrent_acquisition_and_full_cache_refuse_before_fetch(tmp_path, monkeypatch):
    source, revision, layout, inspector, fetches = fixture(tmp_path, monkeypatch)
    cache = module._private_repository_cache(inspector.policy)
    with (cache/'.acquisition.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with pytest.raises(module.RepositoryImportError) as busy:
            inspector.inspect_public_url(URL, revision)
        assert busy.value.code == 'repository_fetch_busy'
    monkeypatch.setattr(module, '_cache_size', lambda root: 1024**3)
    with pytest.raises(module.RepositoryImportError) as full:
        inspector.inspect_public_url(URL, revision)
    assert full.value.code == 'repository_cache_full'
    assert not fetches


def test_interrupted_stage_is_removed_but_changed_completed_snapshot_is_preserved(tmp_path, monkeypatch):
    source, revision, layout, inspector, fetches = fixture(tmp_path, monkeypatch)
    cache = module._private_repository_cache(inspector.policy)
    abandoned = cache/'.acquiring-interrupted'
    abandoned.mkdir()
    (abandoned/'partial').write_text('partial')
    inspected = inspector.inspect_public_url(URL, revision)
    assert not abandoned.exists()
    cached = inspector.policy.resolve_candidate(inspected['candidateId'])
    (cached/'README.md').write_text('corrupted cache')
    with pytest.raises(module.RepositoryImportError) as stale:
        inspector.inspect_public_url(URL, revision)
    assert stale.value.code == 'repository_inspection_stale'
    assert (cached/'README.md').read_text() == 'corrupted cache'
    assert len(fetches) == 1


@pytest.mark.parametrize('url', [_SYNTHETIC_INVALID_CREDENTIAL_URL, 'https://example.com/repo?token=secret', 'https://example.com:bad/repo', 'https://example.com/repo#fragment', 'http://example.com/repo', 'https://localhost/repo', 'https://example.com/\nrepo'])
def test_invalid_public_identifiers_refused_without_resolution(url):
    with pytest.raises(module.RepositoryImportError):
        module.validate_public_https_url(url, resolve=False)


@pytest.mark.skipif(os.environ.get('STATEPORT_PUBLIC_TEMPLATE_PROOF') != '1', reason='Explicit bounded public-network qualification only')
def test_real_public_http_import_review_refusals_receipt_and_restart(tmp_path, monkeypatch):
    from test_template_import_lifecycle import ROOT
    from service_test_product import service_product_fixture
    for variable, child in (("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_STATE_HOME", "state")):
        monkeypatch.setenv(variable, str(tmp_path/child))
    monkeypatch.setenv('STATEPORT_REPOSITORY_ROOTS', '')
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    product = service_product_fixture(tmp_path, ROOT)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    def session():
        with urlopen(base+'/session', timeout=5) as response:
            return response.headers['Set-Cookie'].split(';',1)[0], json.loads(response.read())['result']['csrfToken']
    def request(path, body=None, token=None):
        headers = {'Cookie': cookie}
        if body is not None:
            headers.update({'Content-Type':'application/json', 'Origin':base, 'X-StatePort-CSRF': token or csrf})
        with urlopen(Request(base+path, data=None if body is None else json.dumps(body).encode(), headers=headers), timeout=90) as response:
            return json.loads(response.read())['result']
    url = 'https://github.com/lennertvhoy/ProjectState_Template'
    revision = '7e4cb7c3397324d09f768eeb1d722316714c46e1'
    app.service_start(port=port, repo_root=product)
    try:
        cookie, csrf = session()
        assert request('/v1/repository-import/local-candidates')['candidates'] == []
        with pytest.raises(HTTPError) as denied:
            request('/v1/repository-import/inspect', {'url':url,'revision':revision}, token='wrong')
        assert denied.value.code == 403
        inspected = request('/v1/repository-import/inspect', {'url':url,'revision':revision})
        assert inspected['sourceIdentity']['headCommit'] == revision
        assert inspected['sourceKind'] == 'public_https'
        assert request('/v1/repository-import/inspect', {'candidateId':inspected['candidateId']})['inspectionDigest'] == inspected['inspectionDigest']
        candidate = module.RepositoryInspector(module.RepositorySourcePolicy(app.layout)).policy.resolve_candidate(inspected['candidateId'])
        before = {p.relative_to(candidate).as_posix():p.read_bytes() for p in candidate.rglob('*') if p.is_file()}
        plan_body = {'candidateId':inspected['candidateId'], 'inspectionDigest':inspected['inspectionDigest'], 'instanceId':'public-projectstate', 'name':'Public ProjectState'}
        with pytest.raises(HTTPError):
            request('/v1/template-import/plan', {**plan_body, 'inspectionDigest':'sha256:'+'0'*64})
        plan = request('/v1/template-import/plan', plan_body)
        actor = request('/v1/status')['actor']['actorId']
        with pytest.raises(HTTPError):
            request('/v1/template-import/install', {'plan':plan,'approval':{'decision':'approve','actorId':actor,'planDigest':'sha256:'+'0'*64}})
        with pytest.raises(HTTPError):
            request('/v1/repository-import/register', {**plan_body,'approval':{'decision':'approve','actorId':actor,'proposalDigest':inspected['inspectionDigest']}})
        installed = request('/v1/template-import/install', {'plan':plan,'approval':{'decision':'approve','actorId':actor,'planDigest':plan['planDigest']}})
        receipt_id = installed['receiptId']
        detail = request(f'/v1/instances/public-projectstate/receipts/{receipt_id}')['receipt']
        assert detail['payload']['source']['resolvedCommit'] == revision
        assert detail['payload']['source']['sourceKind'] == 'public_git_snapshot'
        assert detail['payload']['source']['remote'] == url
        assert {p.relative_to(candidate).as_posix():p.read_bytes() for p in candidate.rglob('*') if p.is_file()} == before
        assert (app.layout.instances_root/'public-projectstate'/'PROJECT.md').read_bytes() == (candidate/'PROJECT.md').read_bytes()
    finally:
        app.service_stop()
    app.service_start(port=port, repo_root=product)
    try:
        cookie, csrf = session()
        assert any(item['instanceId']=='public-projectstate' for item in request('/v1/instances')['instances'])
        assert request(f'/v1/instances/public-projectstate/receipts/{receipt_id}')['receipt'] == detail
    finally:
        app.service_stop()


def test_actual_git_shallow_fetch_refuses_dumb_http_before_alternate_object_requests(tmp_path):
    """Adversarial loopback fixture checks Git behavior, not public/TLS proof."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    paths = []
    revision = 'a'*40
    class HostileDumbGit(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            if self.path.startswith('/repo/info/refs'):
                data = f'{revision}\trefs/heads/main\n'.encode()
            elif self.path == '/repo/HEAD':
                data = b'ref: refs/heads/main\n'
            else:
                data = b'https://127.0.0.1/private/objects\n'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1',0), HostileDumbGit)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        subprocess.run(['git','init','--quiet',str(tmp_path/'client')],check=True)
        result = subprocess.run(['git','-c','http.followRedirects=false','fetch','--depth=1','--no-tags',f'http://127.0.0.1:{server.server_port}/repo',revision],cwd=tmp_path/'client',env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_CONFIG_SYSTEM':os.devnull},capture_output=True,text=True,timeout=5)
        assert result.returncode != 0
        assert 'dumb http transport does not support shallow capabilities' in result.stderr
        assert paths and not any('/objects' in path for path in paths)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_secondary_network_helper_is_unavailable_and_future_builtin_is_refused(monkeypatch):
    with module._restricted_git_helpers() as helpers:
        assert sorted(path.name for path in helpers.iterdir()) == ['git', 'git-remote-https']
        assert helpers.stat().st_mode & 0o222 == 0
        result = subprocess.run([str(helpers/'git'),'http-fetch','--packfile='+'a'*40,'https://127.0.0.1/never'],env={'PATH':str(helpers),'GIT_EXEC_PATH':str(helpers),'HOME':'/nonexistent'},capture_output=True,text=True,timeout=5)
        assert result.returncode != 0 and "'http-fetch' is not a git command" in result.stderr
    real_run = module.subprocess.run
    def future_git(command, **kwargs):
        result = real_run(command, **kwargs)
        if '--list-cmds=builtins' in command:
            result.stdout += '\nhttp-fetch\n'
        return result
    monkeypatch.setattr(module.subprocess, 'run', future_git)
    with pytest.raises(module.RepositoryImportError) as refused:
        with module._restricted_git_helpers():
            pytest.fail('future network builtin must not be admitted')
    assert refused.value.code == 'repository_git_unsupported'


def test_hostile_unsolicited_v2_uri_has_no_secondary_connection_with_restricted_helpers(tmp_path):
    """Actual Git and adversarial loopback transport; no public/TLS claim."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    def packet(text):
        data = text.encode() if isinstance(text, str) else text
        return f'{len(data)+4:04x}'.encode()+data
    source = _statespec_repository(tmp_path/'uri-source')
    revision = _git(source,'rev-parse','HEAD')
    pack = subprocess.run(['git','pack-objects','--stdout','--revs'],cwd=source,input=(revision+'\n').encode(),capture_output=True,check=True).stdout
    connections = []
    requests = []
    class Trap(ThreadingHTTPServer):
        def get_request(self):
            pair = super().get_request()
            connections.append(True)
            return pair
    class TrapHandler(BaseHTTPRequestHandler):
        def handle(self): self.connection.close()
    trap = Trap(('127.0.0.1',0),TrapHandler)
    class Hostile(BaseHTTPRequestHandler):
        def do_GET(self):
            self.respond(packet('version 2\n')+packet('ls-refs\n')+packet('fetch=shallow packfile-uris\n')+b'0000','advertisement')
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length','0')))
            requests.append(body)
            if b'command=ls-refs' in body:
                response = packet(revision+' refs/heads/main\n')+b'00000002'
            else:
                response = packet('shallow-info\n')+packet('shallow '+revision+'\n')+b'0001'+packet('packfile-uris\n')+packet('a'*40+f' https://127.0.0.1:{trap.server_port}/private.pack\n')+b'0001'+packet('packfile\n')+packet(b'\x01'+pack)+b'00000002'
            self.respond(response,'result')
        def respond(self, data, kind):
            self.send_response(200)
            self.send_header('Content-Type','application/x-git-upload-pack-'+kind)
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self,*args): pass
    server = ThreadingHTTPServer(('127.0.0.1',0),Hostile)
    threads = [Thread(target=item.serve_forever,daemon=True) for item in (server,trap)]
    for thread in threads: thread.start()
    try:
        destination = tmp_path/'uri-client'
        subprocess.run(['git','init','-q',str(destination)],check=True)
        with module._restricted_git_helpers() as helpers:
            # Only this local fixture adds an HTTP name for the exact trusted
            # HTTPS helper binary; production permits HTTPS only.
            helpers.chmod(0o700)
            (helpers/'git-remote-http').symlink_to(helpers/'git-remote-https')
            helpers.chmod(0o500)
            result = subprocess.run([str(helpers/'git'),'-c','protocol.version=0','-c','fetch.uriprotocols=','-c','transfer.bundleURI=false','fetch','--depth=1','--no-tags',f'http://127.0.0.1:{server.server_port}/repo',revision],cwd=destination,env={'PATH':str(helpers),'GIT_EXEC_PATH':str(helpers),'HOME':'/nonexistent','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull},capture_output=True,text=True,timeout=5)
        assert result.returncode != 0
        assert "'http-fetch' is not a git command" in result.stderr
        assert any(b'command=fetch' in body for body in requests)
        assert not connections
    finally:
        for item in (server,trap):
            item.shutdown()
            item.server_close()
        for thread in threads: thread.join(timeout=2)


def test_git_output_limit_and_stalled_process_timeout_are_enforced(tmp_path):
    from time import monotonic
    source = _statespec_repository(tmp_path/'bounded-source')
    with pytest.raises(module.RepositoryImportError) as output_limit:
        module._remote_git(source, ['ls-tree','-rlz','HEAD'], deadline=monotonic()+5, limit=16)
    assert output_limit.value.code == 'repository_fetch_refused'
    os.mkfifo(source/'stalled-input')
    with pytest.raises(module.RepositoryImportError) as timeout:
        module._remote_git(source, ['hash-object','stalled-input'], deadline=monotonic()+0.1, limit=4096)
    assert timeout.value.code == 'repository_fetch_timeout'


def test_remote_process_home_cannot_read_host_netrc(tmp_path, monkeypatch):
    from time import monotonic
    source = _statespec_repository(tmp_path/'netrc-source')
    host_home = tmp_path/'host-home'
    host_home.mkdir()
    canary = host_home/'.netrc'
    canary.write_text('machine example.com login owner password PRIVATE_CANARY')
    monkeypatch.setenv('HOME',str(host_home))
    real_popen = module.subprocess.Popen
    observed = []
    def check_process(command, *args, **kwargs):
        environment = kwargs.get('env', {})
        if 'GIT_EXEC_PATH' in environment:
            home = Path(environment['HOME'])
            assert home != host_home
            assert str(home) == environment['GIT_EXEC_PATH'] == environment['PATH']
            assert sorted(item.name for item in home.iterdir()) == ['git','git-remote-https']
            assert not (home/'.netrc').exists()
            observed.append(True)
        return real_popen(command,*args,**kwargs)
    monkeypatch.setattr(module.subprocess,'Popen',check_process)
    module._remote_git(source,['rev-parse','HEAD'],deadline=monotonic()+5,limit=4096)
    assert observed == [True]
    assert 'PRIVATE_CANARY' in canary.read_text()


@pytest.mark.parametrize('kind', ['fifo', 'directory', 'symlink'])
def test_completed_candidate_marker_refuses_nonregular_files_without_blocking(tmp_path, monkeypatch, kind):
    from time import monotonic
    source, revision, layout, inspector, fetches = fixture(tmp_path, monkeypatch)
    inspected = inspector.inspect_public_url(URL, revision)
    marker = layout.data_root/'public-repositories'/inspected['candidateId']/'source.json'
    marker.rename(marker.with_suffix('.preserved'))
    if kind == 'fifo': os.mkfifo(marker)
    elif kind == 'directory': marker.mkdir()
    else: marker.symlink_to(marker.with_suffix('.preserved'))
    started = monotonic()
    with pytest.raises(module.RepositoryImportError) as refused:
        inspector.inspect_candidate(inspected['candidateId'])
    assert refused.value.code == 'repository_cache_unsafe'
    assert monotonic()-started < 2
    assert marker.with_suffix('.preserved').is_file()


@pytest.mark.parametrize('failure', ['nonzero', 'resource'])
def test_failed_git_parent_cannot_leave_a_descendant_helper_running(tmp_path, monkeypatch, failure):
    from time import monotonic, sleep
    import sys
    source = _statespec_repository(tmp_path/'descendant-source')
    marker = tmp_path/'child.pid'
    real_popen = module.subprocess.Popen
    def failed_parent(command, *args, **kwargs):
        if 'GIT_EXEC_PATH' in kwargs.get('env', {}):
            code = "import os,resource,subprocess,sys; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); open(sys.argv[1],'w').write(str(child.pid)); "
            code += "sys.exit(7)" if failure == 'nonzero' else "resource.setrlimit(resource.RLIMIT_FSIZE,(1,1)); os.write(1,b'fail'); os.write(1,b'fail')"
            command = [sys.executable,'-I','-c',code,str(marker)]
        return real_popen(command,*args,**kwargs)
    monkeypatch.setattr(module.subprocess,'Popen',failed_parent)
    with pytest.raises(module.RepositoryImportError) as refused:
        module._remote_git(source,['rev-parse','HEAD'],deadline=monotonic()+5,limit=4096)
    assert refused.value.code == 'repository_fetch_refused'
    child = int(marker.read_text())
    deadline = monotonic()+2
    while monotonic() < deadline:
        try:
            state = Path(f'/proc/{child}/stat').read_text().split(') ',1)[1].split()[0]
        except FileNotFoundError:
            break
        if state == 'Z': break  # terminated, awaiting its new parent's reap
        sleep(0.01)
    else:
        pytest.fail('descendant helper survived failed parent cleanup')
