#!/usr/bin/env python3
"""Run one already-booked offline build/pilot stage under the existing governor."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import shutil
import sys
import time
import re

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / 'scripts'))
from build_release_images import build_cgroup_path, governor_cgroup_parent  # noqa: E402


def containment(info: dict, container_id: str, parent: str,
                proc: Path = Path('/proc'), cgroups: Path = Path('/sys/fs/cgroup')) -> dict:
    if info.get('Id') != container_id:
        raise ValueError('container identity changed during containment observation')
    processes = {}
    for name, pid in [('init', info['State']['Pid']), ('conmon', info['State']['ConmonPid'])]:
        if type(pid) is not int or pid <= 0:
            raise ValueError(name + ' process is unavailable')
        before = (proc / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        rows = (proc / str(pid) / 'cgroup').read_text().splitlines()
        if len(rows) != 1 or not rows[0].startswith('0::/'):
            raise ValueError(name + ' has no unique unified cgroup')
        membership = rows[0][3:]
        if not (membership == parent or membership.startswith(parent + '/')):
            raise ValueError(name + ' is outside the booked governor service')
        if '..' in Path(membership).parts:
            raise ValueError('cgroup membership contains traversal')
        directory = cgroups / membership.lstrip('/')
        limits = {key: (directory / key).read_text().strip()
                  for key in ('memory.max', 'cpu.max', 'pids.max')}
        after = (proc / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        if before != after:
            raise ValueError('process identity changed during observation')
        processes[name] = {'pid': pid, 'startTimeTicks': before,
                           'cgroup': membership, 'directLimits': limits}
    ancestor = cgroups / parent.lstrip('/')
    limits = {key: (ancestor / key).read_text().strip()
              for key in ('memory.max', 'cpu.max', 'pids.max')}
    if int(limits['memory.max']) <= 0 or int(limits['cpu.max'].split()[0]) <= 0:
        raise ValueError('governor ancestor is not finitely bounded')
    return {'status': 'passed', 'containerId': container_id, 'bookedScope': parent,
            'ancestorLimits': limits, 'processes': processes}


def prepare_delegation(parent: str, output: Path, *,
                       proc: Path = Path('/proc'),
                       cgroups: Path = Path('/sys/fs/cgroup')) -> None:
    """Enable child controls inside this command's already bounded service.

    A delegated domain must have no direct processes before its domain
    controllers can be enabled. Move only this owned service's direct tasks
    into its runtime child; never move anything outside the booked service or
    alter the aggregate service limits. Podman otherwise creates payload
    children without memory/cpu/pids control files on this host.
    """
    observed_parent = governor_cgroup_parent(
        proc_cgroup=proc / 'self/cgroup', cgroup_root=cgroups)
    if observed_parent != parent:
        raise ValueError('delegation does not match the current governor service')
    directory = cgroups / parent.lstrip('/')
    required = {'cpu', 'memory', 'pids'}
    available = set((directory / 'cgroup.controllers').read_text().split())
    if not required <= available:
        raise ValueError('governor lacks required delegated controllers')
    limit_names = ('memory.max', 'memory.high', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (directory / name).read_text().strip() for name in limit_names}
    if not limits['pids.max'].isdigit() or int(limits['pids.max']) <= 0:
        raise ValueError('governor has no finite process limit')
    enabled_before = (directory / 'cgroup.subtree_control').read_text().split()
    runtime = directory / 'runtime'
    if runtime.is_symlink():
        raise ValueError('governor runtime subgroup cannot be a symlink')
    runtime.mkdir(exist_ok=True)
    moved = []
    for _ in range(3):
        pids = (directory / 'cgroup.procs').read_text().split()
        if not pids:
            break
        for pid in pids:
            if not pid.isdigit() or int(pid) <= 0:
                raise ValueError('invalid direct governor process identity')
            try:
                membership = (proc / pid / 'cgroup').read_text().strip()
                if membership != '0::' + parent:
                    raise ValueError('direct process changed cgroup during delegation')
                (runtime / 'cgroup.procs').write_text(pid)
                moved.append(int(pid))
            except (ProcessLookupError, FileNotFoundError):
                # An exited process needs no move. A live process or missing
                # subgroup control is a real failure, not a waived race.
                if (proc / pid).exists():
                    raise
    if (directory / 'cgroup.procs').read_text().strip():
        raise ValueError('governor still has direct processes; child controls unavailable')
    wanted = required | ({'io'} if 'io' in available else set())
    (directory / 'cgroup.subtree_control').write_text(
        ' '.join('+' + name for name in sorted(wanted)))
    enabled = set((directory / 'cgroup.subtree_control').read_text().split())
    if not wanted <= enabled:
        raise ValueError('governor child controllers did not become available')
    if limits != {name: (directory / name).read_text().strip() for name in limit_names}:
        raise ValueError('governor aggregate limits changed during delegation')
    (output / 'delegation.json').write_text(json.dumps({
        'status': 'passed', 'bookedScope': parent, 'movedDirectPids': moved,
        'enabledBefore': enabled_before, 'enabledAfter': sorted(enabled),
        'unchangedAncestorLimits': limits,
    }, indent=2) + '\n')


def observed_native(command: list[str], output: Path, parent: str, log) -> int:
    try:
        prepare_delegation(parent, output)
    except Exception as error:
        (output / 'containment-failure.json').write_text(json.dumps({
            'status': 'failed', 'error': str(error),
            'nativeCompilation': 'not admitted; delegation failed before launch',
        }) + '\n')
        return 1
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    cidfile = output / 'container-id'
    cid = None
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if cidfile.exists():
                cid = cidfile.read_text().strip()
                if re.fullmatch(r'[0-9a-f]{64}', cid) is None:
                    raise ValueError('unexpected container identity')
                observed = subprocess.run(['/usr/bin/podman', 'inspect', '--format', '{{json .}}', cid],
                                          capture_output=True, text=True, timeout=10, check=False)
                if observed.returncode == 0:
                    info = json.loads(observed.stdout)
                    if info.get('State', {}).get('Running'):
                        proof = containment(info, cid, parent)
                        (output / 'containment.json').write_text(json.dumps(proof, indent=2) + '\n')
                        # The container waits before hashing/extracting inputs or compiling.
                        with (output / 'work/containment-approved.json').open('x') as gate:
                            gate.write(json.dumps(proof) + '\n')
                        return process.wait()
            if process.poll() is not None:
                raise ValueError('container exited before containment was measured')
            time.sleep(0.1)
        raise ValueError('timed out waiting for container containment observation')
    except Exception as error:
        (output / 'containment-failure.json').write_text(json.dumps({'status': 'failed', 'error': str(error),
            'containerId': cid, 'nativeCompilation': 'not admitted'}) + '\n')
        if cid is not None:
            subprocess.run(['/usr/bin/podman', 'stop', '--time=2', cid],
                           stdout=log, stderr=subprocess.STDOUT, timeout=15, check=False)
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['builder', 'native'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--vendor-inputs', type=Path)
    parser.add_argument('--resume-run', type=Path)
    parser.add_argument('--correspondence-receipt', type=Path)
    parser.add_argument('--image-id-file', type=Path)
    parser.add_argument('--timeout-seconds', type=int, default=1500)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 21600:
        parser.error('pilot timeout must be between 1 and 21600 seconds')
    parent = governor_cgroup_parent()
    output = args.output.resolve()
    resume_admission = None
    if bool(args.resume_run) != bool(args.correspondence_receipt):
        parser.error('--resume-run and --correspondence-receipt must be supplied together')
    if args.stage != 'native' and args.resume_run:
        parser.error('only the native stage supports an admitted cache')
    if args.stage == 'native':
        if args.inputs is None or args.vendor_inputs is None or args.image_id_file is None:
            parser.error('native requires --inputs, --vendor-inputs and --image-id-file')
        image = args.image_id_file.read_text().strip()
        if re.fullmatch(r'sha256:[0-9a-f]{64}', image) is None:
            raise ValueError('builder image identity must be an exact SHA-256')
        inputs = args.inputs.resolve(strict=True)
        vendor_inputs = args.vendor_inputs.resolve(strict=True)
        resume_run = args.resume_run.absolute() if args.resume_run else None
        if not inputs.is_dir() or not vendor_inputs.is_dir():
            raise ValueError('input mounts must be existing directories')
        if any(',' in str(path) for path in (inputs, vendor_inputs, output)):
            raise ValueError('mount paths cannot contain commas')
        if resume_run is not None:
            from pilot import validate_resume_admission, sha256
            receipt_path = args.correspondence_receipt.absolute()
            if any(',' in str(path) for path in (resume_run, receipt_path, HERE)):
                raise ValueError('resume mount paths cannot contain commas')
            resume_admission = validate_resume_admission(receipt_path, resume_run, inputs,
                vendor_inputs, sha256(HERE / 'verify_cached_work.py'), sha256(HERE / 'recipe.json'), image)
            target = resume_run / 'work/target'
            if target.is_symlink() or not target.is_dir():
                raise ValueError('cached target must be a real directory')
    output.mkdir(parents=False, exist_ok=False)
    if args.stage == 'builder':
        context = output / 'context'
        shutil.copytree(HERE, context / 'config/codex-runtime/v8-repair',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        command = ['/usr/bin/podman', '--cgroup-manager=cgroupfs', 'build',
                   '--cgroup-parent', build_cgroup_path(parent, digest_file=output / 'image-id'),
                   '--pull=never', '--network=none', '--no-cache', '--layers=false',
                   '--timestamp=1788250972', '--iidfile', str(output / 'image-id'),
                   '-f', str(context / 'config/codex-runtime/v8-repair/Containerfile'), str(context)]
    else:
        work = output / 'work'
        work.mkdir()
        command = ['/usr/bin/podman', '--cgroup-manager=cgroupfs', 'run',
                   # Place the payload directly below the delegated service.
                   # split nests it below the occupied runtime subgroup, where
                   # child controller files are not reliably available. conmon
                   # stays in runtime and is checked by observed_native too.
                   '--pull=never', '--cgroups=no-conmon', '--cgroup-parent', parent,
                   '--network=none',
                   '--cidfile', str(output / 'container-id'),
                   '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                   '--pids-limit=256', '--cpus=1', '--memory=3g', '--memory-swap=3g',
                   '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
                   '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                   '--mount', f'type=bind,src={vendor_inputs},dst=/vendor-inputs,ro',
                   '--mount', f'type=bind,src={work},dst=/work,rw',
                   ]
        if resume_admission is not None:
            admission_path = output / 'resume-admission.json'
            with admission_path.open('x') as stream:
                stream.write(json.dumps(resume_admission, indent=2) + '\n')
            command += ['--mount', f'type=bind,src={resume_run},dst=/cached-run,ro']
            command += ['--mount', f'type=bind,src={receipt_path},dst=/correspondence-receipt.json,ro']
            command += ['--mount', f'type=bind,src={admission_path},dst=/resume-admission.json,ro']
            command += ['--mount', f'type=bind,src={HERE / "pilot.py"},dst=/opt/stateport-v8-repair/pilot.py,ro']
            command += ['--mount', f'type=bind,src={HERE / "verify_cached_work.py"},dst=/opt/stateport-v8-repair/verify_cached_work.py,ro']
        command += [image, f'--timeout-seconds={args.timeout_seconds}', '--require-containment']
        if resume_admission is not None:
            command += ['--resume-admission', '/resume-admission.json']
    from prepare import sha256
    (output / 'command.json').write_text(json.dumps({'command': command, 'governorCgroup': parent,
        'pilotSha256': sha256(HERE / 'pilot.py'), 'runnerSha256': sha256(Path(__file__)),
        'resumeAdmission': resume_admission}, indent=2) + '\n')
    with (output / 'run.log').open('xb') as log:
        code = (observed_native(command, output, parent, log) if args.stage == 'native' else
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False).returncode)
    (output / 'stage-receipt.json').write_text(json.dumps({'exitCode': code,
        'stage': args.stage, 'releaseQualification': 'not_run'}) + '\n')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
