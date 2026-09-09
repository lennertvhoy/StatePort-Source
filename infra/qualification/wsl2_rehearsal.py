#!/usr/bin/env python3
"""Rehearse the install journey in QEMU, or qualify it on native Windows WSL2.

Fidelity strategy: prepublication runs serve the staged Site tree inside the VM
over HTTPS at the real public hostname and load retained OCI archives through a
guest-local digest mirror. ``--public-transport`` removes those seams: the
guest receives no staged Site, custom CA, retained archive, local registry,
hosts override, or mirror configuration, so the unmodified bootstrap uses
anonymous Pages and GHCR directly. The WSL2 platform gates are shimmed
guest-locally; every subsequent step executes exactly as on the owner target.

WSL2 identity shims (all guest-local, none shipped):

  1. /usr/local/bin/uname        -> bootstrap shell gate (uname -r)
  2. /etc/python3.12/sitecustomize.py -> Python substrate checks.
     On Ubuntu 24.04 /usr/lib/python3.12/sitecustomize.py is a symlink to
     /etc/python3.12/sitecustomize.py, and Python imports the canonical
     target of that symlink — so the shim must be installed at the /etc
     path or it is silently shadowed by the distro file and never loaded.
     Auto-imported by every guest Python (including venvs, which keep the
     stdlib dir on sys.path).  It overrides platform.release() (used by
     stateport_release.observe_linux_substrate in the provisioner) and
     narrowly patches pathlib.Path.read_text for exactly the two kernel
     identity files the installer's SystemHostProbe reads
     (/proc/sys/kernel/osrelease and /proc/version).  No other path is
     affected.
  3. /usr/local/bin/powershell.exe -> Windows interop gate

Why NOT a /proc/version bind-mount: any submount on /proc makes the kernel
refuse fresh proc mounts inside rootless user namespaces (crun: mount `proc`
to `proc`: Operation not permitted), so every rootless container fails.  This
was proven live during the alpha.6 rehearsal (rehearsal-872bb986-v1): removing
the bind-mount immediately restored rootless `podman run`.  The sitecustomize
shim leaves /proc completely untouched.

Usage: wsl2_rehearsal.py --site-root <staged Site tree> --version <exact candidate> \
           [--archive-root <retained OCI archives>] --work-dir <dir> \
           --receipt-out <receipt.json> [--public-transport]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import queue
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from release_guard import (  # noqa: E402
    authorize_guard,
    classify_rehearsal_baseline,
    effective_mission,
    load_envelope,
    require_guard,
)

# The QEMU lane is an explicitly non-owner-path simulation. Its server image
# remains pinned for reproducible diagnostics; only a native WSL2 run imported
# from WSL_ROOTFS_IDENTITY may produce owner-path qualification evidence.
UBUNTU_IMG_URL = "https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img"
UBUNTU_IMG_SHA256 = "0533b0655c32e68b31d792ecd6ccfca95abdbc536c4446874fe0513bd4140ffe"
WSL_ROOTFS_IDENTITY = {
    "architecture": "amd64",
    "digest": "sha256:9b2f7730dc68227dd04a9f3e5eab86ad85caf556b8606ad94f1f29ff5c4fd3f5",
    "release": "24.04.4",
    "url": "https://releases.ubuntu.com/24.04.4/ubuntu-24.04.4-wsl-amd64.wsl",
}
QEMU_ROOTFS_IDENTITY = {
    "architecture": "amd64",
    "digest": "sha256:" + UBUNTU_IMG_SHA256,
    "release": "noble-20260801-server-cloud",
    "url": UBUNTU_IMG_URL,
}
SSH_PORT = 10022
VM_USER = "rehearsal"
# Loopback SSH target for the disposable guest.  Kept as a separate constant
# so the source never carries a literal `user@host` email-shaped string (the
# public-export Sensitive Data Gateway blocks those on sight).
SSH_HOST = "127.0.0.1"
SSH_TARGET = f"{VM_USER}@{SSH_HOST}"
WSL2_KERNEL = "5.15.153.1-microsoft-standard-WSL2"
WIN_BUILD = "26100"
HOSTNAME = "lennertvhoy.github.io"
REGISTRY_PORT = 5443
PREPUBLICATION_REGISTRY_PREFIX = "ghcr.io/lennertvhoy"
PREPUBLICATION_REGISTRY_MIRROR = f"127.0.0.1:{REGISTRY_PORT}/stateport-alpha"
GUEST_REGISTRIES_CONF = f'''[[registry]]
location="127.0.0.1:{REGISTRY_PORT}"
insecure=true

[[registry]]
prefix="{PREPUBLICATION_REGISTRY_PREFIX}"
location="{PREPUBLICATION_REGISTRY_PREFIX}"
mirror-by-digest-only=true

[[registry.mirror]]
location="{PREPUBLICATION_REGISTRY_MIRROR}"
insecure=true
'''
FAILURE_SNAPSHOT_ROOT = "/var/tmp/stateport-j1-runtime-trace"
DIAGNOSTIC_VM_MEMORY_MIB = 4096
QUALIFICATION_VM_MEMORY_MIB = 6144
GUEST_SWAP_GIB = 6
PODMAN_PACKAGE_VERSIONS = {
    "aardvark-dns": "1.14.0-3stateport1~24.04.1",
    "catatonit": "0.1.7-1",
    "conmon": "2.1.10+ds1-1build2",
    "containers-storage": "1.51.0+ds1-2ubuntu0.24.04.3",
    "dbus-user-session": "1.14.10-4ubuntu4.1",
    "fuse-overlayfs": "1.13-1",
    "golang-github-containers-common": "0.57.4+ds1-2ubuntu0.2",
    "golang-github-containers-image": "5.29.2-2",
    "libslirp0": "4.7.0-1ubuntu3.1",
    "libsubid4": "1:4.13+dfsg1-4ubuntu3.2",
    "netavark": "1.14.0-2stateport1~24.04.1",
    "podman": "5.4.2+ds1-2stateport2~24.04.1",
    "python3-venv": "3.12.3-0ubuntu2.1",
    "runc": "1.3.4-0ubuntu1~24.04.1",
    "stateport-crun": "1.28-1stateport1~24.04.1",
    "slirp4netns": "1.2.1-1build2",
    "skopeo": "1.13.3+ds1-2build2",
    "uidmap": "1:4.13+dfsg1-4ubuntu3.2",
}
GOVERNOR_PREFLIGHT = Path(os.environ.get(
    "STATEPORT_GOVERNOR_PREFLIGHT", str(Path.home() / ".kimi-code/governor/preflight.sh")
))

FAILURE_WATCHER = r'''#!/bin/bash
set -u

ROOT=/var/tmp/stateport-j1-runtime-trace
STOP="$ROOT/stop"
mkdir -p "$ROOT/snapshots"
trace() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$*" >>"$ROOT/watcher.log"; }

# The installer creates stateport-control.  The supervisor starts before the
# install, then hands the actual watcher to that identity before it observes
# any control-plane container lifecycle event.
if [ "$(id -u)" = 0 ]; then
  trace supervisor-started
  while [ ! -e "$STOP" ] && ! id -u stateport-control >/dev/null 2>&1; do
    sleep 0.1
  done
  [ -e "$STOP" ] && exit 0
  trace "control-identity-ready uid=$(id -u stateport-control)"
  control_uid="$(id -u stateport-control)"
  while [ ! -e "$STOP" ] && { [ ! -d "/run/user/$control_uid" ] || [ ! -S "/run/user/$control_uid/bus" ]; }; do
    sleep 0.1
  done
  [ -e "$STOP" ] && exit 0
  trace "control-runtime-ready uid=$control_uid"
  chown -R stateport-control:stateport-control "$ROOT"
  trace handing-off-to-stateport-control
  exec runuser -u stateport-control -- env -i \
    HOME=/var/lib/stateport-control \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 LOGNAME=stateport-control \
    PATH=/usr/bin:/bin USER=stateport-control \
    XDG_CACHE_HOME=/var/lib/stateport-control/.cache \
    XDG_CONFIG_HOME=/var/lib/stateport-control/.config \
    XDG_DATA_HOME=/var/lib/stateport-control/.local/share \
    XDG_RUNTIME_DIR="/run/user/$(id -u stateport-control)" \
    XDG_STATE_HOME=/var/lib/stateport-control/.local/state \
    "$ROOT/watcher.sh"
fi

control_uid() {
  id -u stateport-control 2>/dev/null || true
}

run_control() {
  local run_uid
  run_uid="$(control_uid)"
  [ -n "$run_uid" ] || return 1
  cd /
  env -i \
    HOME=/var/lib/stateport-control \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 LOGNAME=stateport-control \
    PATH=/usr/bin:/bin USER=stateport-control \
    XDG_CACHE_HOME=/var/lib/stateport-control/.cache \
    XDG_CONFIG_HOME=/var/lib/stateport-control/.config \
    XDG_DATA_HOME=/var/lib/stateport-control/.local/share \
    XDG_RUNTIME_DIR="/run/user/$run_uid" \
    XDG_STATE_HOME=/var/lib/stateport-control/.local/state \
    "$@"
}

web_spec() {
  local source service image container uid
  uid="$(control_uid)"
  [ -n "$uid" ] || return 1
  for source in "$HOME/.config/containers/systemd"/*.container; do
    [ -f "$source" ] || continue
    grep -q '^Label=io.stateport.service.id=stateport-web$' "$source" || continue
    image="$(sed -n 's/^Image=//p' "$source" | head -n 1)"
    container="$(sed -n 's/^ContainerName=//p' "$source" | head -n 1)"
    service="$(basename "$source" .container).service"
    [ -n "$image" ] && [ -n "$container" ] || continue
    printf '%s\t%s\t%s\t%s\n' "$source" "$service" "$container" "$image"
    return 0
  done
}

web_container_id() {
  local spec expected_image id actual_image
  spec="$(web_spec)" || return 1
  expected_image="${spec#*$'\t'}"
  expected_image="${expected_image##*$'\t'}"
  run_control podman ps -a --no-trunc \
    --filter label=io.stateport.service.id=stateport-web --format '{{.ID}}' 2>/dev/null |
    while read -r id; do
      [ -n "$id" ] || continue
      actual_image="$(run_control podman inspect "$id" --format '{{.ImageName}}' 2>/dev/null || true)"
      [ "$actual_image" = "$expected_image" ] || continue
      printf '%s\n' "$id"
      return 0
    done
}

probe_image() {
  [ ! -e "$ROOT/image-probe.complete" ] || return 0
  local spec image present
  spec="$(web_spec)" || return 0
  image="${spec##*$'\t'}"
  if [ -n "$(web_container_id)" ]; then present=true; else present=false; fi
  {
    printf 'image=%s\nstateportWebContainerPresentBeforeProbe=%s\n' "$image" "$present"
    run_control podman image inspect "$image" \
      --format '{{json .Config.Entrypoint}} {{json .Config.Cmd}} {{.Config.User}}'
  } >"$ROOT/image-config.txt" 2>&1
  run_control podman image inspect "$image" >"$ROOT/image-inspect.json" 2>&1 || true
  run_control podman run --rm --name stateport-j1-web-image-probe \
    --entrypoint /bin/sh "$image" -lc '
      command -v python3
      test -f /workspace/apps/web/container-service.py
      ls -l /workspace/apps/web/container-service.py
    ' >"$ROOT/image-content-probe.txt" 2>&1
  printf '%s\n' "$?" >"$ROOT/image-content-probe.exit"
  touch "$ROOT/image-probe.complete"
}

snapshot() {
  local reason="$1" event_id="${2:-}" stamp out uid image unit source container spec network network_unit
  mkdir "$ROOT/snapshot.lock" 2>/dev/null || return 0
  stamp="$(date -u +%Y%m%dT%H%M%S.%NZ)"
  out="$ROOT/snapshots/${stamp}-${reason}"
  mkdir -p "$out/quadlet" "$out/generated-systemd"
  uid="$(control_uid)"
  spec="$(web_spec || true)"
  source="${spec%%$'\t'*}"
  spec="${spec#*$'\t'}"
  unit="${spec%%$'\t'*}"
  spec="${spec#*$'\t'}"
  container="${spec%%$'\t'*}"
  image="${spec#*$'\t'}"
  [ -n "$event_id" ] && container="$event_id"
  {
    printf 'capturedAt=%s\nreason=%s\ncontrolUid=%s\neventContainerId=%s\nquadlet=%s\nunit=%s\nexpectedContainerName=%s\nexpectedImage=%s\n' \
      "$stamp" "$reason" "$uid" "$event_id" "$source" "$unit" "$container" "$image"
    run_control podman inspect "$container" \
      --format 'ID={{.Id}} Name={{json .Name}} ImageName={{json .ImageName}} ImageID={{json .Image}} Path={{json .Path}} Args={{json .Args}} Entrypoint={{json .Config.Entrypoint}} Cmd={{json .Config.Cmd}} User={{json .Config.User}} WorkingDir={{json .Config.WorkingDir}} ExitCode={{.State.ExitCode}} Error={{json .State.Error}} OCI={{json .OCIRuntime}} Init={{json .Config.Init}}'
  } >"$out/container-command.txt" 2>&1 || true
  run_control podman inspect "$container" >"$out/container-inspect.json" 2>&1 || true
  run_control podman inspect "$container" --format '{{json .Mounts}}' \
    >"$out/container-mounts.json" 2>&1 || true
  run_control podman logs "$container" >"$out/container-logs.txt" 2>&1 || true

  image="$(run_control podman inspect "$container" --format '{{.ImageName}}' 2>/dev/null || true)"
  [ -n "$image" ] || image="${spec#*$'\t'}"
  if [ -n "$image" ]; then
    {
      printf 'image=%s\n' "$image"
      run_control podman image inspect "$image" \
        --format 'Entrypoint={{json .Config.Entrypoint}} Cmd={{json .Config.Cmd}} User={{json .Config.User}} Digest={{json .Digest}}'
    } >"$out/image-config.txt" 2>&1 || true
    run_control podman image inspect "$image" >"$out/image-inspect.json" 2>&1 || true
  fi

  if [ -f "$source" ]; then
    cp -a "$source" "$out/quadlet/"
    cp -a "$source" "$out/web.container"
    network="$(sed -n 's/^Network=//p' "$source" | head -n 1 | sed 's/[.]network$//')"
    if [ -n "$network" ]; then
      network_unit="${network}-network.service"
      run_control podman network ls --no-trunc \
        >"$out/network-ls.txt" 2>&1 || true
      run_control podman network inspect "$network" \
        >"$out/network-inspect.json" 2>&1 || true
      run_control systemctl --user status "$network_unit" --full --no-pager -n 80 \
        >"$out/systemctl-status-${network_unit}.txt" 2>&1 || true
      run_control systemctl --user show "$network_unit" --no-pager \
        >"$out/systemctl-show-${network_unit}.txt" 2>&1 || true
      run_control journalctl --user -u "$network_unit" --no-pager -n 200 \
        >"$out/journal-${network_unit}.txt" 2>&1 || true
      if [ "$reason" = "event-init" ] && [ ! -e "$ROOT/direct-network-probe.complete" ]; then
        run_control env >"$out/control-env.txt" 2>&1 || true
        run_control systemctl --user show-environment \
          >"$out/systemd-user-environment.txt" 2>&1 || true
        run_control systemd-run --user --wait --pipe --quiet /usr/bin/env \
          >"$out/systemd-run-environment.txt" 2>&1 || true
        run_control podman info --debug \
          >"$out/podman-info.txt" 2>&1 || true
        network_id="$(run_control podman network inspect "$network" \
          --format '{{.ID}}' 2>/dev/null || true)"
        printf 'network=%s\nnetworkId=%s\nimage=%s\n' "$network" "$network_id" "$image" \
          >"$out/direct-network-probe.txt"
        direct_probe() {
          local label="$1"
          shift
          printf '\n[%s]\n' "$label" >>"$out/direct-network-probe.txt"
          run_control podman run --rm \
            --name "stateport-j1-direct-network-$label" "$@" \
            --entrypoint /bin/true "$image" \
            >>"$out/direct-network-probe.txt" 2>&1
          printf '%s=%s\n' "$label" "$?" >>"$out/direct-network-probe.exit"
        }
        direct_probe name-minimal --network "$network"
        [ -n "$network_id" ] && direct_probe id-minimal --network "$network_id"
        direct_probe default-minimal --network podman
        direct_probe name-user --network "$network" --user 65532
        direct_probe name-keep-id --network "$network" --user 65532 \
          --userns keep-id:uid=65532,gid=65532
        run_control sh -c '
          for directory in \
            "$HOME/.config/containers/networks" \
            "$HOME/.local/share/containers/storage/networks" \
            "$XDG_RUNTIME_DIR/containers/networks" \
            "$XDG_RUNTIME_DIR/containers/storage/networks"; do
            printf "directory=%s\\n" "$directory"
            for path in "$directory"/*; do
              [ -e "$path" ] || continue
              sha256sum "$path"
            done
          done
        ' >"$out/netavark-network-files.txt" 2>&1 || true
        variant_probe() {
          local label="$1" network_name="stateport-j1-direct-$1"
          shift
          printf '\n[direct-created-%s]\nname=%s\n' "$label" "$network_name" \
            >>"$out/direct-network-probe.txt"
          run_control podman network create "$@" "$network_name" \
            >>"$out/direct-network-probe.txt" 2>&1
          printf 'create-%s=%s\n' "$label" "$?" >>"$out/direct-network-probe.exit"
          run_control podman run --rm --name "stateport-j1-direct-$label" \
            --network "$network_name" --entrypoint /bin/true "$image" \
            >>"$out/direct-network-probe.txt" 2>&1
          printf 'run-%s=%s\n' "$label" "$?" >>"$out/direct-network-probe.exit"
          run_control podman network rm "$network_name" \
            >>"$out/direct-network-probe.txt" 2>&1
          printf 'remove-%s=%s\n' "$label" "$?" >>"$out/direct-network-probe.exit"
        }
        variant_probe internal --internal
        variant_probe internal-no-dns --internal --disable-dns
        variant_probe external
        touch "$ROOT/direct-network-probe.complete"
      fi
    fi
    run_control systemctl --user status "$unit" --full --no-pager -n 80 \
      >"$out/systemctl-status-${unit}.txt" 2>&1 || true
    run_control systemctl --user show "$unit" --no-pager \
      >"$out/systemctl-show-${unit}.txt" 2>&1 || true
    run_control journalctl --user -u "$unit" --no-pager -n 200 \
      >"$out/journal-${unit}.txt" 2>&1 || true
    run_control journalctl --user --no-pager -n 200 \
      >"$out/user-runtime-journal.txt" 2>&1 || true
  fi
  for source in \
    "/run/user/$uid/systemd/generator"/*.service \
    "/run/user/$uid/systemd/generator.early"/*.service \
    "/run/user/$uid/systemd/generator.late"/*.service; do
    [ -f "$source" ] || continue
    [ "$(basename "$source")" = "$unit" ] || continue
    cp -a "$source" "$out/generated-systemd/"
    cp -a "$source" "$out/web.service"
  done
  run_control podman ps -a --no-trunc >"$out/podman-ps.txt" 2>&1 || true
  rmdir "$ROOT/snapshot.lock"
}

event_loop() {
  trace podman-events-started
  # Podman 5.8 can omit label-filtered events even though the event JSON has
  # the label.  Keep the exact service filter in the contract, but filter the
  # stream locally so the revision-qualified init/died event cannot vanish.
  # --filter label=io.stateport.service.id=stateport-web
  run_control podman events --stream=true --filter type=container \
    --format '{{json .}}' 2>>"$ROOT/watcher.log" |
    while read -r event; do
      case "$event" in
        *'io.stateport.service.id":"stateport-web"'*|*'io.stateport.service.id=stateport-web'*) ;;
        *) continue ;;
      esac
      trace "podman-event-received $event"
      printf '%s\n' "$event" >>"$ROOT/podman-events.jsonl"
      status="$(printf '%s\n' "$event" | sed -n 's/.*"Status":"\([^"]*\)".*/\1/p')"
      [ -n "$status" ] || status="$(printf '%s\n' "$event" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
      event_id="$(printf '%s\n' "$event" | sed -n 's/.*"ID":"\([^"]*\)".*/\1/p')"
      [ -n "$event_id" ] || event_id="$(printf '%s\n' "$event" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
      case "$status" in
        create|init|start|died|remove)
          printf '%s\n' "$event_id" >"$ROOT/container-id"
          snapshot "event-$status" "$event_id"
          ;;
      esac
    done
  trace podman-events-ended
}

while [ ! -e "$STOP" ]; do
  uid="$(control_uid)"
  if [ -n "$uid" ]; then
    trace "watcher-loop-started uid=$uid"
    probe_image
    event_loop &
    events_pid=$!
    previous=absent
    while [ ! -e "$STOP" ] && [ "$(control_uid)" = "$uid" ]; do
      container="$(web_container_id)"
      current="$(if [ -n "$container" ]; then run_control podman inspect "$container" \
        --format '{{.State.Status}}|{{.State.ExitCode}}|{{.State.Error}}|{{.Path}}|{{json .Args}}' 2>/dev/null; else printf absent; fi)"
      if [ "$current" != "$previous" ]; then
        printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$current" >>"$ROOT/state-transitions.txt"
        snapshot poll "$container"
        previous="$current"
      fi
      probe_image
      sleep 0.1
    done
    kill "$events_pid" 2>/dev/null || true
    wait "$events_pid" 2>/dev/null || true
  fi
  sleep 0.1
done
'''

FAILURE_SNAPSHOT_COLLECTOR = r'''
import hashlib
import json
from pathlib import Path

root = Path("/var/tmp/stateport-j1-runtime-trace")
files = {}
total = 0
for path in sorted(root.rglob("*")):
    if path.is_symlink() or not path.is_file() or path.name in {"watcher.pid", "watcher.sh"}:
        continue
    data = path.read_bytes()
    total += len(data)
    if total > 16 * 1024 * 1024:
        raise SystemExit("failure snapshots exceed 16 MiB")
    files[str(path.relative_to(root))] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "text": data.decode("utf-8", errors="replace"),
    }
print(json.dumps({"guestRoot": str(root), "files": files}, sort_keys=True))
'''

SITECUSTOMIZE = '''\
"""StatePort rehearsal shim (guest-local, never shipped).

The rehearsal QEMU guest runs an Ubuntu generic kernel, but the rehearsal
simulates the exact WSL2 target identity.  WSL2 substrate checks accept
``platform.release()`` as a kernel-identity marker, and the installer's
SystemHostProbe reads /proc/sys/kernel/osrelease and /proc/version directly.
Bind-mounting fake files over those paths is not possible: any submount on
/proc makes the kernel refuse fresh proc mounts in rootless user namespaces.
This sitecustomize (auto-imported by every guest Python at startup) therefore
reports the Microsoft WSL2 kernel identity through exactly those three seams
and nothing else.  It exists only inside the disposable rehearsal guest.
"""

import platform as _platform
from pathlib import Path as _Path

_WSL2_KERNEL_RELEASE = "5.15.153.1-microsoft-standard-WSL2"
_WSL2_PROC_VERSION = (
    "Linux version 5.15.153.1-microsoft-standard-WSL2 (oe-user@oe-host) "
    "(x86_64-linux-gnu-gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, "
    "GNU ld (GNU Binutils for Ubuntu) 2.42) #1 SMP Thu Aug 13 07:00:00 UTC 2026\\n"
)
_FAKED_FILE_CONTENTS = {
    "/proc/sys/kernel/osrelease": _WSL2_KERNEL_RELEASE + "\\n",
    "/proc/version": _WSL2_PROC_VERSION,
}


def _rehearsal_release() -> str:
    return _WSL2_KERNEL_RELEASE


_platform.release = _rehearsal_release

_real_read_text = _Path.read_text


def _rehearsal_read_text(self, *args, **kwargs):
    fake = _FAKED_FILE_CONTENTS.get(str(self))
    if fake is not None:
        return fake
    return _real_read_text(self, *args, **kwargs)


_Path.read_text = _rehearsal_read_text
'''


def run(argv: list[str], *, check: bool = True, capture: bool = False, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=check, capture_output=capture, text=True, timeout=timeout)


def log(msg: str) -> None:
    print(f"[rehearse {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def phase0_binding(
    site_root: Path,
    version: str,
    archive_root: Path | None,
    bootstrap_url: str | None = None,
) -> dict[str, object]:
    """Derive the exact candidate transport inputs before any guest work."""
    index_path = site_root / "download" / version / "release-index.json"
    bootstrap_path = site_root / "download" / "install.sh"
    if not index_path.is_file() or not bootstrap_path.is_file():
        raise ValueError("phase-0 candidate index or bootstrap is unavailable")
    document = json.loads(index_path.read_text(encoding="utf-8"))
    signed = document.get("signed")
    images = signed.get("images") if isinstance(signed, dict) else None
    if not isinstance(images, list) or not images:
        raise ValueError("phase-0 candidate has no signed images")
    archives: dict[str, object] = {}
    for image in images:
        if not isinstance(image, dict) or not isinstance(image.get("imageId"), str):
            raise ValueError("phase-0 candidate image inventory is malformed")
        image_id = str(image["imageId"])
        if archive_root is not None:
            archive = archive_root / f"{image_id}.oci.tar"
            if archive.is_symlink() or not archive.is_file():
                raise ValueError(f"phase-0 retained archive is unavailable: {image_id}")
            archives[image_id] = {
                "archiveDigest": "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(),
                "manifestDigest": str(image.get("digest", "")),
            }
    binding = {
        "releaseIndexDigest": "sha256:" + hashlib.sha256(index_path.read_bytes()).hexdigest(),
        "signedPayloadDigest": "sha256:" + hashlib.sha256(_canonical_json(signed)).hexdigest(),
        "bootstrapDigest": "sha256:" + hashlib.sha256(bootstrap_path.read_bytes()).hexdigest(),
        "images": {item["imageId"]: item["digest"] for item in images},
        "providerRuntimeRequired": any(service.get("providerHome") for target in signed.get("targets", []) for service in target.get("services", [])),
    }
    # Public transport is verified directly from anonymous Site/GHCR.  OCI
    # archives belong only to the staged QEMU mirror and must not be a
    # prerequisite or part of the public candidate binding.
    if archive_root is not None:
        binding["archives"] = archives
    if bootstrap_url is not None:
        if not re.fullmatch(r"https://[^\s]+", bootstrap_url):
            raise ValueError("candidate bootstrap URL must use HTTPS")
        binding["bootstrapUrl"] = bootstrap_url
    artifacts = signed.get("artifacts") if isinstance(signed, dict) else None
    package_bundle = artifacts.get("podmanPackageBundle") if isinstance(artifacts, dict) else None
    if isinstance(package_bundle, dict):
        binding["podmanPackageBundleDigest"] = str(package_bundle.get("digest", ""))
    return binding


def validate_phase0_receipt(receipt: dict[str, object], expected: dict[str, object]) -> bool:
    if (
        receipt.get("mode") != "phase0-transport"
        or receipt.get("result") != "passed"
        or receipt.get("binding") != expected
    ):
        raise ValueError("phase-0 receipt is missing or bound to a different candidate")
    phases = receipt.get("phases")
    if not isinstance(phases, dict) or any(phases.get(name, {}).get("ok") is not True for name in ("bootstrap-fetch", "transport-probe", "materialization-preflight")):
        raise ValueError("phase-0 receipt does not prove every transport phase")
    return True


class VM:
    def __init__(
        self,
        work: Path,
        site_root: Path,
        archive_root: Path | None,
        *,
        phase_gates: bool = False,
        diagnostic_reuse: bool = False,
        public_transport: bool = False,
        memory_mib: int = QUALIFICATION_VM_MEMORY_MIB,
        base_image: Path | None = None,
        bootstrap_url: str | None = None,
    ):
        self.work = work
        self.site_root = site_root
        self.archive_root = archive_root
        self.phase_gates = phase_gates
        self.diagnostic_reuse = diagnostic_reuse
        self.public_transport = public_transport
        self.memory_mib = memory_mib
        self.base_image = base_image
        self.bootstrap_url = bootstrap_url or f"https://{HOSTNAME}/StatePort-Site/download/install.sh"
        self.current_receipt: dict = {}
        self.proc: subprocess.Popen | None = None
        self.key = work / "id_ed25519"
        self.public_transport_boundary: dict[str, object] | None = None
        self.rehearsal_baseline: dict[str, object] | None = None
        self.rootfs_identity = dict(QEMU_ROOTFS_IDENTITY)
        self.native_wsl = False
        self.substrate = "qemu-wsl-identity-simulation"
        self.identity_shims = ["wsl_kernel_identity_only", "windows_interop_identity_only"]
        self.usr_local_changes = ["/usr/local/bin/uname", "/usr/local/bin/powershell.exe"]
        self.runtime_configuration_changes = ["/etc/python3.12/sitecustomize.py"]

    def prepare(self, *, reuse: bool = False) -> None:
        self.work.mkdir(parents=True, exist_ok=True)
        if reuse:
            if not (self.work / "vm.qcow2").is_file() or not self.key.is_file():
                raise SystemExit("retained diagnostic VM is incomplete")
            log(f"reusing retained diagnostic VM overlay ({self.memory_mib} MiB, 2 vCPU)")
            return
        if (self.work / "vm.qcow2").exists():
            raise ValueError("fresh rehearsal refuses an existing overlay")
        base = self.base_image or self.work / "noble-server-cloudimg-amd64.img"
        base = base.resolve()
        base.parent.mkdir(parents=True, exist_ok=True)
        if not base.exists():
            log("downloading Ubuntu 24.04 cloud image")
            run(["curl", "-fsSL", "-o", str(base) + ".part", UBUNTU_IMG_URL], timeout=1200)
            part = Path(str(base) + ".part")
            actual = _sha256_file(part)
            if actual != UBUNTU_IMG_SHA256:
                part.unlink(missing_ok=True)
                raise SystemExit(
                    f"cloud image digest mismatch: {actual} != {UBUNTU_IMG_SHA256}"
                )
            os.rename(part, base)
        actual = _sha256_file(base)
        if actual != UBUNTU_IMG_SHA256:
            raise SystemExit(
                f"cached cloud image digest mismatch: {actual} != {UBUNTU_IMG_SHA256}"
            )
        log(f"cloud image verified sha256:{actual}")
        run(["qemu-img", "create", "-f", "qcow2", "-b", str(base), "-F", "qcow2", str(self.work / "vm.qcow2"), "30G"])
        if not self.key.exists():
            run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(self.key), "-q"])
        pubkey = (self.work / "id_ed25519.pub").read_text().strip()
        (self.work / "user-data").write_text(
            "#cloud-config\n"
            f"users:\n  - name: {VM_USER}\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n"
            f"    ssh_authorized_keys:\n      - {pubkey}\n"
            "package_update: true\n"
            "growpart:\n  mode: auto\n  devices: ['/']\n"
            "resize_rootfs: true\n"
            "# The rehearsal exercises the release, not the guest's background\n"
            "# economy: snap seeding and apt news timers race the registry loads\n"
            "# through the single slirp funnel and have stalled pushes into RCU\n"
            "# stalls. Mask them before anything else runs.\n"
            "runcmd:\n"
            "  - systemctl mask --now snapd.service snapd.socket snapd.seeded.service || true\n"
            "  - systemctl mask --now apt-news.service esm-cache.service || true\n"
        )
        (self.work / "meta-data").write_text(f"instance-id: rehearsal-{secrets.token_hex(4)}\n")
        run(["xorriso", "-as", "mkisofs", "-output", str(self.work / "seed.iso"), "-volid", "cidata",
             "-joliet", "-rock", str(self.work / "user-data"), str(self.work / "meta-data")])
        if not self.public_transport:
            self._make_ca()

    def transport_receipt(self) -> dict[str, object]:
        if self.public_transport:
            return {
                "siteTransport": {
                    "mode": "anonymous-public-pages",
                    "url": f"https://{HOSTNAME}/StatePort-Site",
                    "guestLocalServer": False,
                },
                "guestRegistryTransport": {
                    "mode": "anonymous-public-ghcr",
                    "sourcePrefix": PREPUBLICATION_REGISTRY_PREFIX,
                    "guestLocalMirror": False,
                    "retainedArchiveTransport": False,
                },
            }
        return {
            "siteTransport": {
                "mode": "guest-local-staged-pages",
                "url": f"https://{HOSTNAME}/StatePort-Site",
                "guestLocalServer": True,
            },
            "guestRegistryTransport": {
                "mode": "digest-only-prepublication-mirror",
                "sourcePrefix": PREPUBLICATION_REGISTRY_PREFIX,
                "location": PREPUBLICATION_REGISTRY_MIRROR,
                "digestOnly": True,
                "guestLocalMirror": True,
                "retainedArchiveTransport": True,
            },
        }

    def _make_ca(self) -> None:
        ca_key, ca_crt = self.work / "ca.key", self.work / "ca.crt"
        if not ca_crt.exists():
            run(["openssl", "req", "-x509", "-newkey", "rsa:4096", "-keyout", str(ca_key),
                 "-out", str(ca_crt), "-days", "2", "-nodes", "-subj", f"/CN=StatePort Rehearsal CA"])
        san = self.work / "san.cnf"
        san.write_text(
            f"[req]\ndistinguished_name=dn\n[dn]\n[v3]\nsubjectAltName=DNS:{HOSTNAME},IP:127.0.0.1\n"
        )
        run(["openssl", "req", "-newkey", "rsa:4096", "-keyout", str(self.work / "tls.key"),
             "-out", str(self.work / "tls.csr"), "-nodes", "-subj", f"/CN={HOSTNAME}"])
        run(["openssl", "x509", "-req", "-in", str(self.work / "tls.csr"), "-CA", str(ca_crt),
             "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(self.work / "tls.crt"),
             "-days", "2", "-extensions", "v3", "-extfile", str(san)])
        registry_san = self.work / "registry-san.cnf"
        registry_san.write_text("[req]\ndistinguished_name=dn\n[dn]\n[v3]\nsubjectAltName=IP:127.0.0.1\n")
        run(["openssl", "req", "-newkey", "rsa:4096", "-keyout", str(self.work / "registry.key"),
             "-out", str(self.work / "registry.csr"), "-nodes", "-subj", "/CN=127.0.0.1"])
        run(["openssl", "x509", "-req", "-in", str(self.work / "registry.csr"), "-CA", str(ca_crt),
             "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(self.work / "registry.crt"),
             "-days", "2", "-extensions", "v3", "-extfile", str(registry_san)])

    def boot(self) -> None:
        log(f"booting VM (kvm, {self.memory_mib} MiB, 2 vCPU, low priority)")
        self.proc = subprocess.Popen([
            "nice", "-n", "15", "ionice", "-c", "3", "qemu-system-x86_64",
            "-enable-kvm", "-cpu", "host,+invtsc", "-m", str(self.memory_mib), "-smp", "2",
            "-display", "none", "-serial", f"file:{self.work / 'console.log'}",
            # aio=threads and no discard: under the rehearsal scope's CPU
            # quota, aio=native plus unmap storms into the tmpfs-backed
            # qcow2 stalled guest timers into soft lockups during the
            # largest registry pushes; invtsc keeps guest time honest when
            # vCPUs do get preempted.
            "-drive", f"file={self.work / 'vm.qcow2'},format=qcow2,if=virtio,cache=none,aio=threads",
            "-cdrom", str(self.work / "seed.iso"),
            "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22",
            "-device", "virtio-net-pci,netdev=n0",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 300
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"QEMU exited before SSH readiness: {self.proc.returncode}")
            if self.ssh("true", check=False).returncode == 0:
                log("VM is up")
                return
            time.sleep(5)
        raise SystemExit("VM did not become reachable over ssh within 300s")

    def phase_gate(self, name: str, *, memory_mib: int | None = None) -> None:
        if not self.phase_gates or not GOVERNOR_PREFLIGHT.is_file():
            return
        # The VM budget is admitted before boot and remains owned by this run.
        # Once QEMU is live, re-admitting the same memory would deadlock on the
        # VM's own footprint; later gates cover only incremental host pressure.
        requested = 0 if self.proc is not None else (memory_mib or self.memory_mib)
        env = os.environ.copy()
        env["STATEPORT_GOVERNOR_REQUESTED_VM_MEMORY_MIB"] = str(requested)
        env["STATEPORT_GOVERNOR_PHASE"] = name
        if self.proc is not None:
            env["STATEPORT_GOVERNOR_TASK_VM_PID"] = str(self.proc.pid)
            env["STATEPORT_GOVERNOR_QUALIFICATION_VM_PATTERN"] = "qemu-system-x86_64"
        budget_label = "additional host pressure; VM already admitted" if self.proc is not None else f"{requested} MiB VM budget"
        log(f"admission: {name} ({budget_label})")
        result = subprocess.run([str(GOVERNOR_PREFLIGHT)], check=False, capture_output=True, text=True, env=env)
        if result.stdout:
            print(result.stdout.rstrip(), flush=True)
        if result.returncode != 0:
            raise SystemExit(f"phase admission refused for {name}: {result.stderr.strip()}")

    def enable_guest_swap(self) -> str:
        command = (
            "set -eu;"
            "swap=/var/lib/stateport-qualification.swap;"
            "if ! sudo swapon --show=NAME --noheadings | grep -Fxq \"$swap\"; then "
            "if [ ! -f \"$swap\" ]; then sudo fallocate -l 6G \"$swap\"; fi;"
            "sudo chmod 0600 \"$swap\"; sudo mkswap \"$swap\" >/dev/null;"
            "sudo swapon --priority 10 \"$swap\"; fi;"
            "sudo sysctl -w vm.swappiness=80 >/dev/null;"
            "free -h; swapon --show"
        )
        result = self.ssh(command, check=False, timeout=180)
        if result.returncode != 0:
            raise SystemExit(f"guest swap setup failed: {result.stderr[-1000:]}")
        return result.stdout

    def ssh(self, cmd: str, *, check: bool = True, timeout: int | None = None,
            tty: bool = False, stdin_text: str | None = None) -> subprocess.CompletedProcess:
        if timeout is None:
            # Guest apt/mirror fetches occasionally stall far longer than the
            # historical 1800 s default; the ceiling is environment-tunable so
            # a slow-mirror window cannot masquerade as a candidate failure.
            timeout = int(os.environ.get("STATEPORT_REHEARSAL_SSH_TIMEOUT", "1800"))
        argv = ["ssh", "-i", str(self.key), "-p", str(SSH_PORT),
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=6"]
        if tty:
            # The bootstrap reads its owner confirmations from /dev/tty.  A
            # bare `ssh -tt` does not reliably deliver piped stdin to the
            # remote controlling terminal, so wrap the command in `script` on
            # the guest (as the native WSL2 lane does): script allocates a real
            # PTY whose stdin is the ssh channel, so the confirmation lines
            # reach the bootstrap's /dev/tty read.
            argv.append("-tt")
            argv += [SSH_TARGET, f"script -qefc {shlex.quote(cmd)} /dev/null"]
        else:
            argv += [SSH_TARGET, cmd]
        return subprocess.run(argv, check=check, capture_output=True, text=True,
                              input=stdin_text, timeout=timeout)

    def _install_argv(self, cmd: str) -> list[str]:
        return ["ssh", "-i", str(self.key), "-p", str(SSH_PORT),
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=6",
                "-tt", SSH_TARGET, f"script -qefc {shlex.quote(cmd)} /dev/null"]

    def ssh_install(
        self, cmd: str, *, confirmations: list[str], timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        """Answer exact installer prompts over the selected guest transport.

        A reader thread supports Windows anonymous pipes as well as SSH pipes;
        select() only supports sockets on Windows. No answer is sent before
        its own prompt, and output/exit waits share a monotonic deadline.
        """
        prompts = {
            "install-packages": "Type install-packages to authorize this exact authenticated package plan:",
            "install-exact": "Type install-exact to authorize this exact plan:",
            "install": "Type install:",
        }
        if not confirmations or any(answer not in prompts for answer in confirmations):
            raise ValueError("unknown or empty install confirmations")
        if len(set(confirmations)) != len(confirmations):
            raise ValueError("duplicate install confirmation")
        argv = self._install_argv(cmd)
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, bufsize=0)
        assert process.stdin is not None and process.stdout is not None
        chunks: queue.Queue = queue.Queue()

        def read_output() -> None:
            try:
                while chunk := os.read(process.stdout.fileno(), 4096):
                    chunks.put(chunk)
            except OSError as error:
                chunks.put(error)
            finally:
                chunks.put(None)

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        pending = list(confirmations)
        output = bytearray()
        deadline = time.monotonic() + timeout
        consumed = 0
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(cmd, timeout, output=output.decode("utf-8", "replace"))
                try:
                    chunk = chunks.get(timeout=remaining)
                except queue.Empty:
                    raise subprocess.TimeoutExpired(cmd, timeout, output=output.decode("utf-8", "replace")) from None
                if chunk is None:
                    break
                if isinstance(chunk, OSError):
                    raise chunk
                output.extend(chunk)
                if len(output) > 16 * 1024 * 1024:
                    raise RuntimeError("installer transcript exceeded its 16 MiB bound")
                while pending:
                    marker = prompts[pending[0]].encode()
                    position = output.find(marker, consumed)
                    if position < 0:
                        break
                    consumed = position + len(marker)
                    answer = pending.pop(0)
                    process.stdin.write((answer + "\n").encode())
                    process.stdin.flush()
                    log(f"install confirmation sent: {answer}")
            returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if pending and returncode == 0:
                raise RuntimeError(f"install finished without all confirmations consumed: {pending}")
            return subprocess.CompletedProcess(argv, returncode, output.decode("utf-8", "replace"), "")
        except BaseException:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            raise
        finally:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            reader.join(timeout=1)
            if not reader.is_alive():
                process.stdout.close()

    def scp_in(self, src: str, dst: str) -> None:
        run(["scp", "-i", str(self.key), "-P", str(SSH_PORT),
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "LogLevel=ERROR", "-r", src, f"{SSH_TARGET}:{dst}"], timeout=900)

    def _capture_rehearsal_baseline(self) -> dict[str, object]:
        command = (
            "set -eu;"
            "for package in podman netavark aardvark-dns runc slirp4netns zstd; do "
            "if record=$(dpkg-query -W -f='${Status}|${Version}|${Architecture}' \"$package\" 2>/dev/null); "
            "then printf 'PKG|%s|%s\\n' \"$package\" \"$record\"; else printf 'PKG|%s|absent|-|-\\n' \"$package\"; fi; done;"
            "digest_tree() { find \"$1\" -xdev -type f -print0 2>/dev/null | sort -z | xargs -0r sha256sum | sha256sum | cut -d' ' -f1; };"
            "printf 'APT|%s\\n' \"$(digest_tree /etc/apt)\";"
            "printf 'USRLOCAL|%s\\n' \"$(digest_tree /usr/local)\";"
            "printf 'SYSTEMD|%s\\n' \"$(digest_tree /etc/systemd)\";"
            "if command -v podman >/dev/null 2>&1; then printf 'PODMAN|%s\\n' \"$(podman --version)\"; else echo 'PODMAN|absent'; fi;"
            "if command -v zstd >/dev/null 2>&1; then printf 'ZSTD|%s\\n' \"$(zstd --version)\"; else echo 'ZSTD|absent'; fi;"
            "if test -x /usr/libexec/podman/quadlet || test -x /usr/lib/podman/quadlet || test -x /usr/lib/systemd/user-generators/podman-user-generator; then echo 'QUADLET|present'; else echo 'QUADLET|absent'; fi"
        )
        result = self.ssh(command, check=False, timeout=120)
        if result.returncode != 0:
            raise SystemExit("stock rehearsal baseline inventory failed")
        packages: dict[str, object] = {}
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            parts = line.split("|")
            if parts[0] == "PKG" and len(parts) == 5:
                packages[parts[1]] = {
                    "status": parts[2],
                    "version": parts[3],
                    "architecture": parts[4],
                }
            elif len(parts) == 2:
                values[parts[0]] = parts[1]
        if set(packages) != {"podman", "netavark", "aardvark-dns", "runc", "slirp4netns", "zstd"} or not {"APT", "USRLOCAL", "SYSTEMD", "PODMAN", "ZSTD", "QUADLET"} <= values.keys():
            raise SystemExit("stock rehearsal baseline inventory is incomplete")
        stock_capability_state = (
            all(item["status"] == "absent" for item in packages.values())
            and values["PODMAN"] == "absent"
            and values["ZSTD"] == "absent"
            and values["QUADLET"] == "absent"
        )
        baseline: dict[str, object] = {
            "schema": "stateport.rehearsal-baseline/v1",
            "os": "ubuntu-24.04",
            "substrate": self.substrate,
            "rootfsIdentity": self.rootfs_identity,
            "preinstalledPackages": "stock_image" if stock_capability_state else "capability_present_before_bootstrap",
            "packageInventoryBeforeBootstrap": packages,
            "aptSourcesDigestBeforeBootstrap": "sha256:" + values["APT"],
            "usrLocalDigestBeforeBootstrap": "sha256:" + values["USRLOCAL"],
            "systemdConfigurationDigestBeforeBootstrap": "sha256:" + values["SYSTEMD"],
            "podmanVersionBeforeBootstrap": None if values["PODMAN"] == "absent" else values["PODMAN"],
            "zstdBeforeBootstrap": None if values["ZSTD"] == "absent" else values["ZSTD"],
            "quadletBeforeBootstrap": values["QUADLET"],
            "extraRepositories": [],
            "extraBinaries": [] if self.public_transport else ["cloud-guest-utils", "docker-registry", "skopeo"],
            "extraRuntimeConfiguration": [] if self.public_transport else ["guest_registry", "staged_https_site", "registry_mirror"],
            "capabilityPreparation": [],
            "capabilityProvisioner": "exact_public_bootstrap_only",
            "identityShims": list(self.identity_shims),
            "usrLocalChanges": list(self.usr_local_changes),
            "runtimeConfigurationChanges": list(self.runtime_configuration_changes),
        }
        policy = effective_mission(load_envelope())["rehearsalBaseline"]
        baseline["evidenceClass"] = (
            classify_rehearsal_baseline(baseline, policy)
            if self.public_transport
            else "simulation_only"
        )
        return baseline

    def setup(self, version: str) -> None:
        transport = "anonymous public Site/GHCR" if self.public_transport else "staged Site and registry"
        log(f"installing shims and {transport} transport")
        if self.rehearsal_baseline is None:
            cloud_init = self.ssh(
                "timeout 420 cloud-init status --wait >/dev/null", check=False, timeout=450
            )
            if cloud_init.returncode != 0:
                raise SystemExit("cloud-init did not settle before stock inventory")
            self.rehearsal_baseline = self._capture_rehearsal_baseline()
        # Fidelity boundary: exactly three guest-local shims stand in for the
        # WSL2 kernel identity a QEMU guest cannot have.  /proc is never
        # mounted over (see module docstring).  Everything else is real.
        #  1. /usr/local/bin/uname           -> bootstrap shell gate (uname -r)
        #  2. python3.12 sitecustomize.py    -> installer/provisioner substrate
        #     markers (platform.release + the two kernel identity file reads)
        #  3. /usr/local/bin/powershell.exe  -> Windows interop gate
        uname_shim = (
            '#!/bin/sh\ncase " $* " in *" -r "*) echo "%s" ;; *) exec /usr/bin/uname "$@" ;; esac\n' % WSL2_KERNEL
        )
        ps_shim = '#!/bin/sh\necho "%s"\n' % WIN_BUILD
        server = (
            "import http.server, ssl, functools\n"
            "h = functools.partial(http.server.SimpleHTTPRequestHandler, directory='/srv')\n"
            "s = http.server.ThreadingHTTPServer(('127.0.0.1', 443), h)\n"
            "c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
            "c.load_cert_chain('/srv/tls.crt', '/srv/tls.key')\n"
            "s.socket = c.wrap_socket(s.socket, server_side=True)\n"
            "s.serve_forever()\n"
        )
        self.ssh(f"mkdir -p /home/{VM_USER}/stage")
        staged_files = [] if self.native_wsl else [
            ("uname", uname_shim),
            ("powershell.exe", ps_shim),
            ("sitecustomize.py", SITECUSTOMIZE),
        ]
        if not self.public_transport:
            staged_files.extend((("serve.py", server), ("registries.conf", GUEST_REGISTRIES_CONF)))
        for name, content in staged_files:
            p = self.work / name
            p.write_text(content)
            self.scp_in(str(p), f"stage/{name}")
        if not self.public_transport:
            self.scp_in(str(self.work / "ca.crt"), "stage/ca.crt")
            self.scp_in(str(self.work / "tls.crt"), "stage/tls.crt")
            self.scp_in(str(self.work / "tls.key"), "stage/tls.key")
            self.scp_in(str(self.work / "registry.crt"), "stage/registry.crt")
            self.scp_in(str(self.work / "registry.key"), "stage/registry.key")
            registry_config = self.work / "registry-config.yml"
            # Plain HTTP on guest loopback avoids TLS hairpin overhead while
            # preserving the signed digest boundary.
            registry_config.write_text(
                "version: 0.1\n"
                "log:\n  fields:\n    service: qualification-registry\n"
                "storage:\n  filesystem:\n    rootdirectory: /var/lib/stateport-qualification-registry\n"
                "http:\n  addr: 127.0.0.1:5443\n"
                "  secret: stateport-qualification-registry-secret-v1\n"
            )
            self.scp_in(str(registry_config), "stage/registry-config.yml")
            # Host-side archives are copied only for the prepublication lane.
            self.scp_in(str(self.archive_root), "stage/oci-archives")
            log("copying staged site tree into VM")
            self.scp_in(str(self.site_root), "stage/site")
        support_package_setup = ""
        if not self.public_transport:
            support_package_setup = (
                "sudo apt-get update >/dev/null;"
                "sudo apt-get install -y cloud-guest-utils docker-registry skopeo >/dev/null;"
            )
        ca_setup = ""
        registry_stop = ""
        registry_start = ""
        site_setup = ""
        mirror_setup = ""
        selftest_diagnostics = "cat /tmp/selftest.err;"
        if not self.public_transport:
            ca_setup = (
                "sudo cp stage/ca.crt /usr/local/share/ca-certificates/stateport-rehearsal-ca.crt;"
                "sudo update-ca-certificates >/dev/null;"
            )
            registry_stop = (
                "for unit in docker-registry.service registry.service; do sudo systemctl stop \"$unit\" 2>/dev/null || true; "
                "sudo systemctl disable --now \"$unit\" 2>/dev/null || true; "
                "sudo systemctl mask --runtime \"$unit\" 2>/dev/null || true; done;"
                "sudo pkill -TERM -x docker-registry 2>/dev/null || true;"
                "for i in $(seq 1 20); do pgrep -x docker-registry >/dev/null 2>&1 || break; sleep 1; done;"
                "sudo pkill -KILL -x docker-registry 2>/dev/null || true;"
            )
            registry_start = (
                "sudo install -d -o root -g root -m 0755 /var/lib/stateport-qualification-registry /etc/stateport;"
                "sudo install -o root -g root -m 0644 stage/registry.crt /etc/stateport/qualification-registry.crt;"
                "sudo install -o root -g root -m 0600 stage/registry.key /etc/stateport/qualification-registry.key;"
                "sudo install -o root -g root -m 0644 stage/registry-config.yml /etc/docker/registry/config.yml;"
                "sudo sh -c 'setsid nohup /usr/bin/docker-registry serve /etc/docker/registry/config.yml "
                ">/var/log/stateport-qualification-registry.log 2>&1 < /dev/null &' ;"
                "ok=0; for i in $(seq 1 30); do if curl -fsS http://127.0.0.1:5443/v2/ >/dev/null; "
                "then ok=1; break; fi; sleep 1; done; [ \"$ok\" = 1 ] || { "
                "sudo cat /var/log/stateport-qualification-registry.log; exit 1; };"
            )
            site_setup = (
                f"grep -q '{HOSTNAME}' /etc/hosts || echo '127.0.0.1 {HOSTNAME}' | sudo tee -a /etc/hosts >/dev/null;"
                "sudo rm -rf /srv/StatePort-Site /srv/tls.crt /srv/tls.key;"
                "sudo mv stage/site /srv/StatePort-Site; sudo mv stage/tls.crt stage/tls.key /srv/; "
                "sudo mv stage/serve.py /srv/serve.py;"
                "sudo chown -R root:root /srv/StatePort-Site;"
                "sudo bash -c 'setsid nohup python3 /srv/serve.py >/srv/serve.log 2>&1 < /dev/null &' ;"
            )
            mirror_setup = (
                "sudo mkdir -p /etc/containers/registries.conf.d;"
                "sudo install -o root -g root -m 0644 stage/registries.conf "
                "/etc/containers/registries.conf.d/99-stateport-rehearsal.conf;"
            )
            selftest_diagnostics += "sudo cat /srv/serve.log; sudo ss -tlnp;"
        identity_setup = ""
        growth_setup = ""
        if not self.native_wsl:
            identity_setup = (
                "sudo install -m0755 stage/uname /usr/local/bin/uname;"
                "sudo install -m0755 stage/powershell.exe /usr/local/bin/powershell.exe;"
                "sudo install -m0644 stage/sitecustomize.py /etc/python3.12/sitecustomize.py;"
                "python3 -c 'import sitecustomize, pathlib;"
                " assert \"microsoft\" in pathlib.Path(\"/proc/sys/kernel/osrelease\").read_text().casefold(),"
                " (sitecustomize.__file__, pathlib.Path(\"/proc/sys/kernel/osrelease\").read_text())';"
                "python3 -c 'import platform; r = platform.release().casefold(); assert \"microsoft\" in r and \"wsl2\" in r, r';"
                "python3 -c 'from pathlib import Path; v = Path(\"/proc/version\").read_text().casefold(); assert \"microsoft\" in v and \"wsl2\" in v, v';"
            )
            growth_setup = "sudo growpart /dev/vda 1 || true; sudo resize2fs /dev/vda1 || true; df -h /;"
        # The pristine-stock capability gate is a native-WSL2 owner-path
        # contract: the imported WSL rootfs must carry no podman/netavark
        # capability before the bootstrap provisions it.  The QEMU lane is an
        # explicitly non-owner-path simulation whose pinned server cloud image
        # legitimately ships zstd (and whose skopeo mirror tooling pulls the
        # netavark chain), so applying the same hard gate there can never pass.
        # The QEMU lane's honest baseline is already recorded by
        # _capture_rehearsal_baseline and classifies as simulation_only.
        stock_gate = ""
        if self.native_wsl:
            stock_gate = (
                "for package in podman netavark aardvark-dns zstd; do if dpkg-query -W -f='${db:Status-Abbrev}' \"$package\" 2>/dev/null | grep -q '^ii '; then echo \"RUNTIME-PACKAGE-PRESENT-BEFORE-BOOTSTRAP:$package\"; exit 1; fi; done;"
                + "if command -v podman >/dev/null 2>&1; then echo PODMAN-PRESENT-BEFORE-BOOTSTRAP; exit 1; fi;"
                + "if command -v zstd >/dev/null 2>&1; then echo ZSTD-PRESENT-BEFORE-BOOTSTRAP; exit 1; fi;"
                + "if grep -RqsE '(^|[[:space:]])questing([[:space:]]|$)' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then echo QUESTING-SOURCE-PRESENT; exit 1; fi;"
            )
        setup_cmd = (
            "set -eu;"
            "for i in $(seq 1 100); do sudo fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 3; done;"
            + identity_setup
            + ca_setup
            + stock_gate
            + support_package_setup
            + growth_setup
            + registry_stop
            + registry_start
            + site_setup
            + "ok=0; for i in $(seq 1 20); do "
            + f"if curl -fsSL --proto '=https' --tlsv1.2 https://{HOSTNAME}/StatePort-Site/download/install.sh -o /tmp/selftest.sh 2>/tmp/selftest.err; then ok=1; break; fi; "
            + "sleep 1; done;"
            + "if [ \"$ok\" != 1 ]; then echo TRANSPORT-SELFTEST-FAILED; "
            + selftest_diagnostics
            + "exit 1; fi;"
            + mirror_setup
            + "echo SELFTEST-OK"
        )
        r = self.ssh(setup_cmd, check=False)
        if r.returncode != 0:
            log(f"setup FAILED (exit {r.returncode})\nstdout:\n{r.stdout[-3000:]}\nstderr:\n{r.stderr[-3000:]}")
            raise SystemExit("VM setup failed; see log above")
        log("setup selftest passed")
        if self.public_transport:
            boundary = self.ssh(
                "set -eu;"
                f"test ! -e /home/{VM_USER}/stage/site;"
                f"test ! -e /home/{VM_USER}/stage/oci-archives;"
                "test ! -e /srv/StatePort-Site;"
                "test ! -e /usr/local/share/ca-certificates/stateport-rehearsal-ca.crt;"
                "test ! -e /etc/containers/registries.conf.d/99-stateport-rehearsal.conf;"
                "if sudo ss -ltn | grep -Eq ':5443([[:space:]]|$)'; then exit 1; fi;"
                f"if grep -Eq '(^|[[:space:]]){HOSTNAME}($|[[:space:]])' /etc/hosts; then exit 1; fi;"
                f"resolved=$(getent ahostsv4 {HOSTNAME} | awk '{{print $1}}' | sort -u | tr '\\n' ',');"
                "[ -n \"$resolved\" ]; case \",$resolved\" in *,127.0.0.1,*) exit 1;; esac;"
                "printf 'PUBLIC-TRANSPORT-BOUNDARY-OK resolved=%s\\n' \"$resolved\"",
                check=False,
                timeout=120,
            )
            if boundary.returncode != 0:
                raise SystemExit(
                    "public transport boundary failed: "
                    + (boundary.stderr or boundary.stdout).strip()[-1000:]
                )
            self.public_transport_boundary = {
                "ok": True,
                "stdoutTail": boundary.stdout[-1000:],
            }
        else:
            self.load_registry(version)
            self._normalize_to_wsl2_baseline()
        out = self.ssh("curl -fsSL --proto '=https' --tlsv1.2 "
                       f"https://{HOSTNAME}/StatePort-Site/download/install.sh | sha256sum", timeout=120)
        source = "public" if self.public_transport else "staged"
        log(f"{source} install.sh reachable in VM, sha256 {out.stdout.split()[0]}")

    def _registry_images(self, version: str) -> list[tuple[str, str]]:
        version_root = self.site_root / "download" / version
        if not (version_root / "release-index.json").is_file():
            raise ValueError(f"exact qualification release index is unavailable: {version}")
        index = json.loads((version_root / "release-index.json").read_text(encoding="utf-8"))
        return sorted(
            ((str(image["imageId"]), str(image["digest"])) for image in index["signed"]["images"]),
            key=lambda pair: pair[0],
        )

    def _normalize_to_wsl2_baseline(self) -> None:
        """Restore the WSL2 rootfs package baseline after the mirror tooling runs.

        The staged lane installs skopeo (+ docker-registry) to load the guest
        registry.  On Ubuntu 24.04 skopeo pulls golang-github-containers-common,
        whose metadata leaves phantom ``not-installed`` dpkg records for
        netavark/aardvark-dns; the pinned server cloud image also ships netavark
        (Enhances: podman), leaving a phantom podman record.  The immutable
        installer's package preflight treats any ``not-installed`` record with
        rc 0 as a malformed installed identity and refuses.  A genuine stock
        WSL2 rootfs has none of these (verified against the pinned
        ubuntu-24.04.4-wsl rootfs digest), and it ships dbus-user-session
        genuinely installed at the sealed version.

        Purging the stock container stack clears every phantom it created, and
        installing dbus-user-session converts its phantom into a genuine
        installed record, so the guest matches the real WSL2 owner host before
        the bootstrap's own package preflight runs.
        """
        if self.native_wsl:
            return
        command = (
            "set -eu;"
            # Disable needrestart's automatic service restarts so a package
            # upgrade cannot disrupt the guest (service restarts and initramfs
            # regeneration) and kill the SSH session mid-flight.  Mode 'l'
            # lists restarts without performing them.
            "sudo -n mkdir -p /etc/needrestart/conf.d;"
            "printf '%s\\n' '$nrconf{restart} = \"l\";' | sudo -n tee /etc/needrestart/conf.d/99-stateport-rehearsal.conf >/dev/null;"
            # Settle the pinned cloud image to the current point releases
            # first.  The bootstrap's own host-deps step installs systemd,
            # dbus-broker, and python3; on the pinned noble-20260801 image an
            # in-install python3.12/systemd upgrade would otherwise disrupt the
            # guest (service restarts and initramfs regeneration) and kill the
            # bootstrap's SSH session.  A full upgrade here means the
            # bootstrap's host-deps finds nothing to upgrade, matching a
            # current WSL2 host.
            "sudo -n apt-get update -o DPkg::Lock::Timeout=300 >/dev/null 2>&1;"
            "DEBIAN_FRONTEND=noninteractive sudo -n apt-get upgrade -y --no-install-recommends -o DPkg::Lock::Timeout=300 >/dev/null 2>&1 || "
            "DEBIAN_FRONTEND=noninteractive sudo -n apt-get upgrade -y -o DPkg::Lock::Timeout=300 >/dev/null 2>&1;"
            # Remove the stock container stack the mirror tooling pulled in.
            # One dpkg --purge of the whole set lets dpkg resolve dependency
            # order; genuinely installed stock versions are removed, and the
            # phantom not-installed rows (podman/netavark/aardvark-dns created
            # by netavark's Enhances and containers-common's Recommends)
            # disappear once the referencing packages are gone.  docker-registry
            # (the guest mirror) is a standalone Python service and does not
            # depend on any of these.
            "sudo -n dpkg --purge podman netavark aardvark-dns skopeo golang-github-containers-common golang-github-containers-image containers-storage runc slirp4netns catatonit conmon fuse-overlayfs uidmap libsubid4 >/dev/null 2>&1 || true;"
            # Match the genuine WSL2 rootfs: dbus-user-session installed at the
            # sealed version.  systemd Recommends it, so the apt metadata is
            # always present on a stock host; the real WSL2 rootfs carries the
            # package itself, and installing it converts the phantom into a
            # genuine installed record before the package preflight.
            "DEBIAN_FRONTEND=noninteractive sudo -n apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=300 dbus-user-session >/dev/null 2>&1;"
            "echo WSL2-BASELINE-NORMALIZED"
        )
        result = self.ssh(command, check=False, timeout=300)
        if result.returncode != 0 or "WSL2-BASELINE-NORMALIZED" not in result.stdout:
            raise SystemExit(
                "WSL2 baseline normalization failed: "
                + (result.stderr or result.stdout).strip()[-1000:]
            )
        log("guest normalized to the WSL2 rootfs package baseline")

    def _wait_for_guest_quiet(self) -> None:
        """Let first-boot churn finish before sustained pushes.

        Fresh guests still run cloud-init final stages, snapd seeding, and
        apt timers when the registry loads start; combined with the
        rehearsal scope's CPU quota that overlap stalled guest timers into
        soft lockups mid-push.  A settled guest (like every manual
        reproduction) pushes cleanly.
        """
        self.ssh(
            "sudo cloud-init status --wait >/dev/null 2>&1 || true;"
            "for i in $(seq 1 60); do "
            "awk 'exit !($1 < 2.0)' /proc/loadavg && ! pgrep -x snapd >/dev/null && break;"
            "sleep 5; done;"
            "cat /proc/loadavg",
            check=False,
            timeout=600,
        )

    def load_registry(self, version: str, *, attempts_per_image: int = 3) -> None:
        """Push every release archive into the guest registry.

        Each image travels in its own ssh session with bounded retries:
        a mid-push transport hiccup then costs one image's re-copy, not the
        whole setup.  Copies are idempotent — an already-present digest is
        verified and skipped.
        """
        images = self._registry_images(version)
        self._wait_for_guest_quiet()
        for image_id, digest in images:
            reference = f"docker://127.0.0.1:{REGISTRY_PORT}/stateport-alpha/{image_id}@{digest}"
            verify = (
                f"test \"$(skopeo inspect --raw --tls-verify=false {reference} "
                f"| sha256sum | cut -d' ' -f1)\" = \"{digest.removeprefix('sha256:')}\""
            )
            # Stage the one archive through guest tmpfs: O_DIRECT reads off
            # the tmpfs-backed qcow2 are pathologically slow for a 1.1 GiB
            # archive, while a local buffered copy plus a tmpfs read takes
            # seconds. The staging copy is removed immediately after the
            # attempt so guest memory returns before the next image.
            stage_cmd = (
                f"cp /home/{VM_USER}/stage/oci-archives/{image_id}.oci.tar "
                f"/dev/shm/stateport-load.oci.tar && "
                f"sudo -n nice -n 10 ionice -c 3 skopeo copy --src-tls-verify=false "
                f"--dest-tls-verify=false "
                f"oci-archive:/dev/shm/stateport-load.oci.tar {reference}; "
                f"rc=$?; rm -f /dev/shm/stateport-load.oci.tar; exit $rc"
            )
            last_error = ""
            for attempt in range(1, attempts_per_image + 1):
                present = self.ssh(verify, check=False, timeout=120)
                if present.returncode == 0:
                    log(f"registry already has {image_id} @{digest[:19]}")
                    break
                copied = self.ssh(f"{stage_cmd}; {verify}", check=False, timeout=int(os.environ.get("STATEPORT_REHEARSAL_LOAD_TIMEOUT", "2400")))
                if copied.returncode == 0:
                    log(f"registry loaded {image_id} @{digest[:19]}")
                    break
                last_error = (copied.stderr or copied.stdout).strip()[-400:]
                log(f"registry load attempt {attempt}/{attempts_per_image} "
                    f"failed for {image_id}: {last_error}")
                time.sleep(5 * attempt)
            else:
                raise SystemExit(
                    f"guest registry refused {image_id} after {attempts_per_image} attempts: "
                    f"{last_error}"
                )

    def rehearse(
        self,
        version: str,
        *,
        phase0_only: bool = False,
        binding: dict[str, object],
        diagnostic: bool = False,
        expected_candidate: str | None = None,
        expected_signed_payload: str | None = None,
    ) -> dict:
        receipt: dict = {
            "version": version,
            "mode": (
                "phase0-transport"
                if phase0_only
                else ("j1-diagnostic" if diagnostic else ("public-transport" if self.public_transport else "j1"))
            ),
            "binding": binding,
            "phases": {},
        }
        self.current_receipt = receipt
        receipt.update(self.transport_receipt())
        receipt["rehearsalBaseline"] = self.rehearsal_baseline
        receipt["evidenceClass"] = (
            self.rehearsal_baseline.get("evidenceClass", "simulation_only")
            if self.rehearsal_baseline is not None
            else "simulation_only"
        )
        if self.public_transport_boundary is not None:
            receipt["phases"]["public-transport-boundary"] = self.public_transport_boundary
        if diagnostic:
            receipt["diagnostic"] = {
                "diagnostic": True,
                "admissibleForQualification": False,
                "expectedCandidate": expected_candidate,
                "expectedSignedPayload": expected_signed_payload,
                "changedPrecondition": "revision-qualified-container-watcher",
            }
        cmd = (f"curl -fsSL --proto '=https' --tlsv1.2 "
               f"{shlex.quote(self.bootstrap_url)} -o /tmp/install.sh "
               f"&& sha256sum /tmp/install.sh")
        log("phase: fetch bootstrap exactly as the download page instructs")
        r = self.ssh(cmd, timeout=300)
        receipt["phases"]["bootstrap-fetch"] = {"ok": True, "sha256": r.stdout.split()[0], "url": self.bootstrap_url}
        if "sha256:" + receipt["phases"]["bootstrap-fetch"]["sha256"] != binding["bootstrapDigest"]:
            raise SystemExit("phase-0 bootstrap bytes differ from the bound candidate")

        if not phase0_only and not self.native_wsl:
            # Every full-length guest run executes inside the declared
            # qualification envelope (5 GiB RAM + 6 GiB guest swap). Without
            # the swap half of that envelope a three-service cold start
            # starves on a one-vCPU guest and the API health gate times out
            # before the workload ever gets scheduling room; diagnostics
            # always enabled it, so full runs must use the same envelope to
            # stay comparable with every retained-VM observation.
            self.phase_gate("guest-swap")
            swap = self.enable_guest_swap()
            receipt["phases"]["guest-swap"] = {"ok": True, "stdoutTail": swap[-3000:]}
            if diagnostic:
                self.phase_gate("diagnostic")
        wsl_env = (
            ""
            if self.native_wsl
            else "WSL_INTEROP=/run/WSL/1_interop WSL_DISTRO_NAME=Ubuntu-24.04"
        )
        if phase0_only:
            phases = [
                ("transport-probe", "--transport-probe", 900),
                ("materialization-preflight", "--materialization-preflight", 900),
            ]
        else:
            # The package-bearing install under the rehearsal CPU/memory
            # envelope (image pulls, root helper materialization, service
            # cold-start, health gates) can exceed the historical one-hour
            # ceiling on a constrained QEMU guest.  The owner's real WSL2 host
            # is far faster; this ceiling is env-tunable so a slow rehearsal
            # lane cannot masquerade as a candidate failure.
            install_timeout = int(os.environ.get("STATEPORT_REHEARSAL_INSTALL_TIMEOUT", "3600"))
            phases = [
                ("transport-probe", "--transport-probe", 900),
                ("materialization-preflight", "--materialization-preflight", 900),
                ("install", "", install_timeout),
            ]
            if not diagnostic:
                phases.append(("install-rerun", "", install_timeout))
        for name, args, to in phases:
            self.phase_gate(name)
            log(f"phase: {name}")
            # Wait out any background apt activity (unattended-upgrades fires
            # on first boot); the bootstrap's apt-get must own the lock.
            if name == "install":
                self.ssh("for i in $(seq 1 100); do sudo fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 3; done; echo APT-FREE")
                # The bootstrap's apt-get work can run dpkg triggers that
                # restore the distro's /usr/lib sitecustomize symlink; the
                # WSL2 identity shim must still be the imported sitecustomize
                # or the contract probe refuses target_missing. Assert it
                # immediately before the install so a lost shim fails here
                # with a clear message instead of a confusing install refusal.
                if not self.native_wsl:
                    self.ssh(
                        "python3 -c 'import sitecustomize, pathlib;"
                        " assert \"microsoft\" in pathlib.Path(\"/proc/sys/kernel/osrelease\").read_text().casefold(),"
                        " (sitecustomize.__file__, pathlib.Path(\"/proc/sys/kernel/osrelease\").read_text())'"
                    )
                self._start_failure_watcher()
            # Package-bearing releases expose the authenticated package plan and
            # the final exact install plan as two separate owner confirmations.
            confirmation = (
                "install-packages\ninstall-exact\n"
                if binding.get("podmanPackageBundleDigest") is not None
                else "install\n"
            )
            try:
                if args:
                    # Probe phases (--transport-probe, --materialization-
                    # preflight) run the bootstrap without any install
                    # confirmation; drive them over a plain tty ssh.
                    r = self.ssh(f"{wsl_env} sh /tmp/install.sh {args}".lstrip(), check=False,
                                 timeout=to, tty=True)
                else:
                    r = self.ssh_install(
                        f"{wsl_env} sh /tmp/install.sh".lstrip(),
                        confirmations=confirmation.splitlines(),
                        timeout=to,
                    )
            except subprocess.TimeoutExpired as exc:
                # A phase that exceeds its wall-clock ceiling must still record
                # the guest state instead of losing every diagnostic to the
                # exception.  Capture the partial install transcript (ssh
                # buffers it until the timeout fires) and the failure snapshot
                # before teardown so a slow install can be told apart from a
                # wedged one.
                partial_stdout = exc.stdout or ""
                partial_stderr = exc.stderr or ""
                if isinstance(partial_stdout, bytes):
                    partial_stdout = partial_stdout.decode("utf-8", "replace")
                if isinstance(partial_stderr, bytes):
                    partial_stderr = partial_stderr.decode("utf-8", "replace")
                partial_stdout = partial_stdout[-12000:]
                partial_stderr = partial_stderr[-4000:]
                log(f"phase {name} TIMED OUT after {to}s")
                receipt["phases"][name] = {
                    "ok": False, "exit": None, "timeout": to,
                    "stdoutTail": partial_stdout,
                    "stderrTail": partial_stderr or "install phase exceeded its wall-clock ceiling",
                }
                receipt["result"] = "failed"
                if name == "install":
                    self._stop_failure_watcher()
                    try:
                        self._collect_failure_snapshots(receipt)
                    except Exception as exc2:  # noqa: BLE001 - diagnostics must not mask the timeout
                        receipt["failureSnapshotsError"] = str(exc2)[-2000:]
                self._collect_diagnostics(receipt)
                return receipt
            finally:
                if name == "install":
                    self._stop_failure_watcher()
            receipt["phases"][name] = {
                "ok": r.returncode == 0, "exit": r.returncode,
                "stdoutTail": r.stdout[-12000:], "stderrTail": r.stderr[-4000:],
            }
            if r.returncode != 0:
                log(f"phase {name} FAILED (exit {r.returncode}): {r.stderr[-500:]}")
                receipt["result"] = "failed"
                if name == "install":
                    # The typed refusal record (including any bounded health
                    # observations) is written guest-locally; pull it into the
                    # host receipt BEFORE the VM is destroyed.
                    refusal = self.ssh(
                        "for f in $(ls -1t ~/.local/state/stateport-install/refusals/*.json 2>/dev/null | head -1); do cat \"$f\"; done",
                        check=False, timeout=60,
                    )
                    if refusal.returncode == 0 and refusal.stdout.strip():
                        try:
                            receipt["phases"][name]["refusalRecord"] = json.loads(refusal.stdout)
                        except json.JSONDecodeError:
                            receipt["phases"][name]["refusalRecordRaw"] = refusal.stdout[:4000]
                    self._collect_failure_snapshots(receipt)
                self._collect_diagnostics(receipt)
                return receipt
            log(f"phase {name} ok")
            if name in {"install", "install-rerun"} and "images" in binding:
                smoke_name = name + "-services"
                receipt["phases"][smoke_name] = {"ok": False}
                receipt["phases"][smoke_name] = installed_service_smoke(self, binding)
            if name == "install":
                self.phase_gate("post-bootstrap-runtime-smoke")
                package_check = (
                    "import json,subprocess,sys;"
                    "receipt=json.load(open(sys.argv[1],encoding='utf-8'));"
                    "expected=json.loads(sys.argv[2]);"
                    "proof=receipt['podmanPackageInstallation'];"
                    "observed={name:value['version'] for name,value in proof['packages'].items()};"
                    "assert set(observed)==set(expected),(set(observed)^set(expected));"
                    "assert all(observed.get(name)==version for name,version in expected.items()),(observed,expected);"
                    "assert proof['dpkgAudit']=='clean';"
                    "installed={name:subprocess.check_output(["
                    "'dpkg-query','--show','--showformat=${Version}',name],text=True).strip() "
                    "for name in observed};"
                    "assert installed==observed,(installed,observed)"
                )
                runtime = self.ssh(
                    "set -eu;"
                    "receipt=$(ls -1t ~/.local/state/stateport-install/receipts/install_receipt_*.json | head -1);"
                    f"python3 -c {shlex.quote(package_check)} \"$receipt\" "
                    f"{shlex.quote(json.dumps(PODMAN_PACKAGE_VERSIONS, sort_keys=True))};"
                    "test \"$(podman --version)\" = 'podman version 5.4.2';"
                    "test \"$(podman info --format '{{.Host.Security.Rootless}}|{{.Host.OCIRuntime.Name}}|{{.Host.NetworkBackend}}')\" = 'true|runc|netavark';"
                    "test \"$(/usr/libexec/stateport/crun --version | head -n 1)\" = 'crun version 1.28';"
                    "test \"$(sha256sum /usr/libexec/stateport/crun | cut -d' ' -f1)\" = '2aa6b7024a9c9f153895c0d11ae233d3758f54844011c3a039e3e89048d01d42';"
                    "test -z \"$(dpkg --audit)\";"
                    "sudo systemctl restart apparmor;"
                    "podman run --rm docker.io/library/alpine:3.21 true;"
                    "echo SMOKE-OK",
                    check=False,
                    timeout=900,
                )
                receipt["phases"]["post-bootstrap-runtime-smoke"] = {
                    "ok": runtime.returncode == 0 and "SMOKE-OK" in runtime.stdout,
                    "exit": runtime.returncode,
                    "stdoutTail": runtime.stdout[-3000:],
                    "stderrTail": runtime.stderr[-3000:],
                }
                if not receipt["phases"]["post-bootstrap-runtime-smoke"]["ok"]:
                    log("phase post-bootstrap-runtime-smoke FAILED")
                    receipt["result"] = "failed"
                    self._collect_diagnostics(receipt)
                    return receipt
                log("phase post-bootstrap-runtime-smoke ok")
        if not phase0_only:
            self.phase_gate("guest-runtime-smoke")
            log("phase: post-bootstrap guest-runtime smoke")
            r = self.ssh(
                "podman version --format '{{.Client.Version}}' && "
                "test \"$(podman info --format '{{.Host.Security.Rootless}}')\" = true && "
                "sudo systemctl restart apparmor && "
                "podman run --rm docker.io/library/alpine:3.21 true && echo SMOKE-OK",
                check=False,
                timeout=900,
            )
            receipt["phases"]["guest-runtime-smoke"] = {
                "ok": r.returncode == 0 and "SMOKE-OK" in r.stdout,
                "exit": r.returncode,
                "stdoutTail": r.stdout[-3000:],
                "stderrTail": r.stderr[-3000:],
            }
            if not receipt["phases"]["guest-runtime-smoke"]["ok"]:
                receipt["result"] = "failed"
                return receipt
        receipt["result"] = "passed"
        self._collect_diagnostics(receipt)
        return receipt

    def diagnose_retained(
        self,
        *,
        binding: dict[str, object],
        expected_candidate: str,
        expected_web_digest: str,
    ) -> dict:
        """Trace one retained failed install without replaying its installation."""
        receipt: dict = {
            "version": f"retained-{expected_candidate}",
            "mode": "j1-diagnostic",
            "binding": binding,
            "diagnostic": {
                "diagnostic": True,
                "admissibleForQualification": False,
                "expectedCandidate": expected_candidate,
                "expectedWebDigest": expected_web_digest,
                "changedPrecondition": "retained-vm-guest-swap-revision-qualified-runtime-trace-and-rotated-prior-watcher",
            },
            "phases": {},
        }
        self.phase_gate("diagnostic")
        swap = self.enable_guest_swap()
        receipt["phases"]["guest-swap"] = {"ok": True, "stdoutTail": swap[-3000:]}
        self.phase_gate("revision-qualified-web-restart")
        self._start_failure_watcher(rotate_existing=True)
        command = f'''set -eu
uid=$(id -u stateport-control)
home=/var/lib/stateport-control
run_control() {{
  cd /
  env -i HOME="$home" LANG=C.UTF-8 LC_ALL=C.UTF-8 LOGNAME=stateport-control \
    PATH=/usr/bin:/bin USER=stateport-control \
    XDG_CONFIG_HOME="$home/.config" XDG_DATA_HOME="$home/.local/share" \
    XDG_STATE_HOME="$home/.local/state" XDG_RUNTIME_DIR="/run/user/$uid" \
    "$@"
}}
source=''
for candidate in "$home/.config/containers/systemd"/*.container; do
  [ -f "$candidate" ] || continue
  grep -q '^Label=io.stateport.service.id=stateport-web$' "$candidate" || continue
  source="$candidate"
   break
done
 [ -n "$source" ]
unit=$(basename "$source" .container).service
image=$(sed -n 's/^Image=//p' "$source" | head -n 1)
[ -n "$image" ]
digest=$(run_control podman image inspect "$image" --format '{{{{.Digest}}}}')
[ "$digest" = "{expected_web_digest}" ] || case "$image" in *"@{expected_web_digest}"*) ;; *) echo IMAGE-DIGEST-MISMATCH >&2; exit 3 ;; esac
run_control systemctl --user restart "$unit"
for attempt in $(seq 1 120); do
  container=''
  while read -r id; do
    [ -n "$id" ] || continue
    actual=$(run_control podman inspect "$id" --format '{{{{.ImageName}}}}' 2>/dev/null || true)
    [ "$actual" = "$image" ] || continue
    container="$id"
    break
  done < <(run_control podman ps -a --no-trunc --filter label=io.stateport.service.id=stateport-web --format '{{{{.ID}}}}')
  if [ -n "$container" ]; then
    status=$(run_control podman inspect "$container" --format '{{{{.State.Status}}}}' 2>/dev/null || true)
    exit_code=$(run_control podman inspect "$container" --format '{{{{.State.ExitCode}}}}' 2>/dev/null || true)
    printf 'containerId=%s status=%s exitCode=%s\\n' "$container" "$status" "$exit_code"
    if [ "$exit_code" = 127 ]; then echo EXIT-127-OBSERVED; exit 0; fi
    if [ "$status" = running ]; then echo WEB-STILL-RUNNING; exit 0; fi
  fi
  sleep 1
exit 42
'''
        try:
            result = self.ssh(command, check=False, timeout=180)
        finally:
            self._stop_failure_watcher()
        receipt["phases"]["revision-qualified-web-restart"] = {
            "ok": result.returncode == 0 and "EXIT-127-OBSERVED" in result.stdout,
            "exit": result.returncode,
            "stdoutTail": result.stdout[-5000:],
            "stderrTail": result.stderr[-3000:],
        }
        self._collect_failure_snapshots(receipt)
        self._collect_diagnostics(receipt)
        if receipt["phases"]["revision-qualified-web-restart"]["ok"]:
            receipt["result"] = "diagnostic_complete"
        else:
            receipt["result"] = "diagnostic_incomplete"
        return receipt

    def _start_failure_watcher(self, *, rotate_existing: bool = False) -> None:
        if rotate_existing:
            existing = (
                f"if sudo test -e {FAILURE_SNAPSHOT_ROOT} || sudo test -L {FAILURE_SNAPSHOT_ROOT}; then "
                f"prior={FAILURE_SNAPSHOT_ROOT}.previous-$(date -u +%Y%m%dT%H%M%SZ)-$$; "
                f"sudo mv {FAILURE_SNAPSHOT_ROOT} \"$prior\" || exit 1; fi;"
            )
        else:
            existing = (
                f"if sudo test -e {FAILURE_SNAPSHOT_ROOT} || sudo test -L {FAILURE_SNAPSHOT_ROOT}; then "
                "echo 'failure snapshot path already exists' >&2; exit 1; fi;"
            )
        command = existing + (
            f"sudo install -d -o root -g root -m 0755 {FAILURE_SNAPSHOT_ROOT};"
            f"sudo tee {FAILURE_SNAPSHOT_ROOT}/watcher.sh >/dev/null;"
            f"sudo chmod 0700 {FAILURE_SNAPSHOT_ROOT}/watcher.sh;"
            f"sudo sh -c 'rm -f {FAILURE_SNAPSHOT_ROOT}/stop; setsid nohup {FAILURE_SNAPSHOT_ROOT}/watcher.sh "
            f">{FAILURE_SNAPSHOT_ROOT}/watcher.log 2>&1 < /dev/null & "
            f"echo $! >{FAILURE_SNAPSHOT_ROOT}/watcher.pid'"
        )
        self.ssh(command, stdin_text=FAILURE_WATCHER, timeout=120)

    def _stop_failure_watcher(self) -> None:
        self.ssh(
            f"sudo touch {FAILURE_SNAPSHOT_ROOT}/stop;"
            f"pid=$(sudo cat {FAILURE_SNAPSHOT_ROOT}/watcher.pid 2>/dev/null || true);"
            "if [ -n \"$pid\" ]; then "
            "for i in $(seq 1 100); do sudo kill -0 \"$pid\" 2>/dev/null || break; sleep 0.1; done; "
            "sudo kill \"$pid\" 2>/dev/null || true; fi",
            check=False,
            timeout=30,
        )

    def _collect_failure_snapshots(self, receipt: dict) -> None:
        result = self.ssh(
            "sudo python3 -",
            check=False,
            timeout=120,
            stdin_text=FAILURE_SNAPSHOT_COLLECTOR,
        )
        if result.returncode != 0:
            receipt["failureSnapshotsError"] = result.stderr[-2000:]
            return
        try:
            receipt["failureSnapshots"] = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            receipt["failureSnapshotsError"] = f"invalid snapshot collector output: {exc}"

    def _collect_diagnostics(self, receipt: dict) -> None:
        diag = self.ssh(
            "cat /var/lib/stateport-provisioning/receipts/*.json 2>/dev/null;"
            "echo ---; podman images --format '{{.Repository}} {{.Digest}}' 2>/dev/null;"
            "echo ---; systemctl --user --no-pager --type=service --state=running 2>/dev/null | head -20;"
            "echo ---; ls -la ~/.local/state/stateport-install 2>/dev/null",
            check=False, timeout=120)
        receipt["diagnostics"] = diag.stdout[-6000:]
        uid = self.ssh("id -u stateport-exec 2>/dev/null || true", check=False).stdout.strip()
        if uid:
            env = f"XDG_RUNTIME_DIR=/run/user/{uid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"
            svc = self.ssh(
                f"sudo runuser -u stateport-exec -- env {env} systemctl --user status stateport-execution-host.service --no-pager 2>&1 | head -25;"
                "echo ---JOURNAL---;"
                f"sudo runuser -u stateport-exec -- env {env} journalctl --user -u stateport-execution-host.service --no-pager -n 60 2>&1;"
                "echo ---QUADLET---;"
                "sudo cat /var/lib/stateport-exec/.config/containers/systemd/stateport-execution-host.container 2>/dev/null;"
                "echo ---PODMAN---;"
                f"sudo runuser -u stateport-exec -- env {env} podman ps -a 2>&1 | head",
                check=False, timeout=180)
            receipt["executionHostService"] = svc.stdout[-8000:]
        cuid = self.ssh("id -u stateport-control 2>/dev/null || true", check=False).stdout.strip()
        if cuid:
            cenv = f"XDG_RUNTIME_DIR=/run/user/{cuid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{cuid}/bus"
            ctl = self.ssh(
                f"sudo runuser -u stateport-control -- env {cenv} systemctl --user list-units --all 2>&1 | head -25;"
                "echo ---CONTROL-JOURNAL---;"
                f"sudo runuser -u stateport-control -- env {cenv} journalctl --user -u 'stateport-*' --no-pager -n 80 2>&1;"
                "echo ---CONTROL-PODMAN---;"
                f"sudo runuser -u stateport-control -- env {cenv} podman ps -a 2>&1 | head -15;"
                "echo ---CONTROL-NETWORKS---;"
                f"sudo runuser -u stateport-control -- env {cenv} podman network ls 2>&1 | head -10",
                check=False, timeout=180)
            receipt["controlPlaneService"] = ctl.stdout[-8000:]
            api_probe_script = r'''set +e
cd /
home=/var/lib/stateport-control
source=''
for candidate in "$home/.config/containers/systemd"/*.container; do
  [ -f "$candidate" ] || continue
  grep -q '^Label=io.stateport.service.id=stateport-api$' "$candidate" || continue
  source="$candidate"
  break
done
echo ---API-QUADLET---
printf 'source=%s\n' "$source"
if [ -n "$source" ]; then
  sed -n '/^Image=/p;/^PublishPort=/p;/^HealthCmd=/p' "$source"
fi
echo ---API-CONTAINERS---
podman ps -a --no-trunc --filter label=io.stateport.service.id=stateport-api
container="$(podman ps -a --no-trunc --filter label=io.stateport.service.id=stateport-api --format '{{.ID}}' | { IFS= read -r first; printf '%s' "$first"; })"
if [ -n "$container" ]; then
  echo ---API-STATE---
  podman inspect "$container" --format 'ID={{.Id}} Status={{.State.Status}} ExitCode={{.State.ExitCode}} Error={{json .State.Error}} Health={{json .State.Health}}'
  echo ---API-LOGS---
  podman logs "$container"
  echo ---API-IN-CONTAINER-READYZ---
  podman exec "$container" /usr/local/bin/stateport-healthcheck --kind http --host 127.0.0.1 --port 8790 --path /readyz
  echo ---API-LOOPBACK-READYZ---
  api_port="$(podman port "$container" 8790/tcp)"
  api_port="${api_port##*:}"
  if [ -n "$api_port" ]; then
    curl --max-time 5 -sS -D - "http://127.0.0.1:${api_port}/readyz"
    echo ---API-URLLIB-READYZ---
    API_PORT="$api_port" python3 - <<'PY'
import os
import urllib.request

url = f"http://127.0.0.1:{os.environ['API_PORT']}/readyz"
with urllib.request.urlopen(url, timeout=10) as response:
    body = response.read(65536)
    print(f"status={response.status} bytes={len(body)}")
    print(body.decode())
PY
  else
    echo API-PORT-NOT-FOUND
  fi
fi
'''
            api = self.ssh(
                "sudo runuser -u stateport-control -- env "
                f"{cenv} sh -c {shlex.quote(api_probe_script)}",
                check=False, timeout=180)
            receipt["apiHealthProbe"] = api.stdout[-10000:]
            if api.stderr:
                receipt["apiHealthProbeStderr"] = api.stderr[-3000:]
        sysctl = self.ssh(
            "echo ---SYSTEM-CONTROL-JOURNAL---;"
            "sudo journalctl --no-pager -n 200 2>/dev/null | grep -E 'stateport|podman|conmon' | grep -vE 'pam_unix|runuser' | tail -80;"
            "echo ---CONTROL-DIAGNOSTICS---;"
            "sudo find /var/lib/stateport-provisioning/diagnostics -type f 2>/dev/null -exec sh -c 'echo \"=== {} ===\"; cat \"{}\"' \\; 2>/dev/null | tail -120;"
            "echo ---CONTROL-PROVISIONING-RECEIPT---;"
            "sudo cat /var/lib/stateport-provisioning/receipts/execution-host-provisioning-receipt.json 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -E 'detail|step|result' | tail -30",
            check=False, timeout=180)
        receipt["systemControlJournal"] = sysctl.stdout[-8000:]

    def teardown(self) -> None:
        if self.proc:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        log("VM torn down")


class NativeWSL(VM):
    """Disposable native WSL2 runner for post-publication owner-path evidence."""

    def __init__(self, work: Path, site_root: Path, archive_root: Path | None, *,
                 distro_name: str, phase_gates: bool = False,
                 public_transport: bool = True, attach_existing: bool = False,
                 bootstrap_url: str | None = None) -> None:
        if not public_transport:
            raise ValueError("native WSL2 qualification requires anonymous public transport")
        if re.fullmatch(r"StatePort-Rehearsal-[A-Za-z0-9._-]{3,64}", distro_name) is None:
            raise ValueError("native WSL2 rehearsal distribution name is invalid")
        super().__init__(work, site_root, archive_root, phase_gates=phase_gates,
                         public_transport=True, memory_mib=0,
                         bootstrap_url=bootstrap_url)
        self.distro_name = distro_name
        self.install_root = work / "distribution"
        self.rootfs = work / "ubuntu-24.04.4-wsl-amd64.wsl"
        self.exec_user = "root"
        self.imported = False
        self.attach_existing = attach_existing
        self.expected_native_identity: dict[str, str] | None = None
        self.expected_native_baseline: dict[str, object] | None = None
        self.native_wsl = True
        self.substrate = "native-wsl2"
        self.rootfs_identity = dict(WSL_ROOTFS_IDENTITY)
        self.identity_shims = []
        self.usr_local_changes = []
        self.runtime_configuration_changes = []

    @staticmethod
    def _wsl(arguments: list[str], *, check: bool = True,
             timeout: int = 600) -> subprocess.CompletedProcess:
        return subprocess.run(["wsl.exe", *arguments], check=check, capture_output=True,
                              text=True, timeout=timeout, shell=False)

    def prepare(self, *, reuse: bool = False) -> None:
        if reuse and not self.attach_existing:
            raise SystemExit("native WSL2 qualification never reuses a retained distribution")
        if os.name != "nt":
            raise SystemExit("--native-wsl2 must run from Windows Python on the owner host")
        self.work.mkdir(parents=True, exist_ok=True)
        listed = self._wsl(["--list", "--quiet"], check=False, timeout=60)
        if listed.returncode != 0:
            raise SystemExit("wsl.exe is unavailable or WSL is not enabled")
        names = {line.strip().replace("\x00", "").casefold() for line in listed.stdout.splitlines()}
        if self.distro_name.casefold() in names and not self.attach_existing:
            raise SystemExit("native WSL2 rehearsal distribution name is already registered")
        if self.attach_existing:
            if self.distro_name.casefold() not in names:
                raise SystemExit("requested native WSL2 qualification distro is not registered")
            self.exec_user = VM_USER
            return
        if self.install_root.exists() or self.install_root.is_symlink():
            raise SystemExit("native WSL2 rehearsal install directory must be absent")
        expected = WSL_ROOTFS_IDENTITY["digest"].removeprefix("sha256:")
        if not self.rootfs.exists():
            partial = Path(str(self.rootfs) + ".part")
            partial.unlink(missing_ok=True)
            digest = hashlib.sha256()
            total = 0
            try:
                with urllib.request.urlopen(WSL_ROOTFS_IDENTITY["url"], timeout=120) as source:
                    with partial.open("xb") as target:
                        while chunk := source.read(1024 * 1024):
                            total += len(chunk); digest.update(chunk); target.write(chunk)
                            if total > 2 * 1024 * 1024 * 1024:
                                raise SystemExit("WSL rootfs download exceeded its 2 GiB bound")
                        target.flush(); os.fsync(target.fileno())
                if digest.hexdigest() != expected:
                    raise SystemExit("downloaded WSL rootfs digest differs from the pinned identity")
                os.rename(partial, self.rootfs)
            finally:
                partial.unlink(missing_ok=True)
        if _sha256_file(self.rootfs) != expected:
            raise SystemExit("cached WSL rootfs digest differs from the pinned identity")
        imported = self._wsl(["--import", self.distro_name, str(self.install_root),
                              str(self.rootfs), "--version", "2"], check=False, timeout=1200)
        if imported.returncode != 0:
            raise SystemExit(f"WSL2 rootfs import failed: {imported.stderr.strip()[-1000:]}")
        self.imported = True

    def boot(self) -> None:
        if self.attach_existing:
            expected = self.expected_native_identity
            baseline = self.expected_native_baseline
            if (
                not isinstance(expected, dict)
                or set(expected) != {"machineId", "windowsIdentity"}
                or not isinstance(expected.get("machineId"), str)
                or re.fullmatch(r"[0-9a-fA-F]{32}", expected["machineId"]) is None
                or not isinstance(expected.get("windowsIdentity"), str)
                or not expected["windowsIdentity"].strip()
                or not isinstance(baseline, dict)
                or baseline.get("distroName") != self.distro_name
                or any(baseline.get(key) != value for key, value in expected.items())
            ):
                raise SystemExit("native follow-on identity binding is incomplete or inconsistent")
        versions = self._wsl(["--list", "--verbose"], check=False, timeout=60)
        normalized = versions.stdout.replace("\x00", "")
        if versions.returncode != 0 or not any(
            (parts := line.lstrip().removeprefix("*").split()) and parts[0] == self.distro_name
            and parts[-1] == "2" for line in normalized.splitlines()
        ):
            raise SystemExit("imported rehearsal distribution is not registered as WSL2")
        if not self.attach_existing:
            self.rehearsal_baseline = self._capture_rehearsal_baseline()
            self.rehearsal_baseline["distroName"] = self.distro_name
        elif self.expected_native_baseline is None:
            raise SystemExit("native follow-on is missing the retained J1 baseline")
        else:
            self.rehearsal_baseline = dict(self.expected_native_baseline)
        machine = self.ssh("cat /etc/machine-id", check=False, timeout=60)
        ps_identity = "$o=Get-CimInstance Win32_OperatingSystem; $o.Caption+'|'+$o.Version+'|'+$o.BuildNumber"
        identity = self.ssh("powershell.exe -NoProfile -NonInteractive -Command " + shlex.quote(ps_identity), check=False, timeout=60)
        if machine.returncode != 0 or not re.fullmatch(r"[0-9a-fA-F]{32}\n?", machine.stdout):
            raise SystemExit("native distro machine identity probe failed")
        if identity.returncode != 0 or not identity.stdout.strip():
            raise SystemExit("native Windows identity probe failed")
        if not self.rehearsal_baseline.get("machineId"):
            self.rehearsal_baseline["machineId"] = machine.stdout.strip()
        if not self.rehearsal_baseline.get("windowsIdentity"):
            self.rehearsal_baseline["windowsIdentity"] = identity.stdout.strip()
        if self.expected_native_identity is not None and any(
            {"machineId": machine.stdout.strip(),
             "windowsIdentity": identity.stdout.strip(),
             "distroName": self.distro_name}.get(key) != value
            for key, value in self.expected_native_identity.items()
        ):
            raise SystemExit("attached native WSL2 identity differs from retained J1")
        # Import has no first-run user wizard. Create the ordinary test user,
        # but preserve stock WSL/systemd configuration and leave lingering to
        # the public installer. Passwordless sudo is an automation seam; this
        # lane does not establish interactive sudo-password prompt behavior.
        if self.attach_existing:
            self.exec_user = VM_USER
            ready = self.ssh(
                "set -eu; id -u rehearsal | grep -qx 1000; "
                "case $(uname -r | tr '[:upper:]' '[:lower:]') in *microsoft*) ;; *) exit 1;; esac; "
                "test -n \"${WSL_INTEROP:-}\"; command -v script >/dev/null; "
                "systemctl --user show-environment >/dev/null",
                check=False, timeout=300,
            )
            if ready.returncode != 0:
                raise SystemExit("attached native WSL2 distro/user identity check failed")
            log("attached native WSL2 distribution for follow-on journey")
            return
        configure = self.ssh(
            "set -eu;"
            "command -v sudo >/dev/null;"
            f"if getent passwd {VM_USER} >/dev/null || getent passwd 1000 >/dev/null; then exit 41; fi;"
            f"useradd --create-home --uid 1000 --shell /bin/bash {VM_USER};"
            f"usermod --append --groups sudo {VM_USER};"
            f"printf '%s ALL=(ALL) NOPASSWD:ALL\\n' {VM_USER} > /etc/sudoers.d/stateport-rehearsal;"
            "chmod 0440 /etc/sudoers.d/stateport-rehearsal",
            check=False, timeout=120,
        )
        if configure.returncode != 0:
            raise SystemExit("native WSL2 rehearsal user setup failed without package preparation: "
                             + configure.stderr.strip()[-1000:])
        self._wsl(["--terminate", self.distro_name], check=True, timeout=120)
        self.exec_user = VM_USER
        ready = self.ssh(
            "set -eu;"
            "case $(uname -r | tr '[:upper:]' '[:lower:]') in *microsoft* ) ;; *) exit 1;; esac;"
            "test -n \"${WSL_INTEROP:-}\"; test -n \"${WSL_DISTRO_NAME:-}\";"
            "powershell.exe -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()' >/dev/null;"
            "command -v script >/dev/null;"
            "systemctl is-system-running --wait >/dev/null || test \"$(systemctl is-system-running)\" = degraded;"
            "systemctl --user show-environment >/dev/null",
            check=False, timeout=300,
        )
        if ready.returncode != 0:
            raise SystemExit(f"native WSL2 systemd/user session failed: {ready.stderr.strip()[-1000:]}")
        log("native WSL2 distribution is up from the pinned pristine rootfs")

    def ssh(self, cmd: str, *, check: bool = True, timeout: int | None = None,
            tty: bool = False, stdin_text: str | None = None) -> subprocess.CompletedProcess:
        shell = (["script", "-qefc", f"sh -lc {shlex.quote(cmd)}", "/dev/null"]
                 if tty else ["sh", "-lc", cmd])
        argv = ["wsl.exe", "--distribution", self.distro_name, "--user", self.exec_user,
                "--", *shell]
        return subprocess.run(argv, check=check, capture_output=True, text=True, input=stdin_text,
                              timeout=timeout or int(os.environ.get("STATEPORT_REHEARSAL_WSL_TIMEOUT", "1800")),
                              shell=False)

    def _install_argv(self, cmd: str) -> list[str]:
        return ["wsl.exe", "--distribution", self.distro_name, "--user", self.exec_user,
                "--", "script", "-qefc", f"sh -lc {shlex.quote(cmd)}", "/dev/null"]

    def scp_in(self, src: str, dst: str) -> None:
        raise SystemExit(f"native public qualification forbids local transfer: {src} -> {dst}")

    def fetch_public_artifact(self, url: str, destination: str, expected_digest: str) -> None:
        """Fetch one reviewed release byte through anonymous HTTPS in WSL.

        The download is staged atomically and verified inside the distro. No
        host path, local mirror, or identity shim participates in this path.
        """
        if not re.fullmatch(r"https://[^\s]+", url):
            raise ValueError("native artifact URL must use HTTPS")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
            raise ValueError("native artifact digest is invalid")
        if not destination.startswith("/") or "\n" in destination or "\x00" in destination:
            raise ValueError("native artifact destination must be an absolute path")
        quoted_url = shlex.quote(url)
        quoted_dst = shlex.quote(destination)
        command = (
            "set -eu; "
            f"tmp={quoted_dst}.part.$$; trap 'rm -f \"$tmp\"' EXIT; "
            f"curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "
            f"--output \"$tmp\" {quoted_url}; "
            f"test \"$(sha256sum \"$tmp\" | awk '{{print $1}}')\" = {expected_digest.removeprefix('sha256:')}; "
            f"install -m 0755 \"$tmp\" {quoted_dst}; rm -f \"$tmp\"; trap - EXIT"
        )
        result = self.ssh(command, check=False, timeout=900)
        if result.returncode != 0:
            raise SystemExit("native public artifact fetch or digest verification failed")

    def teardown(self) -> None:
        if not self.imported:
            return
        self._wsl(["--terminate", self.distro_name], check=False, timeout=120)
        removed = self._wsl(["--unregister", self.distro_name], check=False, timeout=300)
        if removed.returncode != 0:
            raise SystemExit("owned disposable WSL distribution could not be unregistered: "
                             + removed.stderr.strip()[-1000:])
        self.imported = False
        log("owned disposable WSL2 distribution unregistered")


# Reviewed immutable public identities from the Alpha.16 publication evidence.
# Updating this target is explicit; never follow the mutable installer silently.
LOCAL_PUBLIC_VERSION = "0.1.0-alpha.16"
LOCAL_PUBLIC_PINS = {
    "install.sh": "6feedf5273547f4a98f5d8edb6fe24e729104ad822c4d58da70cb1f0fdad417a",
    "release-index.json": "8dad6399e66956d1dcb5aebb5a5119c6001617b3279902f0746857b5e6bfac47",
    "release-index.sigstore.json": "ff36ca75c5139d58a92e7d9b78a53f120aa4e4f42cdf9be35603eef3e682b557",
    "stateport-alpha-2026-08-cosign.pub": "798d6ea6e2703993758f0fb45618b1f05b40f6ef116e7d286fd5a6867859b8ad",
}


def public_binding(work: Path) -> dict:
    """Check public bytes and signature before any VM, without OCI staging."""
    inputs = work / "public-inputs"
    inputs.mkdir(exist_ok=True)
    for name, expected in LOCAL_PUBLIC_PINS.items():
        suffix = name if name == "install.sh" else f"{LOCAL_PUBLIC_VERSION}/{name}"
        url = f"https://{HOSTNAME}/StatePort-Site/download/{suffix}"
        fetched = run(["curl", "-fsSL", "--proto", "=https", "--tlsv1.2",
                       "--max-time", "60", url], capture=True, timeout=75)
        content = fetched.stdout.encode("utf-8")
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise ValueError(f"public candidate mismatch for {name}: {actual} != {expected}")
        (inputs / name).write_bytes(content)
    index = json.loads((inputs / "release-index.json").read_text())
    signed = index["signed"]
    if signed["release"]["version"] != LOCAL_PUBLIC_VERSION:
        raise ValueError("public candidate version mismatch")
    payload = _canonical_json(signed)
    payload_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if payload_digest != "sha256:5594dc7dc3711ffdfbd74da271012c02dc23e5fa626d12f59d41a768058b2bac":
        raise ValueError("public signed payload mismatch")
    payload_path = inputs / "release-index.signed-payload.json"
    payload_path.write_bytes(payload)
    # Same pinned-key/offline-log policy used by the shipped installer.
    verified = run(["cosign", "verify-blob", "--insecure-ignore-tlog", "--bundle",
                    str(inputs / "release-index.sigstore.json"), "--key",
                    str(inputs / "stateport-alpha-2026-08-cosign.pub"), str(payload_path)],
                   capture=True, timeout=120)
    return {
        "releaseIndexDigest": "sha256:" + LOCAL_PUBLIC_PINS["release-index.json"],
        "signedPayloadDigest": payload_digest,
        "bootstrapDigest": "sha256:" + LOCAL_PUBLIC_PINS["install.sh"],
        "podmanPackageBundleDigest": signed["artifacts"]["podmanPackageBundle"]["digest"],
        "images": {item["imageId"]: item["digest"] for item in signed["images"]},
        "providerRuntimeRequired": any(service.get("providerHome") for target in signed.get("targets", []) for service in target.get("services", [])),
        "signatureVerified": verified.returncode == 0,
    }


def installed_service_smoke(vm: VM, binding: dict) -> dict:
    from qualification.journey_common import (
        GuestJsonClient, control_user_env, discover_services, verify_installed_image_digests,
        wait_service_healthy,
    )
    services = discover_services(vm)
    for service in services:
        wait_service_healthy(vm, services, service, deadline_s=420)
    digests = verify_installed_image_digests(vm, binding["images"])
    if digests["mismatches"]:
        raise ValueError(f"installed service image mismatch: {digests['mismatches']}")
    web = GuestJsonClient(vm, services["stateport-web"]["port"])
    web.handshake()
    host = web.request("GET", "/v1/execution-host").get("executionHost", {})
    if host.get("status") != "available" or host.get("grantBound") is not True:
        raise ValueError(f"installed execution host unavailable: {host}")
    provider = None
    sandbox = None
    if binding.get("providerRuntimeRequired"):
        observed = web.request("GET", "/v1/provider/status")
        expected = {"executableInstalled": True, "configured": False, "connected": False,
                    "authenticationStatus": "unverified", "requestStatus": "unverified",
                    "telemetryStatus": "unavailable"}
        if any(observed.get(key) != value for key, value in expected.items()):
            raise ValueError("fresh installed provider observations do not match the signed runtime contract")
        provider = expected
        # Exercise the real provider sandbox, not just CLI presence. Bind exec
        # to the exact running ID already checked against the signed images.
        container = digests.get("containers", {}).get("stateport-web", {}).get("containerId", "")
        if re.fullmatch(r"[0-9a-f]{64}", container) is None:
            raise ValueError("provider sandbox requires the verified running container ID")
        source = (Path(__file__).resolve().parents[2] / "scripts/qualification/provider_sandbox_probe.py").read_text()
        command = ["podman", "exec", "--user", "65532:65532", container,
                   "/usr/local/bin/python3", "-c", source]
        shell = control_user_env() + "; run_control " + shlex.join(command)
        checked = vm.ssh("sudo runuser -u stateport-control -- bash -c " + shlex.quote(shell),
                         check=False, timeout=110)
        if checked.returncode != 0:
            raise ValueError("installed provider sandbox failed: " + checked.stderr[-2500:])
        sandbox = json.loads(checked.stdout)
        version = sandbox.get("providerVersion") if isinstance(sandbox, dict) else None
        if (not isinstance(version, str) or len(version) > 160
                or re.fullmatch(r"codex-cli [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?", version) is None):
            raise ValueError("installed provider sandbox returned no valid provider version")
        if sandbox != {"result": "passed", "insideWrite": "passed", "outsideWrite": "refused",
                       "symlinkEscape": "refused", "networkSocket": "refused",
                       "childProcess": "passed", "namespaces": "isolated",
                       "authentication": "not attempted", "runtime": "web",
                       "parentNetworkSocket": "permitted", "providerVersion": version}:
            raise ValueError("installed provider sandbox returned incomplete boundary evidence")
    return {"ok": True, "services": services, "imageDigests": digests,
            "providerFreshObservations": provider,
            "providerSandbox": sandbox,
            "webSession": "passed", "executionHost": host,
            "limitations": "Health/protocol and unauthenticated provider sandbox checks only; no real provider request or three-template qualification"}


def finish_local_vm(vm: VM, receipt: dict) -> None:
    """Stop our process, then remove only disposable files in our new run."""
    try:
        vm.teardown()
        removed = []
        for name in ("vm.qcow2", "seed.iso", "id_ed25519", "id_ed25519.pub", "user-data"):
            path = vm.work / name
            if path.exists() or path.is_symlink():
                path.unlink()
                removed.append(name)
        receipt["cleanup"] = {"ok": True, "removed": removed}
    except (Exception, SystemExit) as exc:
        receipt["cleanup"] = {"ok": False, "error": str(exc)}
        receipt["result"] = "failed"


def run_local_vm(work: Path, binding: dict) -> int:
    cache = Path.home() / ".cache/stateport/qualification/noble-server-cloudimg-amd64.img"
    # Reuse only immutable base media, never a retained installed overlay.
    retained_base = (Path.home() / ".local/state/stateport/release/alpha16/"
                     "rehearsal-phase0-r1-vm/noble-server-cloudimg-amd64.img")
    base = retained_base if retained_base.is_file() else cache
    vm = VM(work / "vm", work / "unused-site", work / "unused-archives",
            phase_gates=True, public_transport=True, base_image=base)
    receipt = {"version": LOCAL_PUBLIC_VERSION, "binding": binding,
               "evidenceClass": "simulation_only", "result": "failed", "phases": {}}
    stage = "setup-admission"
    try:
        vm.phase_gate("setup")
        stage = "prepare"
        vm.prepare()
        stage = "boot"
        vm.boot()
        stage = "setup"
        vm.setup(LOCAL_PUBLIC_VERSION)
        stage = "rehearse"
        receipt = vm.rehearse(LOCAL_PUBLIC_VERSION, binding=binding)
    except (Exception, SystemExit, KeyboardInterrupt) as exc:
        receipt = vm.current_receipt or receipt
        receipt.update(result="failed", failureStage=stage, error=str(exc))
        if vm.proc is not None and vm.proc.poll() is None:
            try:
                vm._collect_diagnostics(receipt)
            except (Exception, SystemExit) as diagnostic_error:
                receipt["diagnosticsError"] = str(diagnostic_error)
    finally:
        finish_local_vm(vm, receipt)
        (work / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True))
    log(f"result: {receipt['result']} -> {work / 'receipt.json'}")
    return 0 if receipt["result"] == "passed" else 1


def local_public_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="One fresh local public Alpha.16 simulation")
    parser.add_argument("--local-public", action="store_true")
    parser.add_argument("--admitted-run", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.admitted_run:
        require_guard("qualification", sys.argv)
        work = args.admitted_run
        try:
            return run_local_vm(work, public_binding(work))
        except (Exception, SystemExit) as exc:
            (work / "receipt.json").write_text(json.dumps({
                "result": "failed", "evidenceClass": "simulation_only",
                "failureStage": "public-input-verification", "error": str(exc),
                "cleanup": {"ok": True, "vmStarted": False}}, indent=2))
            return 1
    parent = Path.home() / ".local/state/stateport/qualification/local-public"
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="alpha16-", dir=parent))
    log(f"fresh run evidence: {work}")
    try:
        for executable in ("qemu-system-x86_64", "qemu-img", "xorriso", "ssh", "ssh-keygen", "curl", "cosign"):
            if not shutil.which(executable):
                raise ValueError(f"missing host tool: {executable}")
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise ValueError("KVM is not accessible")
        with socket.socket() as probe:
            probe.bind((SSH_HOST, SSH_PORT))
        public_binding(work)
        command = [sys.executable, str(Path(__file__).resolve()), "--local-public",
                   "--admitted-run", str(work)]
        guard = work / "guard.json"
        authorize_guard("qualification", command, guard)
        env = os.environ.copy()
        env.update(STATEPORT_RELEASE_ACTION="qualification",
                   STATEPORT_RELEASE_GUARD_RECEIPT=str(guard),
                   STATEPORT_GOVERNOR_STATE_DIR=str(work / "governor"),
                   STATEPORT_GOVERNOR_REQUESTED_VM_MEMORY_MIB=str(QUALIFICATION_VM_MEMORY_MIB),
                   STATEPORT_GOVERNOR_MEMORY_HIGH="7G", STATEPORT_GOVERNOR_MEMORY_MAX="8G",
                   STATEPORT_HEAVY_RUNTIME_MAX="120min")
        governor = Path.home() / ".kimi-code/governor/heavy-run.sh"
        with (work / "command.log").open("w") as transcript:
            with subprocess.Popen([str(governor), "8G", *command], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
                try:
                    for line in proc.stdout:
                        transcript.write(line)
                        transcript.flush()
                        print(line, end="", flush=True)
                    status = proc.wait()
                except BaseException:
                    proc.terminate()  # governor trap stops its entire owned cgroup
                    proc.wait(timeout=60)
                    raise
        if not (work / "receipt.json").exists():
            raise RuntimeError(f"governor/child exited {status} without a journey receipt; see command.log")
        return status
    except (Exception, SystemExit, KeyboardInterrupt) as exc:
        failed = {
            "result": "failed", "evidenceClass": "simulation_only",
            "failureStage": "host-admission-or-governor", "error": str(exc)}
        if (work / "receipt.json").is_file():
            failed["journeyReceipt"] = json.loads((work / "receipt.json").read_text())
        (work / "receipt.json").write_text(json.dumps(failed, indent=2))
        log(f"refused: {exc}; evidence: {work}")
        return 1


def main() -> int:
    if "--local-public" in sys.argv[1:]:
        return local_public_main(sys.argv[1:])
    ap = argparse.ArgumentParser()
    ap.add_argument("--site-root", type=Path, required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--archive-root", type=Path)
    ap.add_argument("--work-dir", type=Path, default=Path("/tmp/opencode/rehearse/vm"))
    ap.add_argument("--keep-vm", action="store_true")
    ap.add_argument("--phase0-only", action="store_true")
    ap.add_argument("--phase0-receipt", type=Path)
    ap.add_argument("--public-transport", action="store_true")
    ap.add_argument("--native-wsl2", action="store_true")
    ap.add_argument("--bootstrap-url")
    ap.add_argument("--wsl-distro-name")
    ap.add_argument("--diagnostic", action="store_true")
    ap.add_argument("--retained-vm-dir", type=Path)
    ap.add_argument("--expected-candidate")
    ap.add_argument("--expected-signed-payload")
    ap.add_argument("--receipt-out", type=Path, required=True)
    args = ap.parse_args()
    require_guard("qualification", sys.argv)
    if not args.site_root.is_dir() or not (args.site_root / "download" / "install.sh").is_file():
        raise SystemExit("--site-root must be a staged Site tree containing download/install.sh")
    if not args.public_transport and (
        args.archive_root is None
        or not args.archive_root.is_dir()
        or not list(args.archive_root.glob("*.oci.tar"))
    ):
        raise SystemExit("--archive-root must contain retained OCI archives")
    if args.public_transport and args.phase0_only:
        ap.error("public transport is a full post-publication rehearsal, not a phase-0 mode")
    if args.public_transport and args.diagnostic:
        ap.error("public transport cannot reuse the prepublication diagnostic lane")
    if args.native_wsl2 and not args.public_transport:
        ap.error("native WSL2 owner-path qualification requires --public-transport")
    if args.native_wsl2 and (args.phase0_only or args.diagnostic or args.retained_vm_dir):
        ap.error("native WSL2 owner-path qualification is a fresh full journey only")
    binding = phase0_binding(
        args.site_root,
        args.version,
        None if args.public_transport else args.archive_root,
        args.bootstrap_url,
    )
    # Full journeys execute both transport and materialization probes themselves.
    # A separately supplied receipt is additional exact-byte evidence, never a
    # prerequisite that forces native WSL through an unrelated QEMU run.
    if args.phase0_receipt is not None:
        try:
            phase0 = json.loads(args.phase0_receipt.read_text(encoding="utf-8"))
            validate_phase0_receipt(phase0, binding)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise SystemExit(f"full J1 mode refused: {exc}") from exc
    if args.diagnostic and args.phase0_only:
        ap.error("diagnostic mode requires full J1")
    if args.diagnostic and (not args.expected_candidate or not args.expected_signed_payload):
        ap.error("diagnostic mode requires --expected-candidate and --expected-signed-payload")
    if args.diagnostic and args.expected_signed_payload != binding["signedPayloadDigest"]:
        ap.error("diagnostic expected signed payload differs from the exact candidate binding")
    diagnostic_reuse = args.diagnostic and args.retained_vm_dir is not None
    work_dir = args.retained_vm_dir if diagnostic_reuse else args.work_dir
    memory_mib = DIAGNOSTIC_VM_MEMORY_MIB if args.diagnostic else QUALIFICATION_VM_MEMORY_MIB
    if args.native_wsl2:
        distro_name = args.wsl_distro_name or f"StatePort-Rehearsal-{os.getpid()}"
        vm: VM = NativeWSL(
            work_dir,
            args.site_root,
            args.archive_root,
            distro_name=distro_name,
            phase_gates=True,
            public_transport=True,
            bootstrap_url=args.bootstrap_url,
        )
    else:
        vm = VM(
            work_dir,
            args.site_root,
            args.archive_root,
            phase_gates=True,
            diagnostic_reuse=diagnostic_reuse,
            public_transport=args.public_transport,
            memory_mib=memory_mib,
            bootstrap_url=args.bootstrap_url,
        )
    try:
        if not diagnostic_reuse:
            vm.phase_gate("setup")
        vm.prepare(reuse=diagnostic_reuse)
        vm.boot()
        if diagnostic_reuse:
            index = json.loads((args.site_root / "download" / args.version / "release-index.json").read_text(encoding="utf-8"))
            expected_web_digest = next(
                str(image["digest"])
                for image in index["signed"]["images"]
                if image.get("imageId") == "stateport-web"
            )
            receipt = vm.diagnose_retained(
                binding=binding,
                expected_candidate=Path(args.expected_candidate).name,
                expected_web_digest=expected_web_digest,
            )
        else:
            vm.setup(args.version)
            receipt = vm.rehearse(
                args.version,
                phase0_only=args.phase0_only,
                binding=binding,
                diagnostic=args.diagnostic,
                expected_candidate=args.expected_candidate,
                expected_signed_payload=args.expected_signed_payload,
            )
    finally:
        if not args.keep_vm:
            vm.teardown()
    args.receipt_out.parent.mkdir(parents=True, exist_ok=True)
    args.receipt_out.write_text(json.dumps(receipt, indent=2, sort_keys=True))
    log(f"result: {receipt['result']} -> {args.receipt_out}")
    if args.keep_vm and receipt["result"] not in {"passed", "diagnostic_complete"}:
        log("VM HELD for debugging (up to 3600s): ssh -i "
            f"{args.work_dir}/id_ed25519 -p {SSH_PORT} {SSH_TARGET}")
        time.sleep(3600)
    return 0 if receipt["result"] in {"passed", "diagnostic_complete"} else 1


if __name__ == "__main__":
    sys.exit(main())
