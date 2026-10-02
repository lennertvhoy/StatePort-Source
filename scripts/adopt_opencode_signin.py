#!/usr/bin/env python3
"""Host-side adoption of the owner's already signed-in OpenCode.

Run this on the machine (the WSL distribution) where OpenCode is already
signed in. It COPIES only the SELECTED provider record(s) out of the file
OpenCode keeps every sign-in in, ``~/.local/share/opencode/auth.json``, into
the three StatePort places that need it. Unrelated providers in that file are
never copied. Selection: ``--provider ID`` (repeatable, must be present), else
the provider of ``--model`` (``<provider>/<model>``), else ``opencode-go`` /
``opencode`` when present, else the helper refuses and lists the detected names.

1. the managed provider home        (control plane, mode 0600, stateport-control)
2. the control agent-provider dir   (mode 0600, stateport-control; the control
   service reads it as its own uid)
3. the execution agent-provider dir (mode 0640, owner stateport-exec, group =
   the host gid the sealed container's gid 10001 maps to, derived from the
   stateport-exec entry in /etc/subgid under rootless podman ``--userns host``)

Copy 3 is read by the sealed agent workspace container (``--user 10001:10001``,
see stateport-agent-run), through the GROUP bit; it is never world-readable. If
the mapped gid cannot be determined the copy stays 0600 and the helper says so:
the provisioner must then chown it to the mapped gid before an agent can use it.
(provider.env is provisioned separately and is not touched here.)

OAuth caveat: OpenCode rotates an OAuth refresh token when it refreshes it. An
OAuth record copied here that refreshes inside StatePort can sign the original
OpenCode out; prefer an API-key provider such as opencode-go.

Nothing is symlinked, the source is never modified, every destination component
is opened with O_NOFOLLOW relative to a directory descriptor (a component
swapped for a symlink cannot redirect root's write), and no value is ever
printed, logged or sent anywhere: the report names paths, sizes, modes and
provider NAMES only.

Normally the in-product "Adopt existing OpenCode sign-in" action does copy 1
by itself; this helper exists for the cases it cannot reach (the container
cannot read the host home, the provider home is owned by another uid) and for
the two agent-provider directories, which are read-only mounts in the web
container.

Writing into the root-provisioned directories needs root (``sudo``); use
``--dry-run`` to see what would happen. ``--model`` also writes the ``model``
file the agent run requires.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import pwd
import sys

HERE = Path(__file__).resolve().parent
ADOPTION_MODULE = (
    HERE.parent / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "provider_adoption.py"
)

CONTROL_USER = "stateport-control"
EXEC_USER = "stateport-exec"
PROVIDER_HOME = "/var/lib/stateport-control/provider-auth/opencode"
CONTROL_AGENT_DIR = "/var/lib/stateport-control/agent-provider"
EXEC_AGENT_DIR = "/var/lib/stateport-exec/stateport-execution-host/agent-provider"
SUBGID_FILE = Path("/etc/subgid")
# engine.py runs the sealed workspace as --user 10001:10001 --userns host.
CONTAINER_GID = 10001


def _load_adoption():
    spec = importlib.util.spec_from_file_location("stateport_provider_adoption_standalone", ADOPTION_MODULE)
    if spec is None or spec.loader is None:
        raise SystemExit(f"adopt: cannot load {ADOPTION_MODULE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def default_source_directory(environment: dict[str, str]) -> Path:
    """The invoking user's OpenCode data directory (the sudo caller, not root)."""
    xdg = environment.get("XDG_DATA_HOME", "")
    sudo_user = environment.get("SUDO_USER", "")
    if sudo_user and os.geteuid() == 0:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir) / ".local" / "share" / "opencode"
        except KeyError:
            pass
    if xdg and Path(xdg).is_absolute():
        return Path(xdg) / "opencode"
    return Path(environment.get("HOME") or Path.home()) / ".local" / "share" / "opencode"


def _ids(user: str, no_chown: bool) -> tuple[int | None, int | None]:
    if no_chown:
        return None, None
    try:
        entry = pwd.getpwnam(user)
    except KeyError as exc:
        raise SystemExit(
            f"adopt: the user {user} does not exist; run the StatePort provisioner first, "
            "or pass --no-chown for a test root"
        ) from exc
    return entry.pw_uid, entry.pw_gid


def mapped_container_gid(user: str, subgid_file: Path = SUBGID_FILE, container_gid: int = CONTAINER_GID) -> int | None:
    """Host gid that rootless podman maps container gid ``container_gid`` to for ``user``.

    Container gid 0 is the user's own gid; container gid N (N >= 1) is the
    N-th gid of the user's subordinate range. None when it cannot be derived.
    """
    try:
        lines = Path(subgid_file).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) == 3 and parts[0] == user:
            try:
                start, count = int(parts[1]), int(parts[2])
            except ValueError:
                continue
            if 1 <= container_gid <= count:
                return start + container_gid - 1
    return None


def main(argv: list[str] | None = None, environment: dict[str, str] | None = None) -> int:
    env = dict(os.environ if environment is None else environment)
    parser = argparse.ArgumentParser(description="Copy an existing OpenCode sign-in into StatePort.")
    parser.add_argument("--source-dir", type=Path, help="OpenCode data directory holding auth.json (default: invoking user's)")
    parser.add_argument("--root", type=Path, default=Path("/"), help="re-root the destination paths (tests)")
    parser.add_argument("--no-chown", action="store_true", help="do not chown (tests / already-owned roots)")
    parser.add_argument("--model", help="also write this model id to the agent-provider directories")
    parser.add_argument("--provider", action="append", default=None, metavar="ID",
                        help="provider id to copy (repeatable; default: the --model provider, else opencode-go/opencode)")
    parser.add_argument("--subgid-file", type=Path, default=SUBGID_FILE, help="subgid map used to derive the container gid")
    parser.add_argument("--skip", action="append", default=[], choices=["provider-home", "control-agent", "exec-agent"])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    adoption = _load_adoption()
    source_dir = args.source_dir or default_source_directory(env)
    source = source_dir / adoption.AUTH_FILE_NAME
    try:
        raw, detected = adoption.read_signin_file(source)
        hint = args.model.strip().split("/", 1)[0] if args.model and "/" in args.model else None
        providers = adoption.select_provider_ids(detected, args.provider, hint)
        data = adoption.select_signin(raw, providers)
    except adoption.AdoptionError as exc:
        print(f"adopt: refused ({exc.code}): {exc.detail}", file=sys.stderr)
        return 2

    root = args.root
    def under(path: str) -> Path:
        return root / path.lstrip("/")

    exec_gid = mapped_container_gid(EXEC_USER, args.subgid_file)
    exec_mode = 0o640 if exec_gid is not None else 0o600
    plan = []
    if "provider-home" not in args.skip:
        plan.append((
            adoption.destination_auth_path(under(PROVIDER_HOME)), 0o600, 0o700, CONTROL_USER, None,
        ))
    if "control-agent" not in args.skip:
        plan.append((under(CONTROL_AGENT_DIR) / adoption.AUTH_FILE_NAME, 0o600, 0o755, CONTROL_USER, None))
    if "exec-agent" not in args.skip:
        plan.append((under(EXEC_AGENT_DIR) / adoption.AUTH_FILE_NAME, exec_mode, 0o755, EXEC_USER, exec_gid))
        if exec_gid is None:
            print(
                f"adopt: WARNING the host gid for container gid {CONTAINER_GID} could not be derived from "
                f"{args.subgid_file} ({EXEC_USER}); the execution copy is mode 0600 and the sealed container "
                "cannot read it until the provisioner chowns it to the mapped gid and sets mode 0640",
                file=sys.stderr,
            )

    print(f"adopt: source {source} ({len(data)} bytes copied; providers: {', '.join(providers)}; "
          f"not copied: {', '.join(n for n in detected if n not in providers) or 'none'})")
    for destination, mode, directory_mode, user, _gid in plan:
        print(f"adopt: {'would copy' if args.dry_run else 'copy'} -> {destination} mode {mode:04o} owner {user}")
    if args.dry_run:
        return 0

    status = 0
    for destination, mode, directory_mode, user, file_gid in plan:
        uid, gid = _ids(user, args.no_chown)
        # The exec copy's group is the mapped container gid; its directories keep the user's own gid.
        try:
            adoption.write_private_file(
                destination, data, mode=mode, directory_mode=directory_mode, uid=uid, gid=gid, base=root,
                file_gid=None if args.no_chown else file_gid,
            )
            if destination.name == adoption.AUTH_FILE_NAME and mode == 0o600:
                adoption.write_private_file(
                    destination.parents[2] / adoption.ADOPTION_MARKER_NAME,
                    adoption.marker_bytes(source, providers),
                    mode=0o600, directory_mode=directory_mode, uid=uid, gid=gid, base=root,
                )
            if args.model and destination.name == adoption.AUTH_FILE_NAME and destination.parent.name == 'agent-provider':
                adoption.write_private_file(
                    destination.parent / "model", (args.model.strip() + "\n").encode("utf-8"),
                    mode=0o644, directory_mode=directory_mode, uid=uid, gid=gid, base=root,
                )
        except adoption.AdoptionError as exc:
            print(f"adopt: FAILED {destination} ({exc.code}): {exc.detail}", file=sys.stderr)
            status = 1
            continue
        info = destination.stat()
        print(f"adopt: wrote {destination} {info.st_size} bytes mode {info.st_mode & 0o777:04o} uid {info.st_uid}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
