#!/usr/bin/env python3
"""Launch a pinned seed stage after observing the disposable Windows desktop.

Repairs the retained vm-r19 helper: QMP replies must succeed; no blind distro
unregister or receipt deletion; resolve the seed by label; verify its script.
This is host qualification tooling, never an installed runtime dependency.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import re
import socket
import stat
import time
from pathlib import Path

KEYS = {c: (c, False) for c in "abcdefghijklmnopqrstuvwxyz0123456789"}
KEYS.update({c.upper(): (c, True) for c in "abcdefghijklmnopqrstuvwxyz"})
KEYS[" "] = ("spc", False)
for plain, shifted, code in (
    ("`", "~", "grave_accent"), ("1", "!", "1"), ("2", "@", "2"),
    ("3", "#", "3"), ("4", "$", "4"), ("5", "%", "5"), ("6", "^", "6"),
    ("7", "&", "7"), ("8", "*", "8"), ("9", "(", "9"), ("0", ")", "0"),
    ("-", "_", "minus"), ("=", "+", "equal"), ("[", "{", "bracket_left"),
    ("]", "}", "bracket_right"), ("\\", "|", "backslash"), (";", ":", "semicolon"),
    ("'", '"', "apostrophe"), (",", "<", "comma"), (".", ">", "dot"), ("/", "?", "slash"),
):
    KEYS[plain] = (code, False)
    KEYS[shifted] = (code, True)


def stage_command(stage_sha256: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", stage_sha256):
        raise ValueError("a lowercase SHA-256 of the verified seed stage is required")
    # Keep the candidate's stage and product bytes unchanged. Old guest state
    # requires explicit inspection/preservation, never scripted deletion here.
    return (
        "& {$ErrorActionPreference='Stop';"
        "$p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());"
        "if(!$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'NOT_ELEVATED'};"
        "$v=@(Get-Volume -FileSystemLabel SPSEED);if($v.Count -ne 1){throw 'SEED_AMBIGUOUS'};"
        "$s=$v[0].DriveLetter+':\\stage-a18.ps1';"
        f"if((Get-FileHash -LiteralPath $s -Algorithm SHA256).Hash.ToLowerInvariant() -ne '{stage_sha256}')"
        "{throw 'STAGE_HASH_MISMATCH'};"
        "$d=(& wsl.exe --list --quiet | Out-String).Replace([string][char]0,'');"
        "if($LASTEXITCODE -ne 0){throw 'DISTRO_LIST_FAILED'};"
        "if(($d -split '\\r?\\n').Trim() -contains 'StatePort-Rehearsal-a18'){throw 'REHEARSAL_DISTRO_EXISTS'};"
        "if((Test-Path C:\\StatePort-r2\\receipt.json) -or (Test-Path C:\\StatePort-r2\\work\\distribution))"
        "{throw 'RETAINED_GUEST_EVIDENCE_EXISTS'};"
        "Set-ExecutionPolicy Bypass -Scope Process -Force;& $s}"
    )


class Qmp:
    def __init__(self, path: Path):
        import os
        info, parent = path.lstat(), path.parent.stat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                or parent.st_uid != os.getuid() or parent.st_mode & 0o077):
            raise ValueError("QMP requires a private, owned socket directory")
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile("rwb")
        self.seq = 0
        try:
            if "QMP" not in self.read():
                raise ValueError("missing QMP greeting")
            self.call("qmp_capabilities")
        except BaseException:
            self.close()
            raise

    def read(self):
        line = self.stream.readline(65537)
        if not line or len(line) > 65536:
            raise ValueError("invalid or closed QMP stream")
        return json.loads(line)

    def call(self, execute, arguments=None):
        self.seq += 1
        request = {"execute": execute, "id": self.seq}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write((json.dumps(request) + "\n").encode())
        self.stream.flush()
        for _ in range(100):
            reply = self.read()
            if reply.get("id") != self.seq:
                continue
            if "error" in reply or "return" not in reply:
                raise ValueError("QMP refused the requested action")
            return reply["return"]
        raise ValueError("QMP response limit reached")

    def key(self, code, down):
        self.call("input-send-event", {"events": [{"type": "key", "data": {
            "down": down, "key": {"type": "qcode", "data": code}}}]})

    def combo(self, *codes):
        try:
            for code in codes:
                self.key(code, True)
                time.sleep(.15)
        finally:
            errors = []
            for code in reversed(codes):
                try:
                    self.key(code, False)
                except Exception as exc:
                    errors.append(exc)
            if errors:
                raise errors[0]

    def type_text(self, value):
        sequence = [KEYS[c] for c in value]  # validate ALL text before input
        for code, shifted in sequence:
            try:
                if shifted:
                    self.key("shift", True)
                    time.sleep(.1)
                self.key(code, True)
                time.sleep(.2)
                self.key(code, False)
            finally:
                if shifted:
                    self.key("shift", False)
            time.sleep(.18)

    def close(self):
        self.stream.close()
        self.socket.close()


def validate_submission(observation_path: Path, capture: Path, stage_sha256: str):
    report = json.loads(observation_path.read_text())
    observed = report.get("observation", {})
    age = time.time() - datetime.strptime(report["observed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc).timestamp()
    if (report.get("scope") != "guest_screen_observation" or not -5 <= age <= 120
            or report.get("expected_stage_sha256") != stage_sha256
            or report.get("image_sha256") != hashlib.sha256(capture.read_bytes()).hexdigest()
            or observed.get("state") != "elevated_powershell"
            or observed.get("command_matches") != "yes"):
        raise ValueError("fresh visual evidence of the complete matching command in elevated PowerShell is required")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path)
    parser.add_argument("--stage-sha256", required=True)
    parser.add_argument("--plan", action="store_true", help="print the exact command; no socket or GUI access")
    parser.add_argument("--observed-elevated-console", action="store_true",
                        help="the isolated guest's elevated PowerShell console was actually observed and is focused")
    parser.add_argument("--capture", type=Path, help="new PNG screenshot after typing, before submission")
    parser.add_argument("--submit-observed-command", type=Path, help="fresh observe_guest JSON verifying the complete echoed command; sends Enter only")
    args = parser.parse_args(argv)
    command = stage_command(args.stage_sha256)
    if args.plan:
        print(command)
        return 0
    if not args.socket or not args.observed_elevated_console:
        parser.error("observe and focus the guest's elevated PowerShell console first; never infer it from QMP liveness")
    if not args.capture:
        parser.error("--capture is required so echoed input can be checked before Enter")
    if args.submit_observed_command:
        validate_submission(args.submit_observed_command, args.capture, args.stage_sha256)
    elif args.capture.exists():
        parser.error("capture already exists; inspect the prior attempt before typing again")
    qmp = Qmp(args.socket)
    try:
        if args.submit_observed_command:
            qmp.combo("ret")
        else:
            for start in range(0, len(command), 64):
                qmp.type_text(command[start:start + 64])
                time.sleep(.5)
            qmp.call("screendump", {"filename": str(args.capture.resolve()), "format": "png"})
    finally:
        qmp.close()
    if args.submit_observed_command:
        print("Stage command submitted once. Verify R2-START and terminal receipts; input success is not a test pass.")
    else:
        print("Command typed, NOT submitted. Verify the entire echo with observe_guest --expected-stage-sha256 before Enter.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
