#!/usr/bin/env bash
# Reproduce the load-dependent failures in scripts/test_execution_host_daemon.py.
#
# WHY THIS EXISTS. Those failures appear in the full 238-file suite (7 of them on
# 2026-09-30) and do NOT appear when the same file runs alone. The recorded
# explanation was "the discriminator is LOAD, not run order", offered as a hypothesis
# with the falsifying step deferred to a 35-minute full-suite re-run. That re-run is
# expensive and, per the record, had not isolated anything.
#
# This script is the cheap version. Two concurrent copies of the SAME file put load on
# the host without changing anything else, and the failure appears in ~80 seconds.
# Measured on 2026-09-30, scripts/test_execution_host_daemon.py:
#
#   isolation, 1 copy        14 passed, 3 skipped in 68s   (matches the recorded baseline)
#   2 concurrent copies      8 failed,  6 passed, 3 skipped in 71s
#                            6 failed,  8 passed, 3 skipped in 84s
#
# A stable core of five tests failed in BOTH concurrent runs:
#   test_kill9_restart_reconciles_ledger_and_container
#   test_workspace_recovery_and_real_history_survive_restarts
#   test_two_grant_owned_workspaces_remain_independent
#   test_workspace_exec_exit_status_is_trustworthy_and_unbounded_output_honest
#   test_terminal_session_flows_through_the_broker_gateway
# The remainder varied between runs, so "the varying subset" is not purely random:
# there is a stable core plus per-run extras.
#
# WHAT THIS DOES NOT CLAIM. It reproduces the condition; it does not diagnose the
# cause. A timing-sensitive reconciliation at
# packages/execution-host/src/execution_host/ledger.py:803 is the standing hypothesis
# and remains unproven - "reproduces under load" is not "the reconciliation is the
# mechanism". Do not record a cause from this script alone.
#
# It also does not touch the 24 pre-existing `stateport-release-registry` containers
# on this host. They are release-related residue, and removing them to make a test
# pass would destroy the evidence of the residue.
#
# Usage:  bash scripts/repro_daemon_load_flake.sh [concurrent-copies]
# Exits 0 if the baseline is clean, 1 if the baseline already fails, 2 if the
# reproducer did not reproduce. Non-zero "did not reproduce" is a real result: the
# condition is load-sensitive, so a quiet or heavily loaded host can mask it.
set -uo pipefail

COPIES="${1:-2}"
FILE="scripts/test_execution_host_daemon.py"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

if [ ! -f "$FILE" ]; then
  echo "missing $FILE; run from the repository root" >&2
  exit 1
fi

echo "== baseline: $FILE alone =="
timeout 900 python3 -m pytest "$FILE" -q -p no:randomly > "$OUT/base.txt" 2>&1
tail -1 "$OUT/base.txt"
if grep -qE '^[1-9][0-9]* failed' "$OUT/base.txt"; then
  echo "baseline already fails in isolation - the load hypothesis is not what is being tested here" >&2
  exit 1
fi

echo "== load: $COPIES concurrent copies of the same file =="
for i in $(seq 1 "$COPIES"); do
  ( timeout 900 python3 -m pytest "$FILE" -q -p no:randomly > "$OUT/c$i.txt" 2>&1 ) &
done
wait

repro=0
for i in $(seq 1 "$COPIES"); do
  line="$(tail -1 "$OUT/c$i.txt")"
  echo "  copy $i: $line"
  grep -qE '^[1-9][0-9]* failed' "$OUT/c$i.txt" && repro=1
  grep -oE '^FAILED [^ ]+' "$OUT/c$i.txt" 2>/dev/null \
    | sed "s#^FAILED $FILE::#    #" || true
done

# Residue check: the recorded runs left zero containers behind, and that must stay true
# under load too, or the reproducer is trading a flake for a leak.
#
# CORRECTED 2026-09-30. This previously used `grep -c '^wt1-'`, which is a NO-OP: the
# engine names containers `stateport-exec-{workload_id}` (engine.py:227), so a workload
# named `wt1-abc` is `stateport-exec-wt1-abc` and never starts with `wt1-`. The old guard
# reported 0 unconditionally - it could not have detected residue even if residue existed,
# and its "0" was quoted as verification. Independent verification caught it.
#
# The pattern is now the real one, and a POSITIVE CONTROL runs first so this guard can
# never silently become a no-op again: it asserts that the pattern matches the sample name
# it is supposed to match, and refuses to report a residue count if it does not.
RESIDUE_PATTERN='^stateport-exec-'
if command -v podman >/dev/null 2>&1; then
  if ! printf 'stateport-exec-wt1-selfcheck\n' | grep -qE "$RESIDUE_PATTERN"; then
    echo "GUARD BROKEN: pattern '$RESIDUE_PATTERN' does not match the expected container" \
         "name shape; refusing to report a residue count." >&2
  else
    left="$(podman ps -a --format '{{.Names}}' 2>/dev/null | grep -cE "$RESIDUE_PATTERN" || true)"
    echo "== stateport-exec-* containers left resident: $left =="
    [ "${left:-0}" -ne 0 ] && echo "WARNING: reproducer left residue behind" >&2
  fi
fi

if [ "$repro" -eq 1 ]; then
  echo "REPRODUCED: failures appear only under concurrent load."
  exit 0
fi
echo "NOT REPRODUCED: $COPIES concurrent copies stayed clean. Treat as a real result:" >&2
echo "the condition is load-sensitive, so host load can mask it." >&2
exit 2
