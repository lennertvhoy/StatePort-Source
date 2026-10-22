#!/usr/bin/env bash
# Scan an exact committed or staged tree without owner-local contamination.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="committed"
if [[ "${1:-}" == "--staged" ]]; then
    MODE="staged"
    shift
elif [[ "${1:-}" == "--working-tree" ]]; then
    MODE="working-tree"
    shift
fi

SCAN_ROOT="$ROOT"
TEMP_ROOT=""
if [[ "$MODE" != "working-tree" ]]; then
    TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/stateport-gitleaks.XXXXXX")"
    trap 'rm -rf -- "$TEMP_ROOT"' EXIT
    SCAN_ROOT="$TEMP_ROOT/tree"
    mkdir -p "$SCAN_ROOT"
    if [[ "$MODE" == "staged" ]]; then
        git -C "$ROOT" checkout-index --all --prefix="$SCAN_ROOT/"
    else
        git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$SCAN_ROOT"
    fi
fi

CONFIG="$SCAN_ROOT/.gitleaks.toml"
if [[ ! -f "$CONFIG" ]]; then
    echo "gitleaks configuration is absent from the selected source tree" >&2
    exit 2
fi

if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --source="$SCAN_ROOT" --config="$CONFIG" --no-git --redact --no-banner "$@"
    exit $?
fi

if command -v podman >/dev/null 2>&1; then
    podman run --rm -w /repo -v "$SCAN_ROOT:/repo:ro,Z" \
        zricethezav/gitleaks:v8.24.2 detect --source=. --config=.gitleaks.toml --no-git --redact --no-banner "$@"
    exit $?
fi

if command -v docker >/dev/null 2>&1; then
    docker run --rm -w /repo -v "$SCAN_ROOT:/repo:ro" \
        zricethezav/gitleaks:v8.24.2 detect --source=. --config=.gitleaks.toml --no-git --redact --no-banner "$@"
    exit $?
fi

echo "gitleaks is required; install gitleaks or podman/docker to run the scan" >&2
exit 2
