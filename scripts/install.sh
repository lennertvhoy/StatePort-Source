#!/usr/bin/env bash
# StatePort local installer.
#
# Computes exact Git provenance for the web image build (so the shipped OCI
# image records this checkout instead of "unknown"), then builds and starts
# the Compose stack and waits for all three health endpoints.
#
# Usage:
#   ./scripts/install.sh [--check|--dry-run]
#
# Optional environment overrides (used by automated cold-run tests on hosts
# where the default ports are occupied; not needed for a normal install):
#   STATEPORT_COMPOSE_FILES  full compose file argument list, default
#                            "-f <repo>/docker-compose.yml"
#   STATEPORT_WEB_PORT             default 8080
#   STATEPORT_HEALTH_TIMEOUT       seconds to wait for health, default 180

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODE="install"
case "${1:-}" in
    "") ;;
    --check) MODE="check" ;;
    --dry-run) MODE="dry-run" ;;
    --help|-h)
        echo "Usage: ./scripts/install.sh [--check|--dry-run]"
        echo "  --check    verify local prerequisites and source provenance only"
        echo "  --dry-run  print the exact Compose command without building or starting"
        exit 0
        ;;
    *)
        echo "install.sh: error: unknown argument: $1" >&2
        echo "Usage: ./scripts/install.sh [--check|--dry-run]" >&2
        exit 2
        ;;
esac
if [ "$#" -gt 1 ]; then
    echo "install.sh: error: expected at most one argument" >&2
    exit 2
fi

WEB_PORT="${STATEPORT_WEB_PORT:-8080}"
HEALTH_TIMEOUT="${STATEPORT_HEALTH_TIMEOUT:-180}"

fail() {
    echo "install.sh: error: $*" >&2
    exit 1
}

require_port() {
    name="$1"
    value="$2"
    case "$value" in
        ""|*[!0-9]*) fail "$name must be an integer from 1 to 65535 (received: $value)." ;;
    esac
    if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
        fail "$name must be an integer from 1 to 65535 (received: $value)."
    fi
}

require_port "STATEPORT_WEB_PORT" "$WEB_PORT"
if [ "$WEB_PORT" = "8790" ] || [ "$WEB_PORT" = "8791" ]; then
    fail "STATEPORT_WEB_PORT must be distinct from the internal API (8790) and worker (8791) ports."
fi
case "$HEALTH_TIMEOUT" in
    ""|*[!0-9]*) fail "STATEPORT_HEALTH_TIMEOUT must be a positive integer (received: $HEALTH_TIMEOUT)." ;;
esac
if [ "$HEALTH_TIMEOUT" -lt 1 ]; then
    fail "STATEPORT_HEALTH_TIMEOUT must be a positive integer (received: $HEALTH_TIMEOUT)."
fi

# --- Prerequisites ---------------------------------------------------------

COMPOSE=()
COMPOSE_PROVIDER=""
PODMAN_COMPOSE_IMPLEMENTATION=""
if command -v podman >/dev/null 2>&1; then
    if PODMAN_COMPOSE_VERSION="$(podman compose version 2>&1)"; then
        COMPOSE=(podman compose)
        COMPOSE_PROVIDER="podman"
        if printf '%s\n' "$PODMAN_COMPOSE_VERSION" | grep -q 'podman-compose version'; then
            PODMAN_COMPOSE_IMPLEMENTATION="podman-compose"
        else
            PODMAN_COMPOSE_IMPLEMENTATION="external-compose"
        fi
    elif command -v podman-compose >/dev/null 2>&1; then
        COMPOSE=(podman-compose)
        COMPOSE_PROVIDER="podman"
        PODMAN_COMPOSE_IMPLEMENTATION="podman-compose"
    fi
fi
if [ "${#COMPOSE[@]}" -eq 0 ] && command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
        COMPOSE=(docker compose)
        COMPOSE_PROVIDER="docker"
    fi
fi
if [ "${#COMPOSE[@]}" -eq 0 ]; then
    fail "no container engine found. Install Podman with podman-compose (reference setup) or Docker with the Compose plugin, then re-run."
fi
command -v git >/dev/null 2>&1 || fail "git is required to compute build provenance."
command -v curl >/dev/null 2>&1 || fail "curl is required for the health checks."
command -v python3 >/dev/null 2>&1 || fail "python3 is required to verify the public-alpha application catalog."
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "$REPO_ROOT is not a Git checkout; provenance cannot be computed."
[ -f "$REPO_ROOT/docker-compose.yml" ] || fail "docker-compose.yml is missing from the checkout."
[ -f "$REPO_ROOT/scripts/public_alpha_preflight.py" ] || fail "scripts/public_alpha_preflight.py is missing from the checkout."

if [ "$PODMAN_COMPOSE_IMPLEMENTATION" = "podman-compose" ]; then
    # Rootless Podman normally starts the image as namespace root.  The
    # Bubblewrap boundary used for approved filesystem transactions must be an
    # ordinary mapped user so it can create its own narrower user namespace.
    # podman-compose otherwise creates a shared pod before its container create
    # commands, and that pod silently prevents PODMAN_USERNS from taking effect.
    # Keep the services on their Compose network without a shared Podman pod so
    # every container inherits the explicit keep-id default. Docker is unchanged.
    COMPOSE+=("--in-pod=false")
fi
if [ "$COMPOSE_PROVIDER" = "podman" ]; then
    export PODMAN_USERNS=keep-id
    if [ "$PODMAN_COMPOSE_IMPLEMENTATION" = "podman-compose" ]; then
        echo "install.sh: Podman container mode: no shared pod"
    else
        echo "install.sh: Podman Compose provider manages service networks without podman-compose pod flags"
    fi
    echo "install.sh: Podman user namespace: keep-id"
fi
echo "install.sh: using compose provider: ${COMPOSE[*]}"

# --- Build provenance ------------------------------------------------------

STATEPORT_BUILD_SOURCE_COMMIT="$(git rev-parse --verify HEAD)"
export STATEPORT_BUILD_SOURCE_COMMIT
STATEPORT_BUILD_SOURCE_TREE="$(git rev-parse --verify "${STATEPORT_BUILD_SOURCE_COMMIT}^{tree}")"
export STATEPORT_BUILD_SOURCE_TREE
REF="$(git symbolic-ref --quiet --short HEAD || true)"
export STATEPORT_BUILD_SOURCE_REF="${REF:-detached}"
if [ -n "$(git status --porcelain)" ]; then
    export STATEPORT_BUILD_SOURCE_DIRTY="true"
else
    export STATEPORT_BUILD_SOURCE_DIRTY="false"
fi
STATEPORT_BUILD_SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$STATEPORT_BUILD_SOURCE_COMMIT")"
export STATEPORT_BUILD_SOURCE_DATE_EPOCH
STATEPORT_BUILD_VERSION="0.0.0-source.${STATEPORT_BUILD_SOURCE_COMMIT:0:12}"
export STATEPORT_BUILD_VERSION
STATEPORT_BUILD_CREATED="$(python3 - "$STATEPORT_BUILD_SOURCE_DATE_EPOCH" <<'PY'
from datetime import datetime, timezone
import sys

print(datetime.fromtimestamp(int(sys.argv[1]), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
export STATEPORT_BUILD_CREATED
STATEPORT_BUILD_ADAPTER="${COMPOSE_PROVIDER}-${PODMAN_COMPOSE_IMPLEMENTATION:-compose}"
export STATEPORT_BUILD_ADAPTER

echo "install.sh: provenance commit=${STATEPORT_BUILD_SOURCE_COMMIT} tree=${STATEPORT_BUILD_SOURCE_TREE} ref=${STATEPORT_BUILD_SOURCE_REF} dirty=${STATEPORT_BUILD_SOURCE_DIRTY} epoch=${STATEPORT_BUILD_SOURCE_DATE_EPOCH} version=${STATEPORT_BUILD_VERSION} created=${STATEPORT_BUILD_CREATED} adapter=${STATEPORT_BUILD_ADAPTER}"

# --- Build and start -------------------------------------------------------

if [ -n "${STATEPORT_COMPOSE_FILES:-}" ]; then
    # The override is intended for automated cold-run tests. It remains an
    # argument list (not shell code); whitespace in an override path is not
    # supported. The normal checkout path is preserved as one exact argument.
    read -r -a COMPOSE_FILE_ARGS <<< "$STATEPORT_COMPOSE_FILES"
else
    COMPOSE_FILE_ARGS=(-f "$REPO_ROOT/docker-compose.yml")
fi
COMPOSE_UP=("${COMPOSE[@]}" "${COMPOSE_FILE_ARGS[@]}" up -d --build)

if [ "$MODE" = "check" ]; then
    echo "install.sh: prerequisites ready; no containers were built or started."
    exit 0
fi
if [ "$MODE" = "dry-run" ]; then
    printf 'install.sh: dry-run command:'
    printf ' %q' "${COMPOSE_UP[@]}"
    printf '\n'
    echo "install.sh: no containers were built or started."
    exit 0
fi

"${COMPOSE_UP[@]}"

# --- Wait for health -------------------------------------------------------

wait_host_healthy() {
    deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if curl -fsS -o /dev/null "http://127.0.0.1:${WEB_PORT}/health" 2>/dev/null; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_internal_healthy() {
    service="$1"
    port="$2"
    path="$3"
    deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if "${COMPOSE[@]}" "${COMPOSE_FILE_ARGS[@]}" exec -T "$service" \
            /usr/local/bin/stateport-healthcheck --kind http --host 127.0.0.1 \
            --port "$port" --path "$path" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    return 1
}

if wait_host_healthy; then
    echo "install.sh: healthy: http://127.0.0.1:${WEB_PORT}/health"
else
    fail "StatePort web did not become healthy within ${HEALTH_TIMEOUT}s. Inspect with: ${COMPOSE[*]} ps && ${COMPOSE[*]} logs"
fi
for service_port_path in "stateport-api:8790:/readyz" "stateport-worker:8791:/readyz"; do
    IFS=: read -r service port path <<< "$service_port_path"
    if wait_internal_healthy "$service" "$port" "$path"; then
        echo "install.sh: healthy internal service: ${service}"
    else
        fail "${service} did not become healthy inside the private Compose network within ${HEALTH_TIMEOUT}s. Inspect with: ${COMPOSE[*]} ps && ${COMPOSE[*]} logs"
    fi
done

# Generic /health is necessary but not sufficient for the public-alpha route:
# verify the exact fictional package is catalogued, installable, and declares
# no network dependency before directing the user to the browser.
python3 "$REPO_ROOT/scripts/public_alpha_preflight.py" \
    --base-url "http://127.0.0.1:${WEB_PORT}"

echo ""
echo "StatePort is running."
echo "Open: http://127.0.0.1:${WEB_PORT}/#/applications"
echo "Choose StudyState Sample to review and give explicit browser confirmation for the local fictional sample installation."
