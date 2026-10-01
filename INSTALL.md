# Install

> Run the StatePort product locally with one command.

This page covers the source-checkout Compose path. A verified no-checkout
install path (signed release index, digest-pinned images, rootless Quadlet)
exists as a private alpha candidate; it is not offered as a public download
yet.

## Prerequisites

- Linux with either:
  - **Podman** with `podman-compose` installed (the reference setup), or
  - **Docker** with the Compose plugin (`docker compose`).
- `git`, `curl`, and Python 3 on the host (used for build provenance, health
  checks, and the provider-free application preflight).
- No other dependencies; everything else runs inside the containers.

## Run

From the repository root:

```bash
./scripts/install.sh
```

Then open <http://127.0.0.1:8080>.

The installer checks prerequisites, stamps the web image with the exact Git
provenance of this checkout (commit, ref, dirty flag, source-date-epoch),
builds and starts the stack with the available engine, and waits until all
three health endpoints respond before printing the URL.

### Manual alternative

If you prefer to drive Compose directly:

```bash
podman compose up -d --build
# or, with Docker:
docker compose up -d --build
```

Note that the raw command builds the web image with `unknown` provenance;
`scripts/install.sh` exists to export the `STATEPORT_BUILD_SOURCE_*` build
arguments from the checkout before building.

This starts three services, all bound to loopback only:

- **stateport-web** — the application product (same-origin AppServer) on `127.0.0.1:8080`
- **stateport-api** — the governed local API on `127.0.0.1:8790`
- **stateport-worker** — the governed run worker on `127.0.0.1:8791`

Nothing listens on a non-loopback interface.

## Stop and reset

```bash
# Stop the stack (data volumes are kept):
podman compose down

# Stop and delete all local data (full reset):
podman compose down -v
```

## Limits

- Linux-first. macOS and Windows are untested: the web service is
  port-mapped (`127.0.0.1:8080:8080`) so it also works under Docker
  Desktop, where host networking is a no-op, but that path has not been
  exercised.
- The web container binds non-loopback inside its private bridge network
  under an explicit `--allow-public-bind` flag; host exposure stays
  loopback-only on every platform, so the AppServer loopback contract is
  preserved. Ports 8080, 8790, and 8791 on `127.0.0.1` must be free
  before starting.
- This is a local-alpha install. It is not a hosted or production
  deployment; see the local-alpha boundaries in `README.md`.
