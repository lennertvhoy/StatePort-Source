# Local alpha observability

StatePort emits local operational diagnostics as newline-delimited JSON using
the `stateport.operational-event/v1` contract. These events help an operator
diagnose service health and transitions; they are not canonical StateSpec
state, authority receipts, acceptance evidence, or billing records.

## Configuration

`STATEPORT_LOG_LEVEL` accepts exactly `debug`, `info`, `warning`, or `error` and
defaults to `info`. An invalid value prevents API or worker startup instead of
silently changing the configured threshold. Source Compose passes the value to
both services explicitly.

The alpha services write JSONL only to local stdout. Compose configures a
bounded `json-file` log (`1m`, three files) for the API and worker. This is a
container-engine retention setting, not a promise about an external log store.
The shared library also provides a local rotating-file sink that creates files
with mode `0600`, rejects symlinks, preserves complete records, and bounds file
count and size. No network exporter or phone-home telemetry is enabled.

## Event boundary

Every event has a timestamp, level, service, and stable event name. Only a
small set of typed scalar fields is accepted: request/result metadata and
opaque instance, deployment, capsule, workspace, revision, job, run, worker,
and receipt identities. Records are limited to 8 KiB.

The contract has no fields for request or response bodies, headers, query
strings, cookies, filesystem paths, command arguments, terminal frames,
conversation content, exception text, stdout/stderr, or tracebacks. Credential
pattern redaction is defense in depth, not permission to log those values.
Observer failures increment an in-process dropped-event counter and cannot
reverse or misreport a product transition.

## Health and readiness

The API and worker expose:

- `/livez`: the process and HTTP listener are alive;
- `/readyz`: already-constructed local dependencies are ready to serve;
- `/health`: the compatible product diagnostics surface.

Readiness checks are cheap, read-only, and network-free. A worker with execution
deliberately disabled is healthy standby. An enabled worker whose loop is not
running is unready. Raw exception messages are never returned by health APIs.
Routine probe completion events are debug-level to avoid log noise.

## Operator checks

```bash
curl --fail http://127.0.0.1:8790/livez
curl --fail http://127.0.0.1:8790/readyz
curl --fail http://127.0.0.1:8791/readyz
docker compose logs --tail 200 stateport-api stateport-worker
./stateport doctor --root .
```

When diagnosing an incident, preserve the exact service, runtime/image
identity, request ID, receipt digest, timestamps, and bounded log files. Keep
the authoritative deployment, workspace, update, backup, or authority receipt
as the source of transition truth. Never paste secret values or private
application content into an incident record.

## Current alpha boundary

API and worker HTTP completion events, strict log levels, liveness/readiness,
bounded Compose logs, and safe worker failure codes are implemented. Durable
deployment/workspace receipt projections, updater/capsule/preview events, and
optional Prometheus/OpenTelemetry adapters remain later slices. External
telemetry stays disabled unless a future operator policy explicitly enables a
reviewed adapter.
