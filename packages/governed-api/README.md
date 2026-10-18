# StatePort governed API

This package is the first headless API boundary for StatePort. It is a
transport-neutral, stdlib-only dispatcher over the existing lifecycle and
StateIR/StatePack contracts.

`GovernedAPI(workspace).dispatch(method, path, body)` returns a `Response` with
an HTTP-like status, JSON body, and headers. The default v1 instance is
read-only. When an embedding service configures identities and operator
capabilities, the same boundary also exposes one narrow approval-backed
mutation:

- `GET /health` and `GET /v1/capabilities`
- `POST /v1/validate/template`
- `POST /v1/validate/instance`
- `POST /v1/lifecycle/overrides`
- `POST /v1/lifecycle/upgrade-plan`
- `POST /v1/context/build`
- `POST /v1/context/inspect`
- `POST /v1/context/compare`
- `POST /v1/policy/check`
- `POST /v1/quota/check`
- `POST /v1/identity/check`
- `POST /v1/mutations/request`
- `POST /v1/approvals/decide`
- `POST /v1/approvals/list`
- `POST /v1/mutations/apply`
- `POST /v1/runs/plan`
- `POST /v1/runs/execute`
- `POST /v1/runs/list`
- `POST /v1/runs/inspect`

All filesystem paths are confined to the configured workspace. The supported
mutation is `materialize-instance`, which requires `write_state`, a persisted
approval, an instance-scoped operator identity, and post-write validation. No
automatic upgrade apply, arbitrary file write, model execution, container
process, authentication, or multi-tenant capability is included. The echo-run
routes are separately governed by `read_state`, quota admission, persistent
run records, audit correlation, and before/after canonical-state integrity
checks. A future HTTP service can adapt `Response` without moving policy into
a framework or allowing clients to edit workflow files directly.

The loopback adapter can add bearer authentication with
`STATEPORT_AUTH_TOKENS_JSON`. In that mode it binds the authenticated actor to
POST requests and rejects body identity spoofing. The transport-neutral API
still expects its embedding caller to provide a trusted actor context.
