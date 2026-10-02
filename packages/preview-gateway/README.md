# StatePort preview gateway

The preview gateway is the only product path from the installed web
application to a workload's development/preview servers. It owns an
authenticated route registry and a loopback-only reverse proxy (HTTP and
WebSocket) mounted inside the web AppServer under `/preview/`.

## Trust model

- A preview route binds an opaque `(capsuleId, serviceId, revisionDigest)`
  triple to exactly one loopback upstream (`127.0.0.1`, port). `capsuleId`
  stays an opaque namespaced binding owned by the deployment record; the
  gateway never interprets it. Upstreams are loopback by construction —
  registration has no host field — so the gateway cannot be turned into an
  SSRF primitive.
- The dev-server port is never published directly by the product; the
  registry-proxied `/preview/{capsuleId}/{serviceId}/...` path is the only
  route to it, and every proxied request requires the operator session.
- Cookie isolation: inbound `Cookie` (including `stateport_session`),
  `Origin`, and `X-StatePort-CSRF` headers are stripped before forwarding.
  Upstream `Set-Cookie` values are rewritten to host-only cookies scoped to
  `Path=/preview/{capsuleId}/{serviceId}` with `Domain`, `SameSite`,
  `Secure`, and expiry attributes dropped, so a preview can never claim the
  application origin or another capsule's routes.
- The preview namespace fails closed: `engine`, `engine-socket`,
  `metadata`, `control-plane`, `session`, `health`, `v1`, and `api` are
  refused at registration and at resolution, path traversal is rejected,
  and a route registered for one capsule cannot be reached through another
  capsule's path.
- Routes expire (`expiresAt`) and can be revoked; both refuse typed at
  resolution time.

## Registry and receipts

`PreviewRouteRegistry` is a single-writer store under the operator's state
root (`preview-gateway/`). Every mutation runs under an exclusive lock,
rewrites the route document with an atomic replace, and appends a chained
`stateport.preview-route-receipt/v1` receipt (`registered`, `rewritten`,
`revoked`). The `rewritten` event is the rollback path: when a deployment
rolls a capsule back to an exact predecessor revision, the route's
`revisionDigest` and upstream port are rebound in one locked, atomic write
so in-flight proxy requests never observe a partial binding.

Documents are validated against
`schemas/preview-route.v1.schema.json` and
`schemas/preview-route-receipt.v1.schema.json`; route and receipt digests
bind the exact content, and the receipt chain is re-validated on every
read.
