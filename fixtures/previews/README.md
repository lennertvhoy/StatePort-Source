# Preview fixtures

Plain-Python fixtures for the preview gateway.

- `echo_server.py` — a loopback-only HTTP + WebSocket echo server standing in
  for a workload development server (HMR-style). It binds `127.0.0.1` only and
  is never published by the product: the authenticated preview-gateway route
  under `/preview/{capsuleId}/{serviceId}/` is the only product path to it.
  Endpoints: `/__headers` (echoes received headers, reports whether any
  `Cookie` arrived), `/__set-cookie` (emits hostile `Domain`/`Path` cookies so
  tests can prove the gateway rewrites them), `/__redirect` (root-relative
  redirect), `/ws` (WebSocket echo with subprotocol negotiation), and a
  catch-all JSON echo.

These fixtures are invented test assets; they contain no third-party content.
