# StatePort API adapter

`stateport_api.http` is the thin stdlib HTTP adapter for the transport-neutral
`governed_api` package. It binds to loopback by default. With no identities or
operator capabilities configured, the launcher remains unauthenticated and
read-only.

Authorization policy is configured with:

- `STATEPORT_IDENTITIES_JSON`
- `STATEPORT_OPERATOR_CAPABILITIES` (comma-separated)

Any non-empty authorization configuration requires exactly one HTTP
authentication mode:

- `STATEPORT_AUTH_TOKENS_JSON`: local actor-to-bearer mapping injected as a
  secret; tokens are constant-time checked and never persisted.
- `STATEPORT_OIDC_CONFIG_JSON`: pinned issuer, audience, static public JWKS,
  leeway, and explicit provider-subject-to-local-actor mappings.

The two authentication variables are mutually exclusive. Authenticated POSTs
receive a server-injected actor and a conflicting body actor is rejected.
Static OIDC validation performs no discovery, key refresh, revocation, login,
or session handling; those remain embedding-service responsibilities.

The adapter exposes lifecycle/context operations, approval-backed
materialisation, deterministic echo runs, and the queued `container_echo`
flow. The API can request approval and enqueue a durable job, but never starts
the container itself. Relevant execution configuration is
`STATEPORT_CONTAINER_ENGINE` plus `STATEPORT_RUNNER_IMAGE`; execution approval
requires the latter to be an immutable SHA-256 image ID/reference.

The API and worker share operational queue/usage metadata below `.stateport`.
The default Compose shape shares that volume but leaves worker execution off
and supplies no engine socket. Do not place bearer tokens, OIDC configuration,
provider credentials, or other secrets in repository or Compose files.
