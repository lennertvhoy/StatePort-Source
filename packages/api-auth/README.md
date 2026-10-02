# Local API authentication

`stateport_auth` provides bearer-token authentication for the loopback HTTP
adapter. Tokens are supplied by an environment variable, hashed in memory,
compared with `hmac.compare_digest`, and never returned or written to audit
records. The authenticated actor is bound to the request body by the HTTP
adapter, so a caller cannot assert a different configured identity.

An empty token mapping is unconfigured. The HTTP launcher fails closed when
identities or operator capabilities are configured without at least one bearer
credential; its empty local default remains unauthenticated and read-only.

This is a local self-hosting credential boundary, not an identity provider or
hosted OIDC lifecycle. Use a real identity provider, trusted JWKS injection,
and a secret store before exposing the service outside a controlled local
deployment.

## Pinned OIDC JWT contract

`OIDCAuthenticator` is the independent, offline SP-023 authentication
primitive. It verifies RS256 JWTs against a statically supplied public JWKS and
performs no discovery, HTTP request, introspection, or key refresh. A minimal
configuration passed to `OIDCAuthenticator.from_mapping(...)` is:

```json
{
  "issuer": "https://identity.example/tenant/v2.0",
  "audience": "stateport-api",
  "jwks": {
    "keys": [
      {"kid": "signing-key-1", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "PUBLIC_MODULUS", "e": "AQAB"}
    ]
  },
  "subjectActors": {"provider-subject-id": "local-actor-id"},
  "leewaySeconds": 60
}
```

The authenticator requires a unique `kid`, an RSA modulus of at least 2048
bits, a valid RS256 signature, exact issuer and audience, `exp`, and `sub`.
Optional `nbf` and `iat` are checked with a configurable leeway bounded to
0–300 seconds. Malformed or duplicate JWT JSON keys, non-canonical base64url,
algorithm confusion, unknown subjects, and invalid time claims fail closed with
safe errors.

`subjectActors` is the only claim-to-local-identity bridge. Token roles, groups,
scopes, capabilities, actor names, and other authorization-looking claims are
ignored; StatePort authorization remains configured separately. Successful
authentication returns only `AuthenticatedActor(actor, token_fingerprint)`.
Tokens and claims are not retained or returned.

Production deployment must inject an issuer-pinned JWKS through trusted
configuration and replace it when the provider rotates signing keys. TLS,
interactive OIDC flows, discovery, revocation, logout, and refresh are outside
this offline validator and remain the embedding service's responsibility.
