"""Environment-configurable bearer authentication with no token persistence."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping


class AuthError(ValueError):
    """A safe authentication failure message."""


@dataclass(frozen=True)
class AuthenticatedActor:
    actor: str
    token_fingerprint: str


class BearerAuthenticator:
    """Map bearer tokens to preconfigured actor ids without storing secrets."""

    def __init__(self, tokens: Mapping[str, str] | None = None):
        self._token_hashes: dict[str, tuple[bytes, str]] = {}
        for actor, token in (tokens or {}).items():
            if not isinstance(actor, str) or not actor.strip():
                raise ValueError("authentication actor must be a non-empty string")
            if not isinstance(token, str) or len(token) < 16:
                raise ValueError("authentication tokens must contain at least 16 characters")
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            self._token_hashes[actor.strip()] = (digest, hashlib.sha256(token.encode("utf-8")).hexdigest()[:16])

    @property
    def configured(self) -> bool:
        return bool(self._token_hashes)

    def authenticate(self, authorization: Any) -> AuthenticatedActor:
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise AuthError("bearer authentication is required")
        token = authorization[7:].strip()
        if not token:
            raise AuthError("bearer authentication is required")
        candidate = hashlib.sha256(token.encode("utf-8")).digest()
        for actor, (expected, fingerprint) in self._token_hashes.items():
            if hmac.compare_digest(candidate, expected):
                return AuthenticatedActor(actor, fingerprint)
        raise AuthError("bearer authentication failed")

    @classmethod
    def from_json_mapping(cls, value: Any) -> "BearerAuthenticator":
        if not isinstance(value, Mapping):
            raise ValueError("authentication token configuration must be a mapping")
        return cls({str(actor): token for actor, token in value.items()})
