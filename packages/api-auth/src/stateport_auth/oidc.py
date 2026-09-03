"""Pinned, offline OIDC JWT authentication with no discovery or network I/O."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from stateport_auth.bearer import AuthError, AuthenticatedActor


_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_TOKEN_LENGTH = 16_384
_MAX_LEEWAY_SECONDS = 300
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_PRIVATE_RSA_PARAMETERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})


@dataclass(frozen=True)
class _RSAKey:
    kid: str
    modulus: int
    exponent: int
    size_bytes: int


def _nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a non-empty trimmed string")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JWT JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON numeric constant: {value}")


def _decode_base64url(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or not value or _B64URL.fullmatch(value) is None:
        raise ValueError(f"{name} must be unpadded base64url")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError(f"{name} must be unpadded base64url") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ValueError(f"{name} must use canonical base64url encoding")
    return decoded


def _decode_json_segment(value: str, name: str) -> dict[str, Any]:
    raw = _decode_base64url(value, name)
    if len(raw) > 8_192:
        raise ValueError(f"{name} is too large")
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(f"{name} must contain a JSON object") from exc
    if not isinstance(decoded, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return decoded


def _decode_uint(value: Any, name: str) -> int:
    raw = _decode_base64url(value, name)
    if raw[0] == 0:
        raise ValueError(f"{name} must use the minimal unsigned encoding")
    return int.from_bytes(raw, "big")


def _numeric_date(claims: Mapping[str, Any], name: str, *, required: bool) -> float | None:
    if name not in claims:
        if required:
            raise ValueError(f"JWT claim {name} is required")
        return None
    value = claims[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"JWT claim {name} must be a NumericDate")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"JWT claim {name} must be finite")
    return result


class OIDCAuthenticator:
    """Validate RS256 JWTs against one pinned issuer and static public JWKS."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks: Mapping[str, Any],
        subject_actors: Mapping[str, str],
        leeway_seconds: int = 60,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.issuer = _nonempty_string(issuer, "issuer")
        self.audience = _nonempty_string(audience, "audience")
        if (
            isinstance(leeway_seconds, bool)
            or not isinstance(leeway_seconds, int)
            or not 0 <= leeway_seconds <= _MAX_LEEWAY_SECONDS
        ):
            raise ValueError(
                f"leewaySeconds must be an integer between 0 and {_MAX_LEEWAY_SECONDS}"
            )
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self.leeway_seconds = leeway_seconds
        self._clock = clock or time.time
        self._keys = self._parse_jwks(jwks)
        self._subject_actors = self._parse_subject_actors(subject_actors)

    @property
    def configured(self) -> bool:
        return True

    @staticmethod
    def _parse_subject_actors(value: Mapping[str, str]) -> dict[str, str]:
        if not isinstance(value, Mapping) or not value:
            raise ValueError("subjectActors must be a non-empty mapping")
        result: dict[str, str] = {}
        for subject, actor in value.items():
            normalized_subject = _nonempty_string(subject, "subjectActors subject")
            normalized_actor = _nonempty_string(actor, "subjectActors actor")
            result[normalized_subject] = normalized_actor
        return result

    @staticmethod
    def _parse_jwks(value: Mapping[str, Any]) -> dict[str, _RSAKey]:
        if not isinstance(value, Mapping):
            raise ValueError("jwks must be a mapping")
        keys = value.get("keys")
        if not isinstance(keys, (list, tuple)) or not keys:
            raise ValueError("jwks.keys must be a non-empty collection")
        result: dict[str, _RSAKey] = {}
        for raw_key in keys:
            if not isinstance(raw_key, Mapping):
                raise ValueError("each JWK must be a mapping")
            if _PRIVATE_RSA_PARAMETERS & set(raw_key):
                raise ValueError("JWKS must contain public RSA parameters only")
            kid = _nonempty_string(raw_key.get("kid"), "JWK kid")
            if kid in result:
                raise ValueError("JWK kid values must be unique")
            if raw_key.get("kty") != "RSA":
                raise ValueError("JWK kty must be RSA")
            if raw_key.get("alg") not in (None, "RS256"):
                raise ValueError("JWK alg must be RS256 when present")
            if raw_key.get("use") not in (None, "sig"):
                raise ValueError("JWK use must be sig when present")
            key_ops = raw_key.get("key_ops")
            if key_ops is not None:
                if (
                    not isinstance(key_ops, (list, tuple))
                    or not key_ops
                    or not all(isinstance(item, str) for item in key_ops)
                    or len(set(key_ops)) != len(key_ops)
                    or "verify" not in key_ops
                ):
                    raise ValueError("JWK key_ops must be a unique collection containing verify")
            modulus = _decode_uint(raw_key.get("n"), "JWK n")
            exponent = _decode_uint(raw_key.get("e"), "JWK e")
            if modulus.bit_length() < 2_048 or modulus % 2 == 0:
                raise ValueError("RSA modulus must be an odd integer of at least 2048 bits")
            if exponent < 3 or exponent % 2 == 0 or exponent > 0xFFFFFFFF:
                raise ValueError("RSA public exponent is invalid")
            if math.gcd(modulus, exponent) != 1:
                raise ValueError("RSA modulus and exponent must be coprime")
            result[kid] = _RSAKey(
                kid=kid,
                modulus=modulus,
                exponent=exponent,
                size_bytes=(modulus.bit_length() + 7) // 8,
            )
        return result

    @classmethod
    def from_mapping(
        cls,
        value: Any,
        *,
        clock: Callable[[], float] | None = None,
    ) -> "OIDCAuthenticator":
        if not isinstance(value, Mapping):
            raise ValueError("OIDC configuration must be a mapping")
        required = {"issuer", "audience", "jwks", "subjectActors"}
        allowed = required | {"leewaySeconds"}
        missing = required - set(value)
        if missing:
            raise ValueError(f"OIDC configuration is missing: {', '.join(sorted(missing))}")
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"OIDC configuration contains unknown keys: {', '.join(sorted(map(str, unknown)))}")
        return cls(
            issuer=value["issuer"],
            audience=value["audience"],
            jwks=value["jwks"],
            subject_actors=value["subjectActors"],
            leeway_seconds=value.get("leewaySeconds", 60),
            clock=clock,
        )

    @staticmethod
    def _bearer_token(authorization: Any) -> str:
        if not isinstance(authorization, str):
            raise AuthError("bearer authentication is required")
        parts = authorization.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            raise AuthError("bearer authentication is required")
        token = parts[1].strip()
        if len(token) > _MAX_TOKEN_LENGTH:
            raise AuthError("OIDC bearer authentication failed")
        return token

    @staticmethod
    def _verify_signature(key: _RSAKey, signing_input: bytes, signature: bytes) -> None:
        if len(signature) != key.size_bytes:
            raise ValueError("JWT signature has an invalid length")
        signature_value = int.from_bytes(signature, "big")
        if signature_value >= key.modulus:
            raise ValueError("JWT signature is outside the RSA modulus")
        digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(signing_input).digest()
        padding_length = key.size_bytes - len(digest_info) - 3
        if padding_length < 8:
            raise ValueError("RSA key is too small for RS256")
        expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
        recovered = pow(signature_value, key.exponent, key.modulus).to_bytes(
            key.size_bytes,
            "big",
        )
        if not hmac.compare_digest(recovered, expected):
            raise ValueError("JWT signature verification failed")

    def _validate_claims(self, claims: Mapping[str, Any]) -> str:
        if claims.get("iss") != self.issuer:
            raise ValueError("JWT issuer does not match")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ValueError("JWT subject is required")
        audience = claims.get("aud")
        if isinstance(audience, str):
            audiences = (audience,)
        elif isinstance(audience, list) and audience and all(
            isinstance(item, str) and item for item in audience
        ):
            audiences = tuple(audience)
        else:
            raise ValueError("JWT audience is required")
        if self.audience not in audiences:
            raise ValueError("JWT audience does not match")

        now = self._clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(float(now)):
            raise ValueError("authentication clock returned an invalid value")
        now_value = float(now)
        expiration = _numeric_date(claims, "exp", required=True)
        not_before = _numeric_date(claims, "nbf", required=False)
        issued_at = _numeric_date(claims, "iat", required=False)
        assert expiration is not None
        if now_value >= expiration + self.leeway_seconds:
            raise ValueError("JWT is expired")
        if not_before is not None and now_value + self.leeway_seconds < not_before:
            raise ValueError("JWT is not active")
        if issued_at is not None and issued_at > now_value + self.leeway_seconds:
            raise ValueError("JWT was issued in the future")
        if not_before is not None and not_before > expiration:
            raise ValueError("JWT nbf is after exp")
        if issued_at is not None and issued_at > expiration:
            raise ValueError("JWT iat is after exp")

        actor = self._subject_actors.get(subject)
        if actor is None:
            raise ValueError("JWT subject has no configured actor")
        return actor

    def _authenticate_token(self, token: str) -> str:
        segments = token.split(".")
        if len(segments) != 3 or not all(segments):
            raise ValueError("JWT must contain three segments")
        encoded_header, encoded_claims, encoded_signature = segments
        header = _decode_json_segment(encoded_header, "JWT header")
        if header.get("alg") != "RS256":
            raise ValueError("JWT alg must be RS256")
        if "crit" in header or header.get("b64") is False:
            raise ValueError("JWT uses unsupported critical processing")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ValueError("JWT kid is required")
        key = self._keys.get(kid)
        if key is None:
            raise ValueError("JWT kid is unknown")
        signature = _decode_base64url(encoded_signature, "JWT signature")
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
        self._verify_signature(key, signing_input, signature)
        claims = _decode_json_segment(encoded_claims, "JWT claims")
        return self._validate_claims(claims)

    def authenticate(self, authorization: Any) -> AuthenticatedActor:
        token = self._bearer_token(authorization)
        try:
            actor = self._authenticate_token(token)
        except (ArithmeticError, binascii.Error, KeyError, TypeError, UnicodeError, ValueError):
            raise AuthError("OIDC bearer authentication failed") from None
        fingerprint = hashlib.sha256(token.encode("ascii")).hexdigest()[:16]
        return AuthenticatedActor(actor=actor, token_fingerprint=fingerprint)


__all__ = ["OIDCAuthenticator"]
