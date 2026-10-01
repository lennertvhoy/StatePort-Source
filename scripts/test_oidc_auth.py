#!/usr/bin/env python3
"""Focused acceptance tests for pinned, offline OIDC JWT authentication."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/api-auth/src"))

from stateport_auth import AuthError, OIDCAuthenticator


_NOW = 1_700_000_000
_RSA_E = 65_537
# Generated solely as a numeric 2048-bit test fixture; it is not a real credential.
_RSA_N = int(
    "a483a2cddfaa7d7597269ba0aac394097235285e5f04f25230d57306a579e398"
    "dca75193243f50fa5997c25be5a95b89c3e5e7d5e27edd8fd045ef9b4f9306ae"
    "2b976cc71e9f681ba6a4bfeb4c6f19de02e54e1b9d66e9030b58a65521edd175"
    "37cf277ab08fe05a1c6863b1e060fd1ee19c2ce1def67cce773f4d001a909a83"
    "44aad6fe079e0f3ccba2d27d82eb99cf9929e9a4a97ad2a1fccaff0ae5820f83"
    "e9f7965d00af8e25151da70edf4717f15d5a5e64dd69ff7eae8dc4a7c51b05"
    "ac008f51dacd10736bad75256b903cee46371989820d8b6a681157c17f2babd5"
    "01f4d3680455e59150ded671f4f804d2e32adb80081460e13b617d25a9d8051863",
    16,
)
_RSA_D = int(
    "1aac853f201ec28cc85f28289ac76f3f40d7419e5b85afcc87c2740e05d28786"
    "87705197abeee030574a75e6f48bcb1dc1378ba97039e5aea5b4512f3b6db94d"
    "901fd3314dd3c6cb84ef7d76a743f44bbce8750ba12fc86407f8edaf2bfb2554"
    "fe2186632c3187ccd4825077cccbacfeced1c5ad31bb816cf084c0f55d5948d3"
    "f144a510acb36a212abff7b358170beb6318278b442f9e4bf21923ee8a6cb823"
    "28e2c4b885e32b1cd340a018d3dd8b15856c43a9110b50e737d27802d3e848f"
    "9fce15617e4e1018501bf0ce71065e37f86bbbf351652cadbd3eefb59eaf4b48"
    "e0243a81d25bb0406218988f9288515a6fee4855bc33850247ca16cd995e75e81",
    16,
)
_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _uint(value: int) -> str:
    return _b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _jwk(kid: str = "key-1", **updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "key_ops": ["verify"],
        "n": _uint(_RSA_N),
        "e": _uint(_RSA_E),
    }
    value.update(updates)
    return value


def _configuration(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "issuer": "https://identity.example/tenant/v2.0",
        "audience": "stateport-api",
        "jwks": {"keys": [_jwk()]},
        "subjectActors": {"subject-123": "alice"},
        "leewaySeconds": 60,
    }
    value.update(updates)
    return value


def _claims(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "iss": "https://identity.example/tenant/v2.0",
        "aud": "stateport-api",
        "sub": "subject-123",
        "exp": _NOW + 300,
        "iat": _NOW,
    }
    value.update(updates)
    return value


def _token(
    claims: dict[str, Any] | None = None,
    *,
    header: dict[str, Any] | None = None,
    header_json: bytes | None = None,
    claims_json: bytes | None = None,
) -> str:
    encoded_header = _b64(
        header_json
        if header_json is not None
        else json.dumps(
            header or {"alg": "RS256", "kid": "key-1", "typ": "JWT"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    encoded_claims = _b64(
        claims_json
        if claims_json is not None
        else json.dumps(
            claims or _claims(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    size = (_RSA_N.bit_length() + 7) // 8
    digest_info = _DIGEST_INFO + hashlib.sha256(signing_input).digest()
    encoded_message = (
        b"\x00\x01"
        + (b"\xff" * (size - len(digest_info) - 3))
        + b"\x00"
        + digest_info
    )
    signature = pow(int.from_bytes(encoded_message, "big"), _RSA_D, _RSA_N).to_bytes(
        size,
        "big",
    )
    return f"{encoded_header}.{encoded_claims}.{_b64(signature)}"


def _auth() -> OIDCAuthenticator:
    return OIDCAuthenticator.from_mapping(_configuration(), clock=lambda: _NOW)


def _assert_rejected(authenticator: OIDCAuthenticator, token: str) -> None:
    try:
        authenticator.authenticate(f"Bearer {token}")
    except AuthError as exc:
        assert str(exc) == "OIDC bearer authentication failed"
        assert token not in str(exc) and token not in repr(exc)
    else:
        raise AssertionError("invalid OIDC token must fail closed")


def _assert_invalid_configuration(value: dict[str, Any]) -> None:
    try:
        OIDCAuthenticator.from_mapping(value, clock=lambda: _NOW)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid OIDC configuration must fail closed")


def test_valid_rs256_token_maps_subject_and_returns_only_fingerprint() -> None:
    token = _token(
        _claims(
            aud=["another-resource", "stateport-api"],
            nbf=_NOW + 30,
            iat=_NOW + 30,
            actor="mallory",
            roles=["admin"],
            capabilities=["write_state"],
        )
    )
    authenticated = _auth().authenticate(f"bearer {token}")
    assert authenticated.actor == "alice"
    assert authenticated.token_fingerprint == hashlib.sha256(token.encode()).hexdigest()[:16]
    assert set(vars(authenticated)) == {"actor", "token_fingerprint"}
    assert token not in repr(authenticated)


def test_configuration_requires_complete_unique_public_rs256_keys() -> None:
    missing_audience = _configuration()
    del missing_audience["audience"]
    duplicate_kid = _configuration(jwks={"keys": [_jwk(), _jwk()]})
    missing_modulus = _configuration(jwks={"keys": [_jwk()]})
    del missing_modulus["jwks"]["keys"][0]["n"]
    small_modulus = _configuration(
        jwks={"keys": [_jwk(n=_uint((1 << 1_023) | 1))]}
    )
    even_modulus = _configuration(jwks={"keys": [_jwk(n=_uint(1 << 2_047))]})
    private_key_material = _configuration(jwks={"keys": [_jwk(d="AQ")]})
    wrong_algorithm = _configuration(jwks={"keys": [_jwk(alg="HS256")]})
    malformed_modulus = _configuration(jwks={"keys": [_jwk(n="not+base64")]})
    excessive_leeway = _configuration(leewaySeconds=301)
    for value in (
        missing_audience,
        duplicate_kid,
        missing_modulus,
        small_modulus,
        even_modulus,
        private_key_material,
        wrong_algorithm,
        malformed_modulus,
        excessive_leeway,
    ):
        _assert_invalid_configuration(value)


def test_rejects_algorithm_key_and_encoding_confusion_with_safe_errors() -> None:
    authenticator = _auth()
    valid = _token()
    header, claims, signature = valid.split(".")
    signature_bytes = bytearray(base64.urlsafe_b64decode(signature + "=="))
    signature_bytes[-1] ^= 1
    bad_signature = f"{header}.{claims}.{_b64(bytes(signature_bytes))}"
    duplicate_header = _token(
        header_json=b'{"alg":"RS256","kid":"key-1","kid":"key-1"}'
    )
    duplicate_claim = _token(
        claims_json=(
            b'{"iss":"https://identity.example/tenant/v2.0",'
            b'"aud":"stateport-api","sub":"subject-123",'
            b'"exp":1700000300,"sub":"subject-123"}'
        )
    )
    deeply_nested_claim = _token(claims_json=(b"[" * 1_100) + b"0" + (b"]" * 1_100))
    cases = (
        "not-a-jwt",
        "@@@.e30.signature",
        f"{_b64(b'{not-json}')}.{claims}.{signature}",
        _token(header={"alg": "HS256", "kid": "key-1"}),
        _token(header={"alg": "none", "kid": "key-1"}),
        _token(header={"alg": "RS256"}),
        _token(header={"alg": "RS256", "kid": "unknown"}),
        duplicate_header,
        duplicate_claim,
        deeply_nested_claim,
        bad_signature,
    )
    for token in cases:
        _assert_rejected(authenticator, token)
    for authorization in (None, "", "Basic value", "Bearer"):
        try:
            authenticator.authenticate(authorization)
        except AuthError as exc:
            assert str(exc) == "bearer authentication is required"
        else:
            raise AssertionError("missing bearer authentication must fail")


def test_rejects_required_claim_time_and_subject_failures() -> None:
    authenticator = _auth()
    invalid_claims: list[dict[str, Any]] = []
    for required in ("iss", "aud", "sub", "exp"):
        value = _claims()
        del value[required]
        invalid_claims.append(value)
    invalid_claims.extend(
        (
            _claims(iss="https://other.example"),
            _claims(aud="another-api"),
            _claims(sub="unknown-subject"),
            _claims(exp=_NOW - 61),
            _claims(nbf=_NOW + 61),
            _claims(iat=_NOW + 61),
            _claims(exp="1700000300"),
            _claims(nbf=True),
            _claims(aud=[]),
            _claims(aud=["stateport-api", 7]),
            _claims(exp=_NOW + 30, nbf=_NOW + 31),
            _claims(exp=_NOW + 30, iat=_NOW + 31),
        )
    )
    for claims in invalid_claims:
        _assert_rejected(authenticator, _token(claims))


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("PASS")
