"""Operator-owned provider API-key storage for managed OpenCode invocations.

OpenCode reads provider credentials from its own data directory
(``$XDG_DATA_HOME/opencode/auth.json``) or from the provider's documented
environment variable. This module implements the second route only: the
operator supplies one API key for one documented provider, StatePort stores it
in a private file with owner-only permissions and injects it into the managed
OpenCode subprocess environment. StatePort never reads, copies or reports
OpenCode's own authentication storage, and the stored value is never returned
by a status projection, log line or HTTP response.

The provider-to-environment-variable map below is the documented environment
contract used by the pinned OpenCode runtime. It was checked against the
models.dev catalog ``env`` arrays consumed by the installed OpenCode release
(``anthropic``, ``openai``, ``openrouter``, ``google``, ``groq`` and ``xai``)
and against OpenCode's provider documentation, which states that credentials
are otherwise held in ``~/.local/share/opencode/auth.json``:
https://opencode.ai/docs/providers/
"""
from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
import tempfile

from external_engine_runtime import filtered_environment

# Fixed documented provider list (provider id -> provider environment variable).
# Unknown ids are refused rather than guessed, and a stored file whose variable
# is not in this map is never injected.
PROVIDER_CREDENTIAL_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "google": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "xai": "XAI_API_KEY",
}

PROVIDER_BY_ENV: dict[str, str] = {
    env_var: provider_id for provider_id, env_var in PROVIDER_CREDENTIAL_ENV.items()
}

# A provider API key is a short opaque token. 4 KiB is far above any documented
# provider key length and far below the request-body bound; anything larger is
# refused instead of silently truncating or writing.
MAX_CREDENTIAL_KEY_BYTES = 4096
# The whole file is one line ``ENV_VAR=value``; the read bound is the key bound
# plus the longest environment variable name and the trailing newline.
MAX_CREDENTIAL_FILE_BYTES = MAX_CREDENTIAL_KEY_BYTES + 256

CREDENTIAL_FILE_NAME = "provider.env"
PROVIDER_HOME_ENV = "STATEPORT_OPENCODE_HOME"


class CredentialError(ValueError):
    """A bounded, fixed-code credential refusal that never echoes the value."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class StoredCredential:
    """One parsed credential: provider id, environment variable name and value."""

    __slots__ = ("provider_id", "env_var", "value")

    def __init__(self, provider_id: str, env_var: str, value: str) -> None:
        self.provider_id = provider_id
        self.env_var = env_var
        self.value = value


def resolve_provider_home(source: Mapping[str, str] | None = None) -> Path:
    """Resolve the operator-owned OpenCode home in documented order.

    ``STATEPORT_OPENCODE_HOME`` (the installed topology's variable) wins;
    otherwise the legacy sibling ``opencode`` directory of ``CODEX_HOME`` for
    pre-W1.6 installs; otherwise ``~/.local/share/opencode``.
    """
    environment = os.environ if source is None else source
    override = str(environment.get(PROVIDER_HOME_ENV, "") or "").strip()
    if override:
        return Path(override)
    codex_home = str(environment.get("CODEX_HOME", "") or "").strip()
    if codex_home:
        return Path(codex_home).parent / "opencode"
    home = str(environment.get("HOME", "") or "").strip()
    base = Path(home) if home else Path.home()
    return base / ".local" / "share" / "opencode"


def _validate_provider(provider_id: object) -> str:
    if not isinstance(provider_id, str) or provider_id not in PROVIDER_CREDENTIAL_ENV:
        raise CredentialError(
            "credential_provider_unknown",
            "the provider is not one of the supported OpenCode credential providers",
        )
    return provider_id


def _validate_key(api_key: object) -> str:
    if not isinstance(api_key, str):
        raise CredentialError("credential_invalid", "the credential value must be text")
    if not api_key.strip():
        raise CredentialError("credential_invalid", "the credential value is empty")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in api_key):
        # Refuses newlines, carriage returns, tabs and NUL so a value can never
        # forge another line or environment entry in the stored file.
        raise CredentialError("credential_invalid", "the credential value contains control characters")
    if len(api_key.encode("utf-8")) > MAX_CREDENTIAL_KEY_BYTES:
        raise CredentialError(
            "credential_invalid",
            f"the credential value exceeds the {MAX_CREDENTIAL_KEY_BYTES}-byte bound",
        )
    return api_key


class ProviderCredentialStore:
    """Read/write the single provider credential file under one provider home."""

    def __init__(self, home: Path) -> None:
        self.home = Path(home)
        self.path = self.home / CREDENTIAL_FILE_NAME

    def load(self) -> StoredCredential | None:
        """Return the stored credential, or None when absent/unsafe/unreadable.

        A malformed, oversized or symlinked file is treated as no credential so
        a status read or an invocation never raises and never follows a link.
        """
        try:
            if not os.path.lexists(self.path):
                return None
            if self.path.is_symlink() or not self.path.is_file():
                return None
            if self.path.stat().st_size > MAX_CREDENTIAL_FILE_BYTES:
                return None
            raw = self.path.read_bytes()
        except OSError:
            return None
        if len(raw) > MAX_CREDENTIAL_FILE_BYTES:
            return None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        line = text.splitlines()[0] if text else ""
        env_var, separator, value = line.partition("=")
        if not separator:
            return None
        provider_id = PROVIDER_BY_ENV.get(env_var)
        if provider_id is None:
            return None
        return StoredCredential(provider_id, env_var, value)

    def status(self) -> dict[str, object]:
        """Project names only: never the stored value."""
        credential = self.load()
        if credential is None:
            return {
                "credentialStatus": "unconfigured",
                "credentialProvider": None,
                "credentialEnvVar": None,
            }
        return {
            "credentialStatus": "configured",
            "credentialProvider": credential.provider_id,
            "credentialEnvVar": credential.env_var,
        }

    def store(self, provider_id: object, api_key: object) -> dict[str, object]:
        selected = _validate_provider(provider_id)
        value = _validate_key(api_key)
        env_var = PROVIDER_CREDENTIAL_ENV[selected]
        try:
            self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            raise CredentialError("credential_unavailable", "the provider home could not be created") from exc
        if self.home.is_symlink() or not self.home.is_dir():
            raise CredentialError("credential_home_unsafe", "the provider home is not a private directory")
        if os.path.lexists(self.path) and self.path.is_symlink():
            raise CredentialError("credential_file_unsafe", "the credential file path is a symbolic link")
        temporary: Path | None = None
        try:
            descriptor, raw_temp = tempfile.mkstemp(
                prefix=".provider.env.", suffix=".tmp", dir=self.home
            )
            temporary = Path(raw_temp)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(f"{env_var}={value}\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return self.status()

    def remove(self, provider_id: object) -> dict[str, object]:
        selected = _validate_provider(provider_id)
        credential = self.load()
        if credential is not None and credential.provider_id != selected:
            # A single-line file holds one credential; refuse to delete a
            # different provider's key than the one the operator selected.
            raise CredentialError(
                "credential_provider_mismatch",
                "a different provider credential is configured",
            )
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        return self.status()


def opencode_subprocess_environment(
    store: ProviderCredentialStore, source: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Build the managed-OpenCode subprocess environment.

    The base is the existing filtered environment plus the two operator-owned
    XDG locations and, only when configured, the provider's documented API-key
    variable. Nothing else is added and the stored value is never logged or
    returned.
    """
    overrides = {
        "XDG_DATA_HOME": str(store.home / "data"),
        "XDG_CONFIG_HOME": str(store.home / "config"),
    }
    allow = ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME"]
    credential = store.load()
    if credential is not None:
        overrides[credential.env_var] = credential.value
        allow.append(credential.env_var)
    return filtered_environment(source=source, allow=tuple(allow), overrides=overrides)


__all__ = [
    "CREDENTIAL_FILE_NAME",
    "CredentialError",
    "MAX_CREDENTIAL_KEY_BYTES",
    "PROVIDER_BY_ENV",
    "PROVIDER_CREDENTIAL_ENV",
    "PROVIDER_HOME_ENV",
    "ProviderCredentialStore",
    "StoredCredential",
    "opencode_subprocess_environment",
    "resolve_provider_home",
]
