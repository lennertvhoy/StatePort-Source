"""Headless, policy-enforcing StatePort API boundary.

The v1 application is deliberately small and stdlib-only at the transport
layer. Its default instance is read-only; configured callers can use the
explicit approval-backed materialisation contract.
"""

from governed_api.application import API_VERSION, GovernedAPI, Response
from governed_api.identity import Identity, IdentityDirectory

__all__ = ["API_VERSION", "GovernedAPI", "Response", "Identity", "IdentityDirectory"]
