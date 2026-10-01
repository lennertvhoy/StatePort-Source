"""Typed preview-gateway refusals."""

from __future__ import annotations


class PreviewGatewayError(RuntimeError):
    """A preview-gateway operation was refused at a known boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
