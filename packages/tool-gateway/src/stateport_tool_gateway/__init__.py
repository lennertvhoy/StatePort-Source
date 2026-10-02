"""Narrow run-bound model access; no generic proxy or credential store."""

from .gateway import ModelGateway, ModelGatewayError, ModelRoute

__all__ = ["ModelGateway", "ModelGatewayError", "ModelRoute"]
