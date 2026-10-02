"""Fail-closed capability intersection and approval state machine."""

from approval_gate.gate import ApprovalGate, ApprovalRequest, CapabilityDecision, intersect_capabilities

__all__ = ["ApprovalGate", "ApprovalRequest", "CapabilityDecision", "intersect_capabilities"]
