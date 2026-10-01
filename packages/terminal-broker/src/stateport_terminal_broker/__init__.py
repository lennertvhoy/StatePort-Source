"""Governed terminal contracts and local PTY broker."""

from .broker import (
    BROKER_STATE_VERSION,
    TerminalAccessDenied,
    TerminalBrokerError,
    TerminalCleanupError,
    TerminalQuarantined,
    TerminalSessionBroker,
    TerminalTargetUnavailable,
    TerminalTokenError,
)
from .contracts import (
    TARGET_CLASSES,
    TERMINAL_FORMAT_VERSION,
    TerminalAuditReceipt,
    TerminalCapabilities,
    TerminalConnectionProfile,
    TerminalExit,
    TerminalInput,
    TerminalOutput,
    TerminalReconnectToken,
    TerminalResize,
    TerminalSession,
    TerminalTarget,
)
from .gateway import (
    GATEWAY_FORMAT_VERSION,
    AuthenticatedTerminalGateway,
    GatewayActor,
    GatewayFrame,
    GatewayHandshake,
    WebSocketGatewayCapability,
)
from .connection_targets import (
    CAPSULE_REASON_CODES,
    CONNECTION_TARGET_FORMAT_VERSION,
    HERDR_MINIMUM_MACHINE_STREAM_VERSION,
    HERDR_REASON_CODES,
    SSH_AUTHENTICATION_ROUTES,
    SSH_EXECUTABLE,
    SSH_REASON_CODES,
    CapsuleTargetProfile,
    CapsuleTargetRegistry,
    ExternalTerminalAuditReceipt,
    HerdrCapability,
    SshLaunchPlan,
    SshTargetProfile,
    SshTargetRegistry,
    assert_no_browser_secret_fields,
    assess_herdr_capability,
    build_ssh_launch_plan,
    classify_ssh_failure,
    probe_herdr_version,
)


def __getattr__(name: str):
    """Load the execution-host capsule adapter lazily.

    The adapter only duck-types the execution-host client, but keeping the
    import lazy guarantees plain broker users never pay for it.
    """

    if name == "ExecutionHostTerminalGateway":
        from .execution_host_gateway import ExecutionHostTerminalGateway

        return ExecutionHostTerminalGateway
    raise AttributeError(name)

__all__ = [
    "AuthenticatedTerminalGateway",
    "BROKER_STATE_VERSION",
    "CONNECTION_TARGET_FORMAT_VERSION",
    "ExecutionHostTerminalGateway",
    "ExternalTerminalAuditReceipt",
    "GATEWAY_FORMAT_VERSION",
    "GatewayActor",
    "GatewayFrame",
    "GatewayHandshake",
    "HERDR_MINIMUM_MACHINE_STREAM_VERSION",
    "HERDR_REASON_CODES",
    "HerdrCapability",
    "SSH_AUTHENTICATION_ROUTES",
    "SSH_EXECUTABLE",
    "SSH_REASON_CODES",
    "SshLaunchPlan",
    "SshTargetProfile",
    "SshTargetRegistry",
    "TARGET_CLASSES",
    "TERMINAL_FORMAT_VERSION",
    "TerminalAccessDenied",
    "TerminalAuditReceipt",
    "TerminalBrokerError",
    "TerminalCapabilities",
    "TerminalCleanupError",
    "TerminalConnectionProfile",
    "TerminalExit",
    "TerminalInput",
    "TerminalOutput",
    "TerminalQuarantined",
    "TerminalReconnectToken",
    "TerminalResize",
    "TerminalSession",
    "TerminalSessionBroker",
    "TerminalTarget",
    "TerminalTargetUnavailable",
    "TerminalTokenError",
    "WebSocketGatewayCapability",
    "assert_no_browser_secret_fields",
    "assess_herdr_capability",
    "build_ssh_launch_plan",
    "classify_ssh_failure",
    "probe_herdr_version",
]
