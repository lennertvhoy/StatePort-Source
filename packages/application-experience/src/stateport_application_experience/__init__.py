"""Trusted declarative application-experience contracts for StatePort.

Application packages describe an experience; they never ship executable
browser code or grant themselves permissions.  StatePort validates the
descriptor, intersects every requested capability with instance grants,
operator policy, runtime availability, and actor permission, then renders
only StatePort-owned components.
"""

from .contracts import (
    APPLICATION_EXPERIENCE_FORMAT,
    TRUSTED_COMPONENTS,
    AdvancedControlContribution,
    ApplicationCapability,
    ApplicationExperienceDescriptor,
    ApplicationView,
    ConversationPresentation,
    ExperienceContractError,
    NavigationContribution,
    PlatformOperationPermission,
)
from .registry import ExperienceRegistry, load_experience_descriptors
from .policy import ApplicationExperiencePolicy, load_experience_policy
from .resolver import resolve_experience

__all__ = [
    "APPLICATION_EXPERIENCE_FORMAT",
    "TRUSTED_COMPONENTS",
    "AdvancedControlContribution",
    "ApplicationCapability",
    "ApplicationExperienceDescriptor",
    "ApplicationExperiencePolicy",
    "ApplicationView",
    "ConversationPresentation",
    "ExperienceContractError",
    "ExperienceRegistry",
    "NavigationContribution",
    "PlatformOperationPermission",
    "load_experience_descriptors",
    "load_experience_policy",
    "resolve_experience",
]
