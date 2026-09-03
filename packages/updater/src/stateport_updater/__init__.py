"""StatePort-owned exact-digest update engine."""

from stateport_release import UpdaterReleaseEnvelope

from .authority import (
    AuthorityManagerAdapter,
    AuthorityScope,
    UpdateAuthorityError,
)
from .engine import UpdateEngine, UpdateError, UpdateHost, UpdateHostError
from .installed import ControlPlaneBinding, InstalledAuthorityAdapter
from .models import (
    DEFAULT_ALPHA_POLICY,
    UpdatePolicy,
)
from .store import UpdateStore

__all__ = [
    "AuthorityManagerAdapter",
    "AuthorityScope",
    "ControlPlaneBinding",
    "DEFAULT_ALPHA_POLICY",
    "InstalledAuthorityAdapter",
    "UpdateEngine",
    "UpdateAuthorityError",
    "UpdateError",
    "UpdateHost",
    "UpdateHostError",
    "UpdatePolicy",
    "UpdateStore",
    "UpdaterReleaseEnvelope",
]
