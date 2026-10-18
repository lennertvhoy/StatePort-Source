"""Shared lifecycle exceptions."""


class LifecycleError(ValueError):
    """Raised when a lifecycle contract cannot be safely applied."""

    def __init__(self, message: str, *, code: str = "lifecycle_error") -> None:
        self.code = code
        super().__init__(message)

    @property
    def diagnostic(self) -> dict[str, str]:
        """Return the stable machine-readable error envelope."""
        return {"code": self.code, "message": str(self)}
