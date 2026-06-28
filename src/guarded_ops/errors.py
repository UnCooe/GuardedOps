class GuardedOpsError(ValueError):
    """Base error raised for user-facing GuardedOps validation failures."""


class ApprovalError(GuardedOpsError):
    """Raised when an approval token is missing or does not match."""


class FleetError(GuardedOpsError):
    """Raised when fleet configuration is invalid."""


class PolicyError(GuardedOpsError):
    """Raised when wrapper policy blocks an action."""

