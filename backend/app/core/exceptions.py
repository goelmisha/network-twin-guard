"""Typed exception hierarchy for the Corporate Twin platform.

Every failure carries a stable ``code`` (exposed in the API error envelope) and
an ``http_status`` so the route layer can translate domain failures into
responses without leaking stack traces.
"""

from __future__ import annotations

from typing import Any

from ..models.errors import ErrorResponse


class TwinError(Exception):
    """Base class for all domain failures.

    Args:
        detail: Human-readable explanation surfaced to the client.
        **context: Structured diagnostic data (node names, argv, exit codes).
    """

    code: str = "twin_error"
    http_status: int = 500

    def __init__(self, detail: str, **context: Any) -> None:
        super().__init__(detail)
        self.detail = detail
        self.context: dict[str, Any] = context

    def to_response(self) -> ErrorResponse:
        """Render this failure as an API error envelope."""
        return ErrorResponse(code=self.code, detail=self.detail, context=self.context)


class TopologyModelError(TwinError):
    """The topology or model definition is missing, malformed or inconsistent."""

    code = "topology_model_error"
    http_status = 500


class PolicyParseError(TwinError):
    """A firewall rule could not be compiled from its iptables representation."""

    code = "policy_parse_error"
    http_status = 500


class RuntimeUnavailableError(TwinError):
    """The container runtime is unreachable, so live state cannot be captured.

    This is an expected, recoverable condition: callers fall back to model-only
    mode rather than failing the request.
    """

    code = "runtime_unavailable"
    http_status = 503


class CommandExecutionError(TwinError):
    """An external command failed, timed out, or exited non-zero."""

    code = "command_execution_failed"
    http_status = 502


class SnapshotNotFoundError(TwinError):
    """No baseline snapshot has been captured yet."""

    code = "snapshot_not_found"
    http_status = 404


class ChangeValidationError(TwinError):
    """A candidate change is not applicable to the current topology."""

    code = "change_validation_error"
    http_status = 422


class RollbackError(TwinError):
    """The twin could not be reverted to its baseline."""

    code = "rollback_failed"
    http_status = 409


__all__ = [
    "ChangeValidationError",
    "CommandExecutionError",
    "PolicyParseError",
    "RollbackError",
    "RuntimeUnavailableError",
    "SnapshotNotFoundError",
    "TopologyModelError",
    "TwinError",
]
