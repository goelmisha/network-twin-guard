"""Error response schemas returned by the REST API.

Every failure the API can produce is represented by :class:`ErrorResponse`, so
clients (including the Streamlit dashboard) can branch on a stable ``code``
field instead of parsing prose.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Machine-readable error envelope.

    Attributes:
        code: Stable error identifier, for example ``runtime_unavailable``.
        detail: Human-readable explanation of what failed.
        context: Optional structured data (node names, commands, exit codes)
            that helps an operator diagnose the problem.
    """

    code: str = Field(description="Stable machine-readable error identifier.")
    detail: str = Field(description="Human-readable failure explanation.")
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured diagnostic context (nodes, commands, exit codes).",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "code": "runtime_unavailable",
                "detail": "Docker daemon is not reachable; continuing in model-only mode.",
                "context": {"command": "docker info", "exit_code": 1},
            }
        }
    }
