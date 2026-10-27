"""Service layer.

Contains everything that touches the outside world (Docker/Containerlab, the
filesystem) and the orchestration that ties the solver core together. Routers
depend on this layer, never on the runtime gateway directly.
"""

from __future__ import annotations

from functools import lru_cache

from ..config import Settings, get_settings
from .render import render_bootstrap_scripts
from .runtime import CommandResult, RuntimeGateway
from .twin_service import MAX_HISTORY, TwinService


@lru_cache(maxsize=1)
def get_twin_service() -> TwinService:
    """Return the process-wide :class:`TwinService` singleton.

    Cached so model loading, the persisted baseline and the simulation history
    are shared across requests. Tests override the FastAPI dependency instead of
    mutating this cache.
    """
    return TwinService(get_settings())


def build_twin_service(settings: Settings | None = None) -> TwinService:
    """Construct an isolated service instance (used by tests and CLI tooling)."""
    return TwinService(settings or get_settings())


__all__ = [
    "MAX_HISTORY",
    "CommandResult",
    "RuntimeGateway",
    "TwinService",
    "build_twin_service",
    "get_twin_service",
    "render_bootstrap_scripts",
]
