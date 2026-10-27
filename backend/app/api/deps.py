"""FastAPI dependency providers.

Routers depend on an injected :class:`~app.services.twin_service.TwinService`
rather than importing the singleton directly, so tests can override the
dependency (``app.dependency_overrides``) without mutating global state.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from ..services import get_twin_service
from ..services.twin_service import TwinService


def provide_twin_service() -> TwinService:
    """Provide the process-wide twin service instance."""
    return get_twin_service()


#: Convenience alias used by route signatures.
TwinServiceDep = Annotated[TwinService, Depends(provide_twin_service)]

__all__ = ["TwinServiceDep", "provide_twin_service"]
