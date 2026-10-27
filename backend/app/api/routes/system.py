"""Health, readiness and policy inspection endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from ... import __version__
from ...models.views import ChainView, HealthView, SimulationHistoryEntry
from ..deps import TwinServiceDep

router = APIRouter(tags=["system"])


@router.get(
    "/health",
    response_model=HealthView,
    summary="Liveness and readiness probe",
    description=(
        "Reports whether the topology loaded, whether the Docker daemon and "
        "containerlab CLI are reachable, whether the lab is deployed, and whether a "
        "baseline snapshot exists. Always returns 200 while the process is alive; "
        "inspect `status` and `checks` for readiness."
    ),
)
async def health(service: TwinServiceDep) -> HealthView:
    """Return the current readiness payload."""
    return await service.health()


@router.get(
    "/version",
    summary="Backend version",
    description="Returns the backend semantic version.",
)
async def version() -> dict[str, str]:
    """Return the backend version."""
    return {"version": __version__}


@router.get(
    "/policies",
    response_model=tuple[ChainView, ...],
    summary="Inspect compiled firewall policy",
    description=(
        "Returns every configured chain with its default verdict and rules in "
        "evaluation order. Chains that are empty and default to ACCEPT are omitted."
    ),
)
async def policies(service: TwinServiceDep) -> tuple[ChainView, ...]:
    """Return the compiled firewall policy per node and chain."""
    return service.chain_views()


@router.get(
    "/simulations",
    response_model=tuple[SimulationHistoryEntry, ...],
    summary="List evaluated changes",
    description="Returns the persisted simulation history, newest first.",
)
async def simulations(service: TwinServiceDep) -> tuple[SimulationHistoryEntry, ...]:
    """Return the simulation history."""
    return service.history()
