"""Topology endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from ...models.simulation import RuntimeStatus
from ...models.views import TopologyView
from ..deps import TwinServiceDep

router = APIRouter(tags=["topology"])


@router.get(
    "/topology",
    response_model=TopologyView,
    summary="Get the modelled topology",
    description=(
        "Returns nodes, links, zones and entry points as projected for the "
        "dashboard map, including per-node container running state and rule counts."
    ),
)
async def topology(service: TwinServiceDep) -> TopologyView:
    """Return the topology projection used by the dashboard map."""
    return await service.topology_view()


@router.get(
    "/runtime",
    response_model=RuntimeStatus,
    summary="Probe container runtime state",
    description=(
        "Reports Docker and containerlab availability plus per-node running state. "
        "Used by the dashboard to display live versus model-only mode."
    ),
)
async def runtime(service: TwinServiceDep) -> RuntimeStatus:
    """Return the container runtime status."""
    return await service.runtime_status()
