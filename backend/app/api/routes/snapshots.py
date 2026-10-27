"""Snapshot endpoints: capture and inspect the pre-change baseline."""

from __future__ import annotations

from fastapi import APIRouter, status

from ...models.simulation import SnapshotResponse
from ...models.snapshot import SnapshotSummary
from ..deps import TwinServiceDep

router = APIRouter(tags=["snapshot"])


@router.post(
    "/snapshot",
    response_model=SnapshotResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Capture the pre-change baseline",
    description=(
        "Captures the current state of the twin as the baseline: interface "
        "addressing and routing tables, the compiled firewall policy, and the fully "
        "solved multi-hop reachability matrix for every probe flow.\n\n"
        "When the Docker daemon and lab containers are available, live state is read "
        "from inside each container (`ip -br addr`, `ip route show`, `iptables -S`). "
        "Otherwise the snapshot is resolved from the declarative model and carries "
        "explanatory warnings. The baseline is persisted to disk so rollback survives "
        "a backend restart."
    ),
    responses={503: {"description": "Container runtime unreachable (never fatal: falls back to model mode)."}},
)
async def capture_snapshot(service: TwinServiceDep) -> SnapshotResponse:
    """Capture and activate a new baseline snapshot."""
    return await service.snapshot_response()


@router.get(
    "/snapshot",
    response_model=SnapshotSummary,
    summary="Get the active baseline",
    description="Returns the active baseline summary, or 404 when none has been captured.",
    responses={404: {"description": "No baseline snapshot exists yet."}},
)
async def get_snapshot(service: TwinServiceDep) -> SnapshotSummary:
    """Return the active baseline summary."""
    baseline = await service.get_baseline()
    from ...core.snapshot import summarise

    return summarise(baseline)


@router.get(
    "/snapshot/nodes",
    summary="Per-node baseline state",
    description=(
        "Returns the per-node view of the baseline: interfaces, effective routing "
        "table, chain default verdicts and rule counts."
    ),
    responses={404: {"description": "No baseline snapshot exists yet."}},
)
async def snapshot_nodes(service: TwinServiceDep) -> list[dict[str, object]]:
    """Return per-node baseline state for operator inspection.

    Raises:
        SnapshotNotFoundError: When no baseline has been captured yet; mapped to
            a 404 error envelope by the application exception handler.
    """
    baseline = await service.get_baseline()
    from ...core.snapshot import node_state_summaries

    return [summary.model_dump(mode="json") for summary in node_state_summaries(baseline)]
