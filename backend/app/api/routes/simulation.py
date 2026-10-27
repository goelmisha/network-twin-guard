"""What-if simulation, blast-radius analysis and rollback endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, Query

from ...models.simulation import (
    BlastRadiusRequest,
    BlastRadiusResponse,
    ChangeRequest,
    RollbackResponse,
    SimulationResult,
)
from ..deps import TwinServiceDep

router = APIRouter(tags=["simulation"])


@router.post(
    "/simulate-change",
    response_model=SimulationResult,
    summary="Evaluate a candidate change before it reaches production",
    description=(
        "Applies a candidate change to an in-memory copy of the twin -- never to the "
        "baseline -- then re-solves the full reachability matrix and reports:\n\n"
        "* `policy_delta`: firewall rules added and removed;\n"
        "* `reachability_delta`: newly opened paths (new exposure) and newly closed "
        "paths (hardening);\n"
        "* `risk`: baseline versus projected risk score, blast radius and risk-level "
        "transition.\n\n"
        "Supported change types: `allow_flow`, `deny_flow`, `add_policy_rule`, "
        "`remove_policy_rule`, `set_link_state`, `compromise_node`.\n\n"
        "Flow-level changes are inserted at position 1 of the target chain "
        "(`iptables -I` semantics)."
    ),
    responses={
        404: {"description": "No baseline snapshot exists and capture failed."},
        422: {"description": "The change does not apply to this topology."},
    },
)
async def simulate_change(
    service: TwinServiceDep,
    change: ChangeRequest = Body(
        ...,
        openapi_examples={
            "risky-permit": {
                "summary": "Accidentally open every port from the corp zone to the database",
                "value": {
                    "change_type": "allow_flow",
                    "target_node": "perimeter-gateway",
                    "chain": "FORWARD",
                    "src": "10.10.10.0/24",
                    "dst": "10.10.20.50",
                    "protocol": "tcp",
                    "description": "CHG-1042: new reporting integration needs DB access",
                },
            },
            "compromise": {
                "summary": "Assume the employee workstation is attacker-controlled",
                "value": {
                    "change_type": "compromise_node",
                    "target_node": "employee-workstation",
                },
            },
        },
    ),
    apply_to_runtime: bool = Query(
        default=False,
        description=(
            "Also push the projected policy to live containers. Requires the lab to be "
            "deployed; ignored (with a warning) in model-only mode."
        ),
    ),
) -> SimulationResult:
    """Evaluate a candidate change against the baseline."""
    return await service.simulate_change(change, apply_to_runtime=apply_to_runtime)


@router.post(
    "/analyze-blast-radius",
    response_model=BlastRadiusResponse,
    summary="Graph-based reachability and blast-radius analysis",
    description=(
        "Fans out from one or more attacker origins across the solved reachability "
        "graph and quantifies the damage a foothold would cause.\n\n"
        "Returns a per-origin `risk_score` (0-100) and `blast_radius_pct` "
        "(criticality-weighted share of the estate reachable from that origin), "
        "crown-jewel exposure, zone penetration, and the concrete attack paths.\n\n"
        "Supply `include_simulated_change` to analyse a candidate change without "
        "committing it, which is how the dashboard validates a firewall rule before "
        "deployment."
    ),
    responses={
        404: {"description": "No baseline snapshot exists yet."},
        422: {"description": "Unknown origin node or probe flow."},
    },
)
async def analyze_blast_radius(
    service: TwinServiceDep,
    request: BlastRadiusRequest = Body(
        default=BlastRadiusRequest(),
        openapi_examples={
            "default-entrypoints": {
                "summary": "Analyse every configured entry point",
                "value": {},
            },
            "specific-origin": {
                "summary": "Analyse a single origin on high-risk flows",
                "value": {
                    "origin_node": "employee-workstation",
                    "flows": ["ssh", "smb", "any-tcp"],
                },
            },
        },
    ),
) -> BlastRadiusResponse:
    """Compute attack paths, blast radius and composite risk."""
    return await service.analyze_blast_radius(request)


@router.post(
    "/rollback",
    response_model=RollbackResponse,
    summary="Revert the twin to the pre-change baseline",
    description=(
        "Discards all evaluated changes and restores the captured baseline. When the "
        "lab is deployed and `apply_to_runtime` is true, the baseline firewall policy "
        "is re-pushed into every running container (chains flushed, defaults reset, "
        "rules re-installed in order). Otherwise the rollback is logical only and a "
        "warning explains that container state was untouched."
    ),
    responses={
        404: {"description": "No baseline snapshot exists."},
        409: {"description": "Rollback could not be completed."},
    },
)
async def rollback(
    service: TwinServiceDep,
    apply_to_runtime: bool = Query(
        default=True,
        description="Re-push the baseline firewall policy to live containers.",
    ),
) -> RollbackResponse:
    """Revert the twin to the baseline."""
    return await service.rollback(apply_to_runtime=apply_to_runtime)
