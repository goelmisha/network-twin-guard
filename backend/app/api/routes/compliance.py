"""Compliance reporting endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from ...models.simulation import ComplianceReport
from ..deps import TwinServiceDep

router = APIRouter(tags=["compliance"])


@router.get(
    "/compliance",
    response_model=ComplianceReport,
    summary="Evaluate compliance controls against the baseline",
    description=(
        "Runs every control against the active baseline and returns a pass/fail "
        "percentage plus per-control findings with severity, evidence and "
        "remediation.\n\n"
        "Controls cover default-deny posture, unrestricted permits, crown-jewel "
        "cross-zone exposure, management-plane reachability from user zones and "
        "legacy cleartext protocols."
    ),
    responses={404: {"description": "No baseline snapshot exists yet."}},
)
async def compliance(service: TwinServiceDep) -> ComplianceReport:
    """Return the compliance report for the active baseline."""
    return await service.compliance()
