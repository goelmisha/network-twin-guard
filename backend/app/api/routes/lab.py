"""Containerlab lifecycle endpoints.

Deploy and destroy are exposed over the API for convenience, but the documented
path is the shell scripts in ``scripts/`` so the topology can be brought up
without the backend running.
"""

from __future__ import annotations

from fastapi import APIRouter

from ...models.simulation import LabLifecycleResponse
from ..deps import TwinServiceDep

router = APIRouter(tags=["lab"])


@router.post(
    "/lab/deploy",
    response_model=LabLifecycleResponse,
    summary="Render bootstrap scripts and deploy the Containerlab topology",
    description=(
        "Regenerates `config/generated/<node>.sh` from `config/model.yaml`, then runs "
        "`containerlab deploy -t corporate-twin.yml`.\n\n"
        "The `twin-host:latest` image must exist first "
        "(`scripts/build_images.sh`). Deployment can take a while on a Raspberry Pi "
        "if images need pulling; the command runs with a 5 minute timeout."
    ),
    responses={503: {"description": "The containerlab CLI is not installed."}},
)
async def deploy_lab(service: TwinServiceDep) -> LabLifecycleResponse:
    """Deploy the lab topology."""
    return await service.deploy_lab()


@router.post(
    "/lab/destroy",
    response_model=LabLifecycleResponse,
    summary="Destroy the Containerlab topology",
    description=(
        "Runs `containerlab destroy -t corporate-twin.yml --cleanup`, removing the "
        "containers and the lab's virtual wiring."
    ),
    responses={503: {"description": "The containerlab CLI is not installed."}},
)
async def destroy_lab(service: TwinServiceDep) -> LabLifecycleResponse:
    """Destroy the lab topology."""
    return await service.destroy_lab()
