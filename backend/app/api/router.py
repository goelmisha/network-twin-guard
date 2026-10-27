"""Aggregated API router.

Every endpoint is mounted under ``/api/v1`` so the version contract is explicit
and a future ``v2`` can be added without breaking commercial integrations.
"""

from __future__ import annotations

from fastapi import APIRouter

from .routes import compliance, lab, simulation, snapshots, system, topology

API_PREFIX = "/api/v1"

api_router = APIRouter(prefix=API_PREFIX)
api_router.include_router(system.router)
api_router.include_router(topology.router)
api_router.include_router(snapshots.router)
api_router.include_router(simulation.router)
api_router.include_router(compliance.router)
api_router.include_router(lab.router)

__all__ = ["API_PREFIX", "api_router"]
