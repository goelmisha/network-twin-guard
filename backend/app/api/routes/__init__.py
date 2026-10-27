"""Route modules grouped by domain.

Each module owns one concern and exposes only an ``APIRouter``; aggregation and
prefixing happen in :mod:`app.api.router`.
"""

from . import compliance, lab, simulation, snapshots, system, topology

__all__ = ["compliance", "lab", "simulation", "snapshots", "system", "topology"]
