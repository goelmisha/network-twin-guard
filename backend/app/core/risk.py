"""Blast-radius and composite risk scoring.

Binary "can the attacker reach it" answers do not help a change-approval board
decide. This module converts solved attack paths into two quantified numbers:

* **Blast radius** -- the share of total asset value (criticality-weighted) that
  becomes reachable from a compromise origin, where each asset only counts to
  the extent of its most exploitable reachable service.
* **Risk score** (0-100) -- a weighted blend of blast radius, zone penetration,
  crown-jewel exposure and path novelty, bucketed into LOW / MEDIUM / HIGH.

The weights are deliberately explicit module constants so an enterprise can tune
them per organisation and so every score is explainable to an auditor.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..models.enums import RiskLevel
from ..models.simulation import RiskAssessment
from ..models.snapshot import ReachabilityPath, Snapshot

#: Exploitability weight per destination port. Higher means more dangerous to
#: leave reachable: remote-admin and file-sharing ports dominate, application
#: data ports are moderate, and unauthenticated web/plaintext ports are lower.
PORT_SENSITIVITY: dict[int, float] = {
    22: 0.95,    # SSH - full remote control
    23: 0.98,    # Telnet - remote control, cleartext
    445: 0.95,   # SMB - lateral movement, ransomware
    3389: 0.92,  # RDP - full remote control
    1433: 0.85,  # MSSQL
    3306: 0.85,  # MySQL
    6379: 0.85,  # Redis - frequently unauthenticated
    9200: 0.80,  # Elasticsearch
    5432: 0.50,  # PostgreSQL - expected application dependency
    1521: 0.60,  # Oracle
    53: 0.15,    # DNS
    80: 0.30,    # HTTP
    443: 0.30,   # HTTPS
}

#: Sensitivity when every destination port is reachable (the worst case).
ANY_PORT_SENSITIVITY: float = 1.0

#: Sensitivity for ICMP reachability (reconnaissance value only).
ICMP_SENSITIVITY: float = 0.20

#: Sensitivity applied to ports with no explicit mapping.
DEFAULT_PORT_SENSITIVITY: float = 0.60

#: Weight of each scoring component. Must sum to 1.0.
W_BLAST_RADIUS: float = 0.40
W_ZONE_PENETRATION: float = 0.25
W_CROWN_JEWEL_EXPOSURE: float = 0.25
W_PATH_NOVELTY: float = 0.10

#: Risk bucket thresholds (inclusive lower bounds).
HIGH_RISK_THRESHOLD: float = 70.0
MEDIUM_RISK_THRESHOLD: float = 30.0


def port_sensitivity(dport: int | None, protocol: str = "tcp") -> float:
    """Exploitability weight for a destination port.

    Args:
        dport: Destination port, or ``None`` for an unrestricted permit.
        protocol: IP protocol; ICMP uses a fixed reconnaissance weight.

    Returns:
        A weight in the range ``0.0``-``1.0``.
    """
    if protocol.lower() == "icmp":
        return ICMP_SENSITIVITY
    if dport is None:
        return ANY_PORT_SENSITIVITY
    return PORT_SENSITIVITY.get(dport, DEFAULT_PORT_SENSITIVITY)


def range_sensitivity(low: int, high: int) -> float:
    """Exploitability of an inclusive destination-port interval.

    Uses the most dangerous known port inside the interval; if the interval also
    contains ports with no explicit mapping, the default weight is considered
    too. An interval spanning the whole port space is the maximal case.

    Args:
        low: Inclusive lower bound.
        high: Inclusive upper bound.

    Returns:
        A weight in the range ``0.0``-``1.0``.
    """
    if low <= 0 and high >= 65535:
        return ANY_PORT_SENSITIVITY

    best = 0.0
    known_inside = 0
    for port, sensitivity in PORT_SENSITIVITY.items():
        if low <= port <= high:
            known_inside += 1
            best = max(best, sensitivity)
    if (high - low + 1) > known_inside:
        best = max(best, DEFAULT_PORT_SENSITIVITY)
    return best


def path_exposure(path: ReachabilityPath) -> float:
    """Exploitability of a single reachable path.

    For port-agnostic flows the exposure is the *most* dangerous port every hop
    agreed on, which is the worst case an attacker could actually realise.
    """
    if path.protocol.lower() == "icmp":
        return ICMP_SENSITIVITY
    if path.dport is not None:
        return port_sensitivity(path.dport, path.protocol)
    if not path.reachable_ports:
        return 0.0
    return max(range_sensitivity(low, high) for low, high in path.reachable_ports)


def bucket(score: float) -> RiskLevel:
    """Map a numeric score onto a risk category."""
    if score >= HIGH_RISK_THRESHOLD:
        return RiskLevel.HIGH
    if score >= MEDIUM_RISK_THRESHOLD:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def attack_paths(
    snapshot: Snapshot, origin: str, flows: tuple[str, ...] = ()
) -> list[ReachabilityPath]:
    """Return reachable paths originating at ``origin``.

    Args:
        snapshot: Snapshot whose solved matrix is inspected.
        origin: Node the attacker is assumed to control.
        flows: Optional probe-flow names to restrict the analysis to.

    Returns:
        Reachable paths, most exploitable first.
    """
    selected = [
        path
        for path in snapshot.paths_from(origin)
        if not flows or path.flow_name in flows
    ]
    return sorted(selected, key=path_exposure, reverse=True)


def assess(
    snapshot: Snapshot,
    origin: str,
    flows: tuple[str, ...] = (),
    novelty_ratio: float = 0.0,
) -> RiskAssessment:
    """Quantify posture from ``origin`` under the state captured in ``snapshot``.

    Args:
        snapshot: Snapshot to analyse.
        origin: Compromise origin node.
        flows: Optional probe-flow filter.
        novelty_ratio: Fraction of previously blocked origin paths that this
            change opened (``0.0`` for a standalone assessment).

    Returns:
        A populated :class:`~app.models.simulation.RiskAssessment`.

    Raises:
        KeyError: If ``origin`` is not a node in the snapshot topology.
    """
    topology = snapshot.topology
    # Fail loudly on an unknown origin rather than silently scoring zero.
    topology.node(origin)
    origin_zone = topology.zone_of(origin).name

    paths = attack_paths(snapshot, origin, flows)

    exposure_by_node: dict[str, float] = {}
    for path in paths:
        exposure = path_exposure(path)
        if path.dst_node == origin:
            continue
        exposure_by_node[path.dst_node] = max(exposure_by_node.get(path.dst_node, 0.0), exposure)

    reachable_nodes = sorted(exposure_by_node)
    # The denominator is the whole estate, including the origin: it is part of
    # the protected estate even though it is assumed lost. Keeping the same
    # denominator as `aggregate` makes per-origin and union radii comparable.
    total_mass = sum(node.criticality for node in topology.nodes.values())
    reached_mass = sum(
        topology.node(name).criticality * exposure for name, exposure in exposure_by_node.items()
    )

    blast_radius_pct = (100.0 * reached_mass / total_mass) if total_mass else 0.0

    crown_jewels_reached = sorted(
        name for name in reachable_nodes if topology.node(name).is_crown_jewel
    )
    crown_jewel_exposure = max(
        (exposure_by_node[name] for name in crown_jewels_reached), default=0.0
    )

    zones_penetrated = sorted(
        {
            topology.zone_of(name).name
            for name in reachable_nodes
            if topology.zone_of(name).name != origin_zone
        }
    )
    zone_denominator = max(1, len(topology.zones) - 1)
    zone_penetration_ratio = len(zones_penetrated) / zone_denominator

    components = {
        "blast_radius": W_BLAST_RADIUS * (blast_radius_pct / 100.0),
        "zone_penetration": W_ZONE_PENETRATION * zone_penetration_ratio,
        "crown_jewel_exposure": W_CROWN_JEWEL_EXPOSURE * crown_jewel_exposure,
        "path_novelty": W_PATH_NOVELTY * max(0.0, min(1.0, novelty_ratio)),
    }
    risk_score = round(100.0 * min(1.0, sum(components.values())), 2)

    findings: list[str] = []
    if crown_jewels_reached:
        for name in crown_jewels_reached:
            best = next((p for p in paths if p.dst_node == name), None)
            if best is None:  # pragma: no cover - defensive
                continue
            service = (
                f"TCP/{best.dport}"
                if best.dport is not None
                else ("any port" if best.reachable_ports is None else f"ports {list(best.reachable_ports)}")
            )
            findings.append(
                f"Crown-jewel asset {name} is reachable from {origin} via "
                f"{best.flow_name} ({service}); exposure {exposure_by_node[name]:.2f}."
            )
    if zones_penetrated:
        findings.append(
            f"Compromise of {origin} penetrates zone(s) {', '.join(zones_penetrated)} "
            f"beyond its own zone '{origin_zone}'."
        )
    if blast_radius_pct >= 60.0:
        findings.append(
            f"Blast radius is {blast_radius_pct:.1f}% of weighted asset value; a single "
            "foothold would reach most of the estate."
        )
    if any(exposure >= ANY_PORT_SENSITIVITY for exposure in exposure_by_node.values()):
        findings.append(
            "At least one asset is reachable on every port, indicating a missing "
            "port-level restriction somewhere on the path."
        )
    if not findings:
        findings.append(
            f"No crown-jewel asset is exposed from {origin}; blast radius is "
            f"{blast_radius_pct:.1f}%."
        )

    return RiskAssessment(
        origin_node=origin,
        risk_score=risk_score,
        risk_level=bucket(risk_score),
        blast_radius_pct=round(blast_radius_pct, 2),
        reachable_nodes=tuple(reachable_nodes),
        crown_jewels_reached=tuple(crown_jewels_reached),
        zones_penetrated=tuple(zones_penetrated),
        exposure_by_node={k: round(v, 3) for k, v in sorted(exposure_by_node.items())},
        findings=tuple(findings),
    )


def aggregate(
    snapshot: Snapshot,
    origins: tuple[str, ...],
    flows: tuple[str, ...] = (),
    novelty_by_origin: Mapping[str, float] | None = None,
) -> tuple[float, RiskLevel, float]:
    """Combine per-origin assessments into a worst-case score and union radius.

    Args:
        snapshot: Snapshot to analyse.
        origins: Origin nodes to fan out from.
        flows: Optional probe-flow filter.
        novelty_by_origin: Per-origin path-novelty ratios, supplied when the
            analysis folds in a candidate change. Passing them keeps this
            function's scores identical to the differential engine's, so the
            two endpoints never disagree about the same change.

    Returns:
        A ``(worst_score, worst_level, union_blast_radius_pct)`` tuple.
    """
    if not origins:
        return 0.0, RiskLevel.LOW, 0.0

    novelty = novelty_by_origin or {}
    assessments = [
        assess(snapshot, origin, flows, novelty_ratio=novelty.get(origin, 0.0))
        for origin in origins
    ]
    worst_score = max(a.risk_score for a in assessments)

    topology = snapshot.topology
    reached: dict[str, float] = {}
    for origin in origins:
        for path in attack_paths(snapshot, origin, flows):
            reached[path.dst_node] = max(reached.get(path.dst_node, 0.0), path_exposure(path))
    # Same denominator as `assess`: the whole estate.
    total_mass = sum(node.criticality for node in topology.nodes.values())
    union_mass = sum(topology.node(name).criticality * exposure for name, exposure in reached.items())
    union_pct = (100.0 * union_mass / total_mass) if total_mass else 0.0

    return worst_score, bucket(worst_score), round(union_pct, 2)


def novelty_ratio(snapshot: Snapshot, origin: str, projected_paths: tuple[ReachabilityPath, ...]) -> float:
    """Fraction of previously blocked origin paths that a change opens up.

    Args:
        snapshot: Baseline snapshot.
        origin: Origin node.
        projected_paths: Paths solved under the candidate change.

    Returns:
        A ratio in ``0.0``-``1.0``; ``0.0`` when nothing new opened.
    """
    baseline = snapshot.path_index()
    blocked_before = 0
    opened = 0
    for path in projected_paths:
        if path.src_node != origin or not path.reachable:
            continue
        before = baseline.get(path.key)
        if before is not None and not before.reachable:
            blocked_before += 1
            opened += 1

    total_blocked = sum(
        1 for path in snapshot.paths if path.src_node == origin and not path.reachable
    )
    if total_blocked == 0:
        return 0.0
    return min(1.0, opened / total_blocked)


__all__ = [
    "ANY_PORT_SENSITIVITY",
    "DEFAULT_PORT_SENSITIVITY",
    "HIGH_RISK_THRESHOLD",
    "ICMP_SENSITIVITY",
    "MEDIUM_RISK_THRESHOLD",
    "PORT_SENSITIVITY",
    "W_BLAST_RADIUS",
    "W_CROWN_JEWEL_EXPOSURE",
    "W_PATH_NOVELTY",
    "W_ZONE_PENETRATION",
    "aggregate",
    "assess",
    "attack_paths",
    "bucket",
    "novelty_ratio",
    "path_exposure",
    "port_sensitivity",
    "range_sensitivity",
]
