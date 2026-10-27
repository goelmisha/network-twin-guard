"""Snapshot construction.

Turns a validated :class:`~app.core.topology_loader.TwinModel` plus optional
live container observations into an immutable
:class:`~app.models.snapshot.Snapshot`: the solved reachability matrix, the
compiled policy, and the runtime state the platform later diffs against.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..models.enums import RuntimeMode
from ..models.snapshot import (
    NodeRuntimeState,
    NodeStateSummary,
    Snapshot,
    SnapshotSummary,
)
from .reachability import ReachabilitySolver
from .topology_loader import TwinModel


def build_snapshot(
    model: TwinModel,
    *,
    runtime_available: bool = False,
    node_states: Mapping[str, NodeRuntimeState] | None = None,
    warnings: Sequence[str] = (),
) -> Snapshot:
    """Capture a snapshot of the twin.

    Args:
        model: Validated topology plus compiled policy.
        runtime_available: Whether live container state could be read.
        node_states: Observed per-node runtime state, keyed by node name.
        warnings: Degraded-mode observations to attach to the snapshot.

    Returns:
        A fully solved, content-addressed :class:`Snapshot`.
    """
    solver = ReachabilitySolver(model.topology, model.policy_set)
    paths = solver.solve_matrix()

    snapshot = Snapshot(
        snapshot_id="pending",
        lab_name=model.topology.lab_name,
        runtime_mode=RuntimeMode.LIVE if runtime_available else RuntimeMode.MODEL,
        runtime_available=runtime_available,
        topology=model.topology,
        policy_set=model.policy_set,
        nodes=dict(node_states or {}),
        paths=paths,
        warnings=tuple(warnings),
    )
    return snapshot.with_id()


def summarise(snapshot: Snapshot) -> SnapshotSummary:
    """Project a snapshot into the compact form returned by the API."""
    return SnapshotSummary(
        snapshot_id=snapshot.snapshot_id,
        created_at=snapshot.created_at,
        lab_name=snapshot.lab_name,
        runtime_mode=snapshot.runtime_mode,
        runtime_available=snapshot.runtime_available,
        total_pairs=snapshot.total_pairs(),
        reachable_count=snapshot.reachable_count,
        node_count=len(snapshot.topology.nodes),
        warnings=snapshot.warnings,
    )


def node_state_summaries(snapshot: Snapshot) -> list[NodeStateSummary]:
    """Build the per-node projection used by the inspect endpoint and UI."""
    summaries: list[NodeStateSummary] = []
    for name, node in snapshot.topology.nodes.items():
        runtime = snapshot.nodes.get(name)
        rule_count = sum(
            len(snapshot.policy_set.chain(name, chain).rules) for chain in snapshot.policy_set.node_chains(name)
        )
        summaries.append(
            NodeStateSummary(
                node=name,
                zone=node.zone,
                criticality=node.criticality,
                crown_jewel=node.is_crown_jewel,
                container_name=node.container_name,
                running=runtime.running if runtime else False,
                interfaces=node.interfaces,
                routes=node.all_routes(),
                default_policies={
                    str(chain.value): str(action.value)
                    for chain, action in sorted(node.default_policies.items())
                },
                policy_rule_count=rule_count,
            )
        )
    return summaries


__all__ = ["build_snapshot", "node_state_summaries", "summarise"]
