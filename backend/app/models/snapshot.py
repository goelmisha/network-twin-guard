"""Snapshot domain model.

A snapshot is the platform's immutable unit of truth: the declarative topology,
the compiled policy set, the observed runtime state of every container, and the
fully solved reachability matrix. Candidate changes are evaluated *against* a
snapshot and never mutate it, which is what makes safe rollback possible.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .enums import RuntimeMode
from .policy import PolicySet
from .topology import Interface, RouteEntry, Topology


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class ReachabilityPath(BaseModel):
    """The solved verdict for one ordered ``(source, destination, flow)`` triple."""

    model_config = ConfigDict(frozen=True)

    src_node: str = Field(description="Source node name.")
    dst_node: str = Field(description="Destination node name.")
    src_ip: str = Field(description="Source address used for policy matching.")
    dst_ip: str = Field(description="Destination address.")
    flow_name: str = Field(description="Probe flow label.")
    protocol: str = Field(description="IP protocol.")
    dport: int | None = Field(description="Requested destination port, or None for any.")
    reachable: bool = Field(description="Whether a new connection could complete.")
    hops: int = Field(default=0, ge=0, description="Number of layer-3 hops traversed.")
    path: tuple[str, ...] = Field(default_factory=tuple, description="Ordered node names.")
    reachable_ports: tuple[tuple[int, int], ...] = Field(
        default_factory=tuple,
        description=(
            "Reachable destination ports as inclusive ``(low, high)`` intervals. "
            "Empty when the path is blocked; ``((0, 65535),)`` when every port is "
            "open. For port-agnostic flows this is the exact intersection of the "
            "port intervals each hop permits, so a wildcard permit cannot mask an "
            "upstream DROP."
        ),
    )
    blocked_at: str | None = Field(default=None, description="Node that dropped the flow.")
    blocked_by: str | None = Field(
        default=None, description="Offending rule or chain default that blocked the flow."
    )
    reason: str = Field(default="", description="Human-readable explanation.")

    @property
    def key(self) -> tuple[str, str, str]:
        """Stable identity of the path: ``(src, dst, flow)``."""
        return (self.src_node, self.dst_node, self.flow_name)


class NodeRuntimeState(BaseModel):
    """Observed container state for a node, used to detect drift from the model."""

    model_config = ConfigDict(frozen=True)

    node: str = Field(description="Logical node name.")
    container_name: str = Field(description="Runtime container name.")
    running: bool = Field(description="Whether the container reports as running.")
    observed_interfaces: tuple[str, ...] = Field(
        default_factory=tuple, description="Live ``ip -br addr`` output lines."
    )
    observed_routes: tuple[str, ...] = Field(
        default_factory=tuple, description="Live ``ip route show`` output lines."
    )
    observed_policy_rules: int = Field(
        default=0, ge=0, description="Count of live iptables rules captured."
    )
    capture_error: str | None = Field(
        default=None, description="Why live capture failed, when it did."
    )


class Snapshot(BaseModel):
    """A complete, immutable point-in-time view of the twin."""

    model_config = ConfigDict(frozen=True)

    snapshot_id: str = Field(description="Unique snapshot identifier (content-derived).")
    created_at: datetime = Field(default_factory=utc_now, description="Capture timestamp (UTC).")
    lab_name: str = Field(description="Containerlab lab name.")
    runtime_mode: RuntimeMode = Field(description="Whether live runtime data was available.")
    runtime_available: bool = Field(
        default=False, description="Whether the Docker runtime was reachable at capture time."
    )
    topology: Topology = Field(description="Validated topology at capture time.")
    policy_set: PolicySet = Field(description="Compiled firewall policy at capture time.")
    nodes: dict[str, NodeRuntimeState] = Field(
        default_factory=dict, description="Per-node runtime observations."
    )
    paths: tuple[ReachabilityPath, ...] = Field(
        default_factory=tuple, description="Solved reachability matrix."
    )
    warnings: tuple[str, ...] = Field(
        default_factory=tuple, description="Degraded-mode and drift warnings."
    )

    # -- Derived views -------------------------------------------------------

    def path_index(self) -> dict[tuple[str, str, str], ReachabilityPath]:
        """Index every solved path by ``(src, dst, flow)``."""
        return {p.key: p for p in self.paths}

    def reachable_paths(self) -> list[ReachabilityPath]:
        """Only the paths that permit a new connection."""
        return [p for p in self.paths if p.reachable]

    def paths_from(self, node: str) -> list[ReachabilityPath]:
        """Reachable paths originating at ``node`` (attack paths)."""
        return [p for p in self.paths if p.src_node == node and p.reachable]

    def total_pairs(self) -> int:
        """Number of evaluated ``(src, dst, flow)`` triples."""
        return len(self.paths)

    @property
    def reachable_count(self) -> int:
        """Number of triples that permit a new connection."""
        return len(self.reachable_paths())

    def checksum(self) -> str:
        """Deterministic content hash over the security-relevant state.

        The digest covers topology, policy and the solved matrix -- but not the
        capture timestamp -- so identical states hash identically and drift can
        be detected without diffing full payloads.
        """
        payload: dict[str, Any] = {
            "nodes": {
                name: {
                    "interfaces": [i.address for i in node.interfaces],
                    "routes": [r.prefix + "|" + (r.via or "-") for r in node.all_routes()],
                    "defaults": {
                        str(k.value): str(v.value) for k, v in sorted(node.default_policies.items())
                    },
                }
                for name, node in sorted(self.topology.nodes.items())
            },
            "policy": [
                {
                    "node": r.node,
                    "chain": str(r.chain.value),
                    "index": r.index,
                    "raw": r.raw,
                    "action": str(r.action.value),
                }
                for r in self.policy_set.all_rules()
            ],
            "reachability": sorted(
                f"{p.src_node}->{p.dst_node}:{p.flow_name}={'up' if p.reachable else 'down'}"
                for p in self.paths
            ),
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def with_id(self) -> Snapshot:
        """Return a copy whose ``snapshot_id`` is the computed content checksum."""
        return self.model_copy(update={"snapshot_id": self.checksum()})


class SnapshotSummary(BaseModel):
    """Compact snapshot projection returned by the API list/detail endpoints."""

    model_config = ConfigDict(frozen=True)

    snapshot_id: str = Field(description="Snapshot identifier.")
    created_at: datetime = Field(description="Capture timestamp (UTC).")
    lab_name: str = Field(description="Containerlab lab name.")
    runtime_mode: RuntimeMode = Field(description="live or model.")
    runtime_available: bool = Field(description="Whether Docker was reachable.")
    total_pairs: int = Field(description="Evaluated (src, dst, flow) triples.")
    reachable_count: int = Field(description="Triples permitting a new connection.")
    node_count: int = Field(description="Number of nodes.")
    warnings: tuple[str, ...] = Field(default_factory=tuple, description="Degraded-mode warnings.")


class NodeStateSummary(BaseModel):
    """Per-node view of a snapshot for operator inspection."""

    model_config = ConfigDict(frozen=True)

    node: str = Field(description="Node name.")
    zone: str = Field(description="Zone name.")
    criticality: int = Field(description="Business criticality 1-5.")
    crown_jewel: bool = Field(description="Whether the node is a crown-jewel asset.")
    container_name: str = Field(description="Runtime container name.")
    running: bool = Field(description="Container running state.")
    interfaces: tuple[Interface, ...] = Field(description="Declared interfaces.")
    routes: tuple[RouteEntry, ...] = Field(description="Effective routing table.")
    default_policies: dict[str, str] = Field(description="Chain default verdicts.")
    policy_rule_count: int = Field(description="Number of installed firewall rules.")
