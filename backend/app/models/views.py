"""API-facing projection models.

These are deliberately separate from the domain models: the dashboard needs a
flattened, presentation-oriented view (zone labels, running state, rule counts)
without dragging the full solver state across the wire.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .enums import ChangeDirection, NodeRole, RiskLevel, RuleAction, RuntimeMode


class InterfaceView(BaseModel):
    """Flattened interface projection."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Interface name.")
    address: str = Field(description="CIDR address.")
    subnet: str = Field(description="Attached subnet.")
    up: bool = Field(description="Whether the interface is up.")


class NodeView(BaseModel):
    """Topology node projection for map rendering."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Node name.")
    role: NodeRole = Field(description="Router, host or firewall.")
    zone: str = Field(description="Zone name.")
    zone_label: str = Field(description="Zone display label.")
    zone_tier: int = Field(description="Zone sensitivity tier.")
    criticality: int = Field(description="Business criticality 1-5.")
    crown_jewel: bool = Field(description="Whether this is a crown-jewel asset.")
    ip_forward: bool = Field(description="Whether the node forwards packets.")
    container_name: str = Field(description="Runtime container name.")
    primary_ip: str | None = Field(default=None, description="Primary data-plane address.")
    running: bool = Field(description="Whether the container is running.")
    interfaces: tuple[InterfaceView, ...] = Field(description="Interfaces.")
    policy_rule_count: int = Field(description="Installed firewall rule count.")
    default_policies: dict[str, str] = Field(description="Chain default verdicts.")


class LinkView(BaseModel):
    """Topology link projection."""

    model_config = ConfigDict(frozen=True)

    source: str = Field(description="First endpoint node.")
    target: str = Field(description="Second endpoint node.")
    source_iface: str = Field(description="First endpoint interface.")
    target_iface: str = Field(description="Second endpoint interface.")
    subnet: str = Field(description="Shared subnet.")
    up: bool = Field(description="Whether both endpoints are up.")


class ZoneView(BaseModel):
    """Zone projection including node counts."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Zone name.")
    label: str = Field(description="Display label.")
    tier: int = Field(description="Sensitivity tier.")
    crown_jewel: bool = Field(description="Whether the zone hosts crown jewels.")
    node_count: int = Field(description="Nodes in this zone.")


class TopologyView(BaseModel):
    """Complete topology projection consumed by the dashboard map."""

    model_config = ConfigDict(frozen=True)

    lab_name: str = Field(description="Containerlab lab name.")
    runtime_mode: RuntimeMode = Field(description="live or model.")
    runtime_detail: str = Field(description="Human-readable runtime status.")
    nodes: tuple[NodeView, ...] = Field(description="Nodes.")
    links: tuple[LinkView, ...] = Field(description="Links.")
    zones: tuple[ZoneView, ...] = Field(description="Zones.")
    entrypoints: tuple[str, ...] = Field(description="Configured attacker entry points.")
    probe_flows: tuple[str, ...] = Field(description="Configured probe flow names.")


class SimulationHistoryEntry(BaseModel):
    """Compact record of a previously evaluated change."""

    model_config = ConfigDict(frozen=True)

    simulation_id: str = Field(description="Simulation identifier.")
    created_at: datetime = Field(description="Evaluation timestamp.")
    change_type: str = Field(description="Change type that was evaluated.")
    target_node: str = Field(description="Node the change targeted.")
    description: str | None = Field(default=None, description="Operator rationale.")
    direction: ChangeDirection = Field(description="improved | regressed | neutral.")
    baseline_score: float = Field(description="Risk score before the change.")
    projected_score: float = Field(description="Risk score after the change.")
    risk_level: RiskLevel = Field(description="Projected risk level.")
    blast_radius_pct: float = Field(description="Projected blast radius.")
    paths_opened: int = Field(description="Newly reachable paths.")
    paths_closed: int = Field(description="Newly blocked paths.")
    summary: str = Field(description="Operator summary.")


class HealthView(BaseModel):
    """Liveness and readiness payload for the dashboard and orchestrators."""

    model_config = ConfigDict(frozen=True)

    status: str = Field(description="ok | degraded.")
    version: str = Field(description="Backend version.")
    lab_name: str = Field(description="Containerlab lab name.")
    runtime_mode: RuntimeMode = Field(description="live or model.")
    docker_available: bool = Field(description="Docker daemon reachable.")
    containerlab_available: bool = Field(description="containerlab CLI installed.")
    lab_deployed: bool = Field(description="All lab containers running.")
    baseline_captured: bool = Field(description="Whether a baseline snapshot exists.")
    baseline_snapshot_id: str | None = Field(default=None, description="Baseline identifier.")
    detail: str = Field(description="Human-readable status detail.")
    checks: dict[str, bool] = Field(default_factory=dict, description="Named readiness checks.")


class ChainView(BaseModel):
    """A node chain rendered for inspection in the UI."""

    model_config = ConfigDict(frozen=True)

    node: str = Field(description="Owning node.")
    chain: str = Field(description="Chain name.")
    default_policy: RuleAction = Field(description="Default verdict.")
    rule_count: int = Field(description="Number of rules.")
    rules: tuple[str, ...] = Field(description="Rule arguments in evaluation order.")


__all__ = [
    "ChainView",
    "HealthView",
    "InterfaceView",
    "LinkView",
    "NodeView",
    "SimulationHistoryEntry",
    "TopologyView",
    "ZoneView",
]
