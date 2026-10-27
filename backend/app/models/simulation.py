"""Simulation domain model: candidate changes, deltas and risk assessment."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .enums import (
    ChainName,
    ChangeDirection,
    ChangeType,
    ComplianceStatus,
    RiskLevel,
    RuleAction,
    RuntimeMode,
)
from .policy import PolicyRule
from .snapshot import ReachabilityPath, SnapshotSummary, utc_now

# =============================================================================
# Change requests
# =============================================================================


class ChangeRequest(BaseModel):
    """A candidate change to evaluate before it touches production.

    Only the fields relevant to :attr:`change_type` are required; the validator
    below enforces that contract and produces actionable error messages.
    """

    change_type: ChangeType = Field(description="Operation to simulate.")
    target_node: str = Field(
        description="Node the change is applied to (the enforcing device for flow changes)."
    )
    description: str | None = Field(
        default=None, description="Change-ticket reference or free-text rationale."
    )

    # -- Flow-level operations ----------------------------------------------
    chain: ChainName = Field(
        default=ChainName.FORWARD, description="Chain to modify for flow-level changes."
    )
    src: str | None = Field(default=None, description="Source prefix, e.g. '10.10.10.0/24'.")
    dst: str | None = Field(default=None, description="Destination prefix or host address.")
    protocol: str = Field(default="tcp", description="Protocol for the permitted/denied flow.")
    dport: int | None = Field(
        default=None, ge=0, le=65535, description="Destination port; omit for all ports."
    )

    # -- Raw rule operations -------------------------------------------------
    rule: str | None = Field(
        default=None, description="Raw iptables argument string, e.g. '-s 10.0.0.0/8 -j ACCEPT'."
    )
    rule_index: int | None = Field(
        default=None, ge=1, description="1-based index of the rule to remove."
    )

    # -- Link operations -----------------------------------------------------
    neighbour: str | None = Field(
        default=None, description="Peer node whose cable is toggled for set_link_state."
    )
    enabled: bool | None = Field(
        default=None, description="Desired link state for set_link_state."
    )

    # -- Compromise simulation ----------------------------------------------
    origin_node: str | None = Field(
        default=None, description="Assumed-compromised node for compromise_node changes."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "change_type": "allow_flow",
                    "target_node": "perimeter-gateway",
                    "chain": "FORWARD",
                    "src": "10.10.10.0/24",
                    "dst": "10.10.20.50",
                    "protocol": "tcp",
                    "dport": 22,
                    "description": "CHG-1042: open SSH from corp zone to database server",
                },
                {
                    "change_type": "compromise_node",
                    "target_node": "employee-workstation",
                    "origin_node": "employee-workstation",
                    "description": "Assume workstation is attacker-controlled",
                },
            ]
        }
    )

    @model_validator(mode="after")
    def _require_fields_for_type(self) -> ChangeRequest:
        """Enforce the per-operation required-field contract.

        Raises:
            ValueError: When required fields for the requested change type are
                missing, with a message naming the missing fields.
        """
        missing: list[str] = []

        if self.change_type in (ChangeType.ALLOW_FLOW, ChangeType.DENY_FLOW):
            if not self.src:
                missing.append("src")
            if not self.dst:
                missing.append("dst")
        elif self.change_type == ChangeType.ADD_POLICY_RULE:
            if not self.rule:
                missing.append("rule")
        elif self.change_type == ChangeType.REMOVE_POLICY_RULE:
            if self.rule_index is None:
                missing.append("rule_index")
        elif self.change_type == ChangeType.SET_LINK_STATE:
            if not self.neighbour:
                missing.append("neighbour")
            if self.enabled is None:
                missing.append("enabled")

        if missing:
            raise ValueError(
                f"change_type={self.change_type.value!r} requires: {', '.join(missing)}"
            )
        return self


# =============================================================================
# Deltas
# =============================================================================


class PolicyDelta(BaseModel):
    """Firewall rule differences between a baseline and a projected state."""

    model_config = ConfigDict(frozen=True)

    added: tuple[PolicyRule, ...] = Field(default_factory=tuple, description="Newly installed rules.")
    removed: tuple[PolicyRule, ...] = Field(default_factory=tuple, description="Removed rules.")
    chain_defaults_changed: dict[str, Any] = Field(
        default_factory=dict, description="Chain default verdict changes keyed by 'node:CHAIN'."
    )

    @property
    def is_empty(self) -> bool:
        """Whether the change touched no firewall state."""
        return not self.added and not self.removed and not self.chain_defaults_changed


class ReachabilityDelta(BaseModel):
    """Reachability differences between a baseline and a projected state."""

    model_config = ConfigDict(frozen=True)

    newly_reachable: tuple[ReachabilityPath, ...] = Field(
        default_factory=tuple, description="Paths that opened up (new exposure)."
    )
    newly_blocked: tuple[ReachabilityPath, ...] = Field(
        default_factory=tuple, description="Paths that closed (hardening)."
    )
    exposure_widened: tuple[ReachabilityPath, ...] = Field(
        default_factory=tuple,
        description=(
            "Paths that stayed reachable but became more exploitable, for example a "
            "port-agnostic flow whose permitted port set widened to every port."
        ),
    )
    unchanged_reachable: int = Field(default=0, ge=0, description="Paths open before and after.")
    total_paths: int = Field(default=0, ge=0, description="Total paths evaluated.")


class RiskAssessment(BaseModel):
    """Quantified posture for one origin (attacker) node."""

    model_config = ConfigDict(frozen=True)

    origin_node: str = Field(description="Node the analysis fans out from.")
    risk_score: float = Field(ge=0.0, le=100.0, description="Composite risk score, 0-100.")
    risk_level: RiskLevel = Field(description="Bucketed risk category.")
    blast_radius_pct: float = Field(
        ge=0.0, le=100.0,
        description="Weighted share of non-origin asset value reachable from the origin.",
    )
    reachable_nodes: tuple[str, ...] = Field(
        default_factory=tuple, description="Nodes reachable from the origin."
    )
    crown_jewels_reached: tuple[str, ...] = Field(
        default_factory=tuple, description="Crown-jewel assets reachable from the origin."
    )
    zones_penetrated: tuple[str, ...] = Field(
        default_factory=tuple, description="Zones beyond the origin's own zone that were reached."
    )
    exposure_by_node: dict[str, float] = Field(
        default_factory=dict, description="Highest exploitability score per reached node (0-1)."
    )
    findings: tuple[str, ...] = Field(
        default_factory=tuple, description="Plain-language findings for the change ticket."
    )


class RiskDelta(BaseModel):
    """Baseline-versus-projected risk comparison."""

    model_config = ConfigDict(frozen=True)

    baseline: RiskAssessment = Field(description="Risk under the current baseline.")
    projected: RiskAssessment = Field(description="Risk if the change is deployed.")
    score_delta: float = Field(description="projected - baseline risk score.")
    blast_radius_delta: float = Field(description="projected - baseline blast radius (pp).")
    risk_level_transition: str = Field(
        description="Human-readable transition, e.g. 'medium -> high'."
    )
    direction: ChangeDirection = Field(description="improved | regressed | neutral.")


# =============================================================================
# Responses
# =============================================================================


class SimulationResult(BaseModel):
    """Outcome of evaluating one candidate change against the baseline."""

    model_config = ConfigDict(frozen=True)

    simulation_id: str = Field(description="Unique simulation identifier.")
    created_at: datetime = Field(default_factory=utc_now, description="Evaluation timestamp (UTC).")
    lab_name: str = Field(description="Containerlab lab name.")
    runtime_mode: RuntimeMode = Field(description="live or model.")
    runtime_available: bool = Field(description="Whether Docker was reachable.")
    applied: bool = Field(
        default=False,
        description="Whether the change was also pushed to live containers.",
    )
    baseline_snapshot_id: str = Field(description="Snapshot the change was evaluated against.")
    change: ChangeRequest = Field(description="The change that was evaluated.")
    policy_delta: PolicyDelta = Field(description="Firewall rule differences.")
    reachability_delta: ReachabilityDelta = Field(description="Reachability differences.")
    risk: RiskDelta = Field(description="Baseline versus projected risk.")
    summary: str = Field(description="One-paragraph operator summary.")
    warnings: tuple[str, ...] = Field(default_factory=tuple, description="Non-fatal issues.")


class BlastRadiusRequest(BaseModel):
    """Request body for graph-based blast-radius analysis."""

    origin_node: str | None = Field(
        default=None,
        description="Node to fan out from. Defaults to every configured entry point.",
    )
    origin_nodes: tuple[str, ...] = Field(
        default_factory=tuple, description="Explicit set of origins (overrides origin_node)."
    )
    flows: tuple[str, ...] = Field(
        default_factory=tuple, description="Probe flows to consider; empty means all."
    )
    include_simulated_change: ChangeRequest | None = Field(
        default=None, description="Optional candidate change to analyse instead of the baseline."
    )


class BlastRadiusResponse(BaseModel):
    """Blast-radius and attack-path analysis result."""

    model_config = ConfigDict(frozen=True)

    lab_name: str = Field(description="Containerlab lab name.")
    runtime_mode: RuntimeMode = Field(description="live or model.")
    baseline_snapshot_id: str = Field(description="Snapshot used as the analysis base.")
    analysed_change: ChangeRequest | None = Field(
        default=None, description="Candidate change folded into the analysis, if any."
    )
    assessments: tuple[RiskAssessment, ...] = Field(
        description="Per-origin risk assessments."
    )
    aggregate_risk_score: float = Field(
        ge=0.0, le=100.0, description="Worst-case score across origins."
    )
    aggregate_risk_level: RiskLevel = Field(description="Bucket for the aggregate score.")
    blast_radius_pct: float = Field(
        ge=0.0, le=100.0, description="Union blast radius across all origins."
    )
    attack_paths: tuple[ReachabilityPath, ...] = Field(
        default_factory=tuple, description="Reachable paths that constitute attack paths."
    )


class RollbackResponse(BaseModel):
    """Result of reverting the twin to its captured baseline."""

    model_config = ConfigDict(frozen=True)

    restored_snapshot_id: str = Field(description="Baseline snapshot now in effect.")
    reverted_simulation_ids: tuple[str, ...] = Field(
        default_factory=tuple, description="Simulations discarded by the rollback."
    )
    runtime_applied: bool = Field(
        default=False, description="Whether rules were re-pushed to live containers."
    )
    warnings: tuple[str, ...] = Field(default_factory=tuple, description="Non-fatal issues.")


class SnapshotResponse(BaseModel):
    """Response for ``POST /api/v1/snapshot``."""

    model_config = ConfigDict(frozen=True)

    snapshot: SnapshotSummary = Field(description="Summary of the captured baseline.")
    is_baseline: bool = Field(description="Whether this snapshot is the active baseline.")
    node_states: tuple[Any, ...] = Field(
        default_factory=tuple, description="Per-node state summaries."
    )


class ComplianceFinding(BaseModel):
    """A single compliance control evaluation."""

    model_config = ConfigDict(frozen=True)

    control_id: str = Field(description="Stable control identifier.")
    title: str = Field(description="Control name.")
    status: ComplianceStatus = Field(description="pass | fail | warn.")
    severity: RiskLevel = Field(description="Severity if the control fails.")
    detail: str = Field(description="What was observed.")
    remediation: str = Field(description="How to fix it.")
    affected_nodes: tuple[str, ...] = Field(
        default_factory=tuple, description="Nodes implicated by the finding."
    )


class ComplianceReport(BaseModel):
    """Aggregated compliance posture."""

    model_config = ConfigDict(frozen=True)

    lab_name: str = Field(description="Containerlab lab name.")
    evaluated_at: datetime = Field(default_factory=utc_now, description="Evaluation timestamp.")
    score_pct: float = Field(ge=0.0, le=100.0, description="Percentage of controls passing.")
    passed: int = Field(ge=0, description="Controls passing.")
    failed: int = Field(ge=0, description="Controls failing.")
    warned: int = Field(ge=0, description="Controls with warnings.")
    findings: tuple[ComplianceFinding, ...] = Field(description="Per-control results.")


class RuntimeStatus(BaseModel):
    """Runtime availability probe result."""

    model_config = ConfigDict(frozen=True)

    docker_available: bool = Field(description="Whether the Docker daemon responded.")
    containerlab_available: bool = Field(description="Whether the containerlab CLI is installed.")
    lab_deployed: bool = Field(description="Whether lab containers are running.")
    running_nodes: tuple[str, ...] = Field(
        default_factory=tuple, description="Nodes whose containers are running."
    )
    missing_nodes: tuple[str, ...] = Field(
        default_factory=tuple, description="Nodes whose containers are absent or stopped."
    )
    runtime_mode: RuntimeMode = Field(description="Effective mode: live or model.")
    detail: str = Field(description="Human-readable status explanation.")


class LabLifecycleResponse(BaseModel):
    """Result of a deploy or destroy operation."""

    model_config = ConfigDict(frozen=True)

    action: str = Field(description="deploy | destroy.")
    success: bool = Field(description="Whether the command completed successfully.")
    command: tuple[str, ...] = Field(description="Exact argv that was executed.")
    return_code: int = Field(description="Process exit status.")
    stdout_tail: str = Field(default="", description="Trailing stdout for operator debugging.")
    stderr_tail: str = Field(default="", description="Trailing stderr for operator debugging.")
    duration_seconds: float = Field(ge=0.0, description="Wall-clock duration.")


__all__ = [
    "BlastRadiusRequest",
    "BlastRadiusResponse",
    "ChangeRequest",
    "ComplianceFinding",
    "ComplianceReport",
    "LabLifecycleResponse",
    "PolicyDelta",
    "ReachabilityDelta",
    "RiskAssessment",
    "RiskDelta",
    "RollbackResponse",
    "RuleAction",
    "RuntimeStatus",
    "SimulationResult",
    "SnapshotResponse",
]
