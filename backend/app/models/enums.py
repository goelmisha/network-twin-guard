"""Shared enumerations for the Corporate Twin domain model.

Values are plain strings so they serialise cleanly over the REST API and remain
stable for external consumers (dashboards, CI pipelines, ticketing webhooks).
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """String enum base that serialises to its value."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


class NodeRole(StrEnum):
    """Functional role a twin node plays in the simulated network."""

    ROUTER = "router"
    HOST = "host"
    FIREWALL = "firewall"


class ChainName(StrEnum):
    """Netfilter hook points modelled by the solver."""

    INPUT = "INPUT"
    FORWARD = "FORWARD"
    OUTPUT = "OUTPUT"


class RuleAction(StrEnum):
    """Verdict a firewall rule or chain policy can produce.

    ``ACCEPT``, ``DROP`` and ``REJECT`` are terminal: evaluation stops at the
    first matching rule. ``LOG`` is non-terminal in netfilter -- it records the
    packet and evaluation continues to the next rule -- so the solver skips it.
    """

    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    LOG = "LOG"

    @property
    def is_terminal(self) -> bool:
        """Whether matching this action ends chain evaluation."""
        return self is not RuleAction.LOG


class RuntimeMode(StrEnum):
    """How a snapshot or simulation was produced."""

    LIVE = "live"
    """State captured from running containers via the Docker API."""

    MODEL = "model"
    """State resolved from the declarative model only (no runtime available)."""


class RiskLevel(StrEnum):
    """Bucketed risk categorisation exposed to the dashboard."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ChangeDirection(StrEnum):
    """Whether a candidate change improves or degrades posture."""

    IMPROVED = "improved"
    REGRESSED = "regressed"
    NEUTRAL = "neutral"


class ChangeType(StrEnum):
    """Candidate change operations accepted by the what-if engine."""

    ALLOW_FLOW = "allow_flow"
    DENY_FLOW = "deny_flow"
    ADD_POLICY_RULE = "add_policy_rule"
    REMOVE_POLICY_RULE = "remove_policy_rule"
    SET_LINK_STATE = "set_link_state"
    COMPROMISE_NODE = "compromise_node"


class ComplianceStatus(StrEnum):
    """Outcome of a single compliance control check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class InterfaceState(StrEnum):
    """Operational state of a node interface."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"
