"""Solver core: topology loading, policy compilation, reachability and risk.

Layering rule: nothing in :mod:`app.core` imports from :mod:`app.services` or
:mod:`app.api`, so the simulation engine can be unit-tested and reused headlessly.
"""

from .change import ChangeOutcome, apply_change
from .compliance import evaluate_compliance
from .diff import build_summary, diff_policy, diff_reachability, diff_risk
from .exceptions import (
    ChangeValidationError,
    CommandExecutionError,
    PolicyParseError,
    RollbackError,
    RuntimeUnavailableError,
    SnapshotNotFoundError,
    TopologyModelError,
    TwinError,
)
from .policy_engine import PolicyEngine, Verdict, compile_policy_set, parse_rule
from .reachability import MAX_HOPS, FlowVerdict, ReachabilitySolver
from .snapshot import build_snapshot, node_state_summaries, summarise
from .topology_loader import TwinModel, load_twin_model

__all__ = [
    "MAX_HOPS",
    "ChangeOutcome",
    "ChangeValidationError",
    "CommandExecutionError",
    "FlowVerdict",
    "PolicyEngine",
    "PolicyParseError",
    "ReachabilitySolver",
    "RollbackError",
    "RuntimeUnavailableError",
    "SnapshotNotFoundError",
    "TopologyModelError",
    "TwinError",
    "TwinModel",
    "Verdict",
    "apply_change",
    "build_snapshot",
    "build_summary",
    "compile_policy_set",
    "diff_policy",
    "diff_reachability",
    "diff_risk",
    "evaluate_compliance",
    "load_twin_model",
    "node_state_summaries",
    "parse_rule",
    "summarise",
]
