"""Differential engine.

Compares a baseline against a projected state across the two dimensions that
matter to a change-approval board:

* **Policy delta** -- which firewall rules were added or removed.
* **Reachability delta** -- which previously blocked paths opened up (new
  exposure) and which previously open paths closed (hardening).

Both are computed as set differences over stable keys so the result is
deterministic and safe to attach to a change ticket.
"""

from __future__ import annotations

from collections import Counter

from ..models.enums import ChainName
from ..models.policy import PolicyRule, PolicySet
from ..models.simulation import (
    ChangeRequest,
    PolicyDelta,
    ReachabilityDelta,
    RiskDelta,
)
from ..models.snapshot import ReachabilityPath, Snapshot
from . import risk as risk_module


def _rule_key(rule: PolicyRule) -> tuple[str, str, str]:
    """Stable identity of a firewall rule for set comparison."""
    return (rule.node, str(rule.chain.value), rule.raw)


def diff_policy(before: PolicySet, after: PolicySet) -> PolicyDelta:
    """Compute the firewall rule difference between two policy sets.

    Args:
        before: Baseline policy.
        after: Projected policy.

    Returns:
        A :class:`PolicyDelta` listing added and removed rules plus any chain
        default verdict changes.
    """
    before_rules = {_rule_key(rule): rule for rule in before.all_rules()}
    after_rules = {_rule_key(rule): rule for rule in after.all_rules()}

    # Counter over the *keys* so duplicate rules are handled as a multiset.
    before_counts = Counter(before_rules.keys())
    after_counts = Counter(after_rules.keys())

    added_keys = list((after_counts - before_counts).elements())
    removed_keys = list((before_counts - after_counts).elements())

    added = tuple(after_rules[key] for key in added_keys if key in after_rules)
    removed = tuple(before_rules[key] for key in removed_keys if key in before_rules)

    defaults_changed: dict[str, dict[str, str]] = {}
    for node in sorted(set(before.chains) | set(after.chains)):
        for chain in ChainName:
            old = before.chain(node, chain).default_action
            new = after.chain(node, chain).default_action
            if old != new:
                defaults_changed[f"{node}:{chain.value}"] = {
                    "from": str(old.value),
                    "to": str(new.value),
                }

    return PolicyDelta(added=added, removed=removed, chain_defaults_changed=defaults_changed)


def diff_reachability(
    baseline: Snapshot, projected_paths: tuple[ReachabilityPath, ...]
) -> ReachabilityDelta:
    """Compute the reachability difference between a baseline and a projection.

    Args:
        baseline: Snapshot the change was evaluated against.
        projected_paths: Solved matrix under the candidate change.

    Returns:
        A :class:`ReachabilityDelta` with newly opened and newly closed paths.
    """
    baseline_index = baseline.path_index()

    newly_reachable: list[ReachabilityPath] = []
    newly_blocked: list[ReachabilityPath] = []
    exposure_widened: list[ReachabilityPath] = []
    unchanged_reachable = 0

    for path in projected_paths:
        previous = baseline_index.get(path.key)
        if previous is None:
            # A pair that did not exist before (new node / new flow).
            if path.reachable:
                newly_reachable.append(path)
            continue
        if path.reachable and not previous.reachable:
            newly_reachable.append(path)
        elif not path.reachable and previous.reachable:
            newly_blocked.append(path)
        elif path.reachable and previous.reachable:
            unchanged_reachable += 1
            # A path can stay reachable while becoming far more dangerous (for
            # example a port-agnostic flow whose permitted port set widens from
            # one application port to every port). That must be reported.
            if risk_module.path_exposure(path) > risk_module.path_exposure(previous):
                exposure_widened.append(path)

    return ReachabilityDelta(
        newly_reachable=tuple(newly_reachable),
        newly_blocked=tuple(newly_blocked),
        exposure_widened=tuple(exposure_widened),
        unchanged_reachable=unchanged_reachable,
        total_paths=len(projected_paths),
    )


def diff_risk(
    baseline: Snapshot,
    projected_paths: tuple[ReachabilityPath, ...],
    origin: str,
    flows: tuple[str, ...] = (),
) -> RiskDelta:
    """Compare baseline and projected risk for one origin.

    Args:
        baseline: Snapshot the change was evaluated against.
        projected_paths: Solved matrix under the candidate change.
        origin: Compromise origin node.
        flows: Optional probe-flow filter.

    Returns:
        A :class:`RiskDelta` including the risk-level transition and direction.
    """
    projected_snapshot = baseline.model_copy(update={"paths": projected_paths})
    projected = risk_module.assess(
        projected_snapshot,
        origin,
        flows,
        novelty_ratio=risk_module.novelty_ratio(baseline, origin, projected_paths),
    )
    baseline_assessment = risk_module.assess(baseline, origin, flows)

    score_delta = round(projected.risk_score - baseline_assessment.risk_score, 2)
    blast_delta = round(projected.blast_radius_pct - baseline_assessment.blast_radius_pct, 2)

    from ..models.enums import ChangeDirection

    if score_delta > 0.5:
        direction = ChangeDirection.REGRESSED
    elif score_delta < -0.5:
        direction = ChangeDirection.IMPROVED
    else:
        direction = ChangeDirection.NEUTRAL

    return RiskDelta(
        baseline=baseline_assessment,
        projected=projected,
        score_delta=score_delta,
        blast_radius_delta=blast_delta,
        risk_level_transition=(
            f"{baseline_assessment.risk_level.value} -> {projected.risk_level.value}"
        ),
        direction=direction,
    )


def build_summary(
    change: ChangeRequest,
    policy_delta: PolicyDelta,
    reachability_delta: ReachabilityDelta,
    risk_delta: RiskDelta,
) -> str:
    """Compose the one-paragraph operator summary attached to a simulation.

    Args:
        change: The evaluated change.
        policy_delta: Firewall rule differences.
        reachability_delta: Reachability differences.
        risk_delta: Risk comparison.

    Returns:
        A concise, decision-ready narrative.
    """
    parts: list[str] = [
        f"{change.change_type.value.replace('_', ' ').title()} on {change.target_node}"
    ]
    if policy_delta.added:
        parts.append(f"+{len(policy_delta.added)} rule(s)")
    if policy_delta.removed:
        parts.append(f"-{len(policy_delta.removed)} rule(s)")

    opened = len(reachability_delta.newly_reachable)
    closed = len(reachability_delta.newly_blocked)
    parts.append(f"{opened} path(s) opened, {closed} closed")
    if reachability_delta.exposure_widened:
        parts.append(f"{len(reachability_delta.exposure_widened)} existing path(s) widened")

    verdict = {
        "regressed": "REGRESSION",
        "improved": "HARDENING",
        "neutral": "NO NET CHANGE",
    }[risk_delta.direction.value]
    parts.append(
        f"{verdict}: risk {risk_delta.baseline.risk_score:.1f} -> "
        f"{risk_delta.projected.risk_score:.1f} ({risk_delta.risk_level_transition}), "
        f"blast radius {risk_delta.baseline.blast_radius_pct:.1f}% -> "
        f"{risk_delta.projected.blast_radius_pct:.1f}%"
    )

    if risk_delta.projected.crown_jewels_reached:
        parts.append(
            "crown jewels exposed: " + ", ".join(risk_delta.projected.crown_jewels_reached)
        )
    return "; ".join(parts) + "."


__all__ = ["build_summary", "diff_policy", "diff_reachability", "diff_risk"]
