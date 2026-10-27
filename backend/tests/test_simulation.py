"""Tests for candidate-change application and the differential engine."""

from __future__ import annotations

import pytest

from app.core.change import apply_change
from app.core.diff import build_summary, diff_policy, diff_reachability, diff_risk
from app.core.exceptions import ChangeValidationError, PolicyParseError
from app.core.reachability import ReachabilitySolver
from app.core.topology_loader import TwinModel
from app.models.enums import ChainName, ChangeDirection, ChangeType, RiskLevel
from app.models.simulation import ChangeRequest
from app.models.snapshot import Snapshot


def _evaluate(baseline: Snapshot, change: ChangeRequest):
    """Apply a change to the baseline and return (policy delta, reachability delta, risk delta, paths)."""
    base_model = TwinModel(topology=baseline.topology, policy_set=baseline.policy_set)
    outcome = apply_change(base_model, change)
    paths = ReachabilitySolver(outcome.model.topology, outcome.model.policy_set).solve_matrix()
    origin = change.origin_node or baseline.topology.entrypoints[0]
    return (
        diff_policy(baseline.policy_set, outcome.model.policy_set),
        diff_reachability(baseline, paths),
        diff_risk(baseline, paths, origin),
        paths,
        outcome,
    )


def test_allowing_all_ports_regresses_posture_from_medium_to_high(baseline: Snapshot) -> None:
    """The headline scenario: a blanket permit opens the crown jewel."""
    change = ChangeRequest(
        change_type=ChangeType.ALLOW_FLOW,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        src="10.10.10.0/24",
        dst="10.10.20.50",
        protocol="tcp",
        description="CHG-1042",
    )
    policy_delta, _reach_delta, risk_delta, _, _ = _evaluate(baseline, change)

    assert len(policy_delta.added) == 1
    assert policy_delta.removed == ()
    assert risk_delta.baseline.risk_level is RiskLevel.MEDIUM
    assert risk_delta.projected.risk_level is RiskLevel.HIGH
    assert risk_delta.direction is ChangeDirection.REGRESSED
    assert risk_delta.projected.blast_radius_pct > risk_delta.baseline.blast_radius_pct
    assert risk_delta.projected.crown_jewels_reached == ("database-server",)


def test_regression_opens_the_remote_admin_and_file_sharing_paths(baseline: Snapshot) -> None:
    """The blanket permit exposes SSH, SMB and HTTP on the database server."""
    change = ChangeRequest(
        change_type=ChangeType.ALLOW_FLOW,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        src="10.10.10.0/24",
        dst="10.10.20.50",
        protocol="tcp",
    )
    _, reach_delta, _, _, _ = _evaluate(baseline, change)

    opened = {(path.dst_node, path.flow_name) for path in reach_delta.newly_reachable}
    assert ("database-server", "ssh") in opened
    assert ("database-server", "smb") in opened
    assert ("database-server", "http") in opened


def test_an_opened_path_is_never_a_closed_path(baseline: Snapshot) -> None:
    """Opening paths and closing paths are disjoint by construction."""
    change = ChangeRequest(
        change_type=ChangeType.ALLOW_FLOW,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        src="10.10.10.0/24",
        dst="10.10.20.50",
        protocol="tcp",
    )
    _, reach_delta, _, _, _ = _evaluate(baseline, change)
    opened = {path.key for path in reach_delta.newly_reachable}
    closed = {path.key for path in reach_delta.newly_blocked}
    assert opened.isdisjoint(closed)


def test_exposure_widening_is_reported_for_already_reachable_paths(baseline: Snapshot) -> None:
    """A port-agnostic path that widens to every port is flagged even though it stayed reachable."""
    change = ChangeRequest(
        change_type=ChangeType.ALLOW_FLOW,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        src="10.10.10.0/24",
        dst="10.10.20.50",
        protocol="tcp",
    )
    _, reach_delta, _, _, _ = _evaluate(baseline, change)

    assert reach_delta.exposure_widened
    widened = {path.flow_name for path in reach_delta.exposure_widened}
    assert "any-tcp" in widened
    assert all(path.reachable for path in reach_delta.exposure_widened)


def test_removing_a_permit_hardens_posture(baseline: Snapshot) -> None:
    """Removing the application permit improves the score and closes paths."""
    change = ChangeRequest(
        change_type=ChangeType.REMOVE_POLICY_RULE,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        rule_index=2,
    )
    policy_delta, reach_delta, risk_delta, _, _ = _evaluate(baseline, change)

    assert len(policy_delta.removed) == 1
    assert risk_delta.direction is ChangeDirection.IMPROVED
    assert risk_delta.projected.risk_score < risk_delta.baseline.risk_score
    assert reach_delta.newly_blocked
    assert reach_delta.newly_reachable == ()


def test_deny_flow_closes_an_existing_path(baseline: Snapshot) -> None:
    """An explicit deny inserted at the top of the chain closes the approved flow."""
    change = ChangeRequest(
        change_type=ChangeType.DENY_FLOW,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        src="10.10.10.0/24",
        dst="10.10.20.50",
        protocol="tcp",
        dport=5432,
    )
    _, reach_delta, risk_delta, _, _ = _evaluate(baseline, change)

    assert reach_delta.newly_blocked
    assert risk_delta.projected.blast_radius_pct < risk_delta.baseline.blast_radius_pct


def test_raw_rule_is_inserted_with_iptables_i_semantics(baseline: Snapshot) -> None:
    """A raw rule lands at position 1 and takes precedence over existing policy."""
    change = ChangeRequest(
        change_type=ChangeType.ADD_POLICY_RULE,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        rule="-p tcp --dport 445 -j DROP",
    )
    policy_delta, _, _, _, outcome = _evaluate(baseline, change)

    assert len(policy_delta.added) == 1
    first = outcome.model.policy_set.chain("perimeter-gateway", ChainName.FORWARD).rules[0]
    assert first.dport == 445
    assert first.index == 1


def test_compromise_node_does_not_modify_policy(baseline: Snapshot) -> None:
    """An attacker simulation changes only the analysis origin."""
    change = ChangeRequest(
        change_type=ChangeType.COMPROMISE_NODE,
        target_node="employee-workstation",
    )
    policy_delta, _, risk_delta, _, outcome = _evaluate(baseline, change)

    assert policy_delta.is_empty
    assert outcome.origin_node == "employee-workstation"
    assert risk_delta.projected.risk_score == pytest.approx(risk_delta.baseline.risk_score)


def test_policy_delta_is_empty_when_nothing_changed(baseline: Snapshot) -> None:
    """Comparing a policy set with itself yields a clean delta."""
    delta = diff_policy(baseline.policy_set, baseline.policy_set)

    assert delta.is_empty
    assert delta.added == ()
    assert delta.removed == ()
    assert delta.chain_defaults_changed == {}


def test_host_input_chain_changes_are_supported(baseline: Snapshot) -> None:
    """A change can target a host firewall, not only the gateway."""
    change = ChangeRequest(
        change_type=ChangeType.ADD_POLICY_RULE,
        target_node="database-server",
        chain=ChainName.INPUT,
        rule="-p tcp --dport 5432 -j DROP",
    )
    _, reach_delta, risk_delta, _, _ = _evaluate(baseline, change)

    assert reach_delta.newly_blocked
    assert risk_delta.direction is ChangeDirection.IMPROVED


def test_summary_is_decision_ready(baseline: Snapshot) -> None:
    """The generated summary names the verdict, the scores and the crown jewels."""
    change = ChangeRequest(
        change_type=ChangeType.ALLOW_FLOW,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        src="10.10.10.0/24",
        dst="10.10.20.50",
        protocol="tcp",
    )
    policy_delta, reach_delta, risk_delta, _, _ = _evaluate(baseline, change)
    summary = build_summary(change, policy_delta, reach_delta, risk_delta)

    assert "REGRESSION" in summary
    assert "blast radius" in summary
    assert "database-server" in summary


def test_unknown_target_node_is_rejected(baseline: Snapshot) -> None:
    """A change aimed at a non-existent node is rejected with context."""
    change = ChangeRequest(
        change_type=ChangeType.COMPROMISE_NODE,
        target_node="ghost-node",
    )
    with pytest.raises(ChangeValidationError) as excinfo:
        apply_change(TwinModel(topology=baseline.topology, policy_set=baseline.policy_set), change)
    assert "ghost-node" in excinfo.value.detail


def test_removing_a_missing_rule_is_rejected(baseline: Snapshot) -> None:
    """Removing a rule that does not exist is rejected rather than ignored."""
    change = ChangeRequest(
        change_type=ChangeType.REMOVE_POLICY_RULE,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        rule_index=99,
    )
    with pytest.raises(ChangeValidationError):
        apply_change(TwinModel(topology=baseline.topology, policy_set=baseline.policy_set), change)


def test_severing_an_absent_link_is_rejected(baseline: Snapshot) -> None:
    """Toggling a link that does not exist is rejected."""
    change = ChangeRequest(
        change_type=ChangeType.SET_LINK_STATE,
        target_node="employee-workstation",
        neighbour="database-server",
        enabled=False,
    )
    with pytest.raises(ChangeValidationError):
        apply_change(TwinModel(topology=baseline.topology, policy_set=baseline.policy_set), change)


def test_invalid_raw_rule_surfaces_a_parse_error(baseline: Snapshot) -> None:
    """A malformed raw rule fails loudly instead of being silently dropped."""
    change = ChangeRequest(
        change_type=ChangeType.ADD_POLICY_RULE,
        target_node="perimeter-gateway",
        chain=ChainName.FORWARD,
        rule="-p tcp --dport 99999 -j ACCEPT",
    )
    with pytest.raises(PolicyParseError):
        apply_change(TwinModel(topology=baseline.topology, policy_set=baseline.policy_set), change)


def test_change_request_requires_the_fields_for_its_type() -> None:
    """Per-change-type required fields are enforced at the model boundary."""
    with pytest.raises(ValueError):
        ChangeRequest(change_type=ChangeType.ALLOW_FLOW, target_node="perimeter-gateway")
    with pytest.raises(ValueError):
        ChangeRequest(change_type=ChangeType.SET_LINK_STATE, target_node="perimeter-gateway")
