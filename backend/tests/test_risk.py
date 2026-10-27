"""Tests for blast-radius and composite risk scoring."""

from __future__ import annotations

import pytest

from app.core import risk
from app.models.enums import RiskLevel
from app.models.snapshot import Snapshot
from app.models.topology import FlowSpec


def test_baseline_posture_is_medium_with_a_known_blast_radius(baseline: Snapshot) -> None:
    """The reference topology lands in the MEDIUM band with a 29.2% blast radius.

    This is the anchor the README quotes, so it is asserted explicitly.
    """
    assessment = risk.assess(baseline, "employee-workstation")

    assert assessment.risk_level is RiskLevel.MEDIUM
    assert 30.0 <= assessment.risk_score < 70.0
    assert assessment.blast_radius_pct == pytest.approx(29.17, abs=0.1)
    assert assessment.crown_jewels_reached == ("database-server",)


def test_crown_jewel_exposure_drives_the_score(baseline: Snapshot) -> None:
    """The database is the crown jewel reachable from the user zone."""
    assessment = risk.assess(baseline, "employee-workstation")
    assert "database-server" in assessment.exposure_by_node
    # Reachable on a single application port, not on every port.
    assert assessment.exposure_by_node["database-server"] == pytest.approx(0.5, abs=0.01)


def test_zone_penetration_is_reported(baseline: Snapshot) -> None:
    """Both the infrastructure and data zones are reported as penetrated."""
    assessment = risk.assess(baseline, "employee-workstation")
    assert set(assessment.zones_penetrated) == {"perimeter", "data"}


def test_findings_are_generated_for_the_operator(baseline: Snapshot) -> None:
    """Every assessment carries at least one human-readable finding."""
    assessment = risk.assess(baseline, "employee-workstation")
    assert assessment.findings
    assert any("database-server" in finding for finding in assessment.findings)


def test_port_sensitivity_ranks_remote_admin_above_application_ports() -> None:
    """Remote-control and file-sharing ports outweigh an application data port."""
    assert risk.port_sensitivity(22) > risk.port_sensitivity(5432)
    assert risk.port_sensitivity(445) > risk.port_sensitivity(80)
    assert risk.port_sensitivity(None) == risk.ANY_PORT_SENSITIVITY
    assert risk.port_sensitivity(22, protocol="icmp") == risk.ICMP_SENSITIVITY


def test_unknown_port_uses_the_default_sensitivity() -> None:
    """An unmapped port falls back to a documented default weight."""
    assert risk.port_sensitivity(9999) == risk.DEFAULT_PORT_SENSITIVITY


def test_bucketing_respects_the_published_thresholds() -> None:
    """Risk buckets are derived from the documented thresholds."""
    assert risk.bucket(0.0) is RiskLevel.LOW
    assert risk.bucket(risk.MEDIUM_RISK_THRESHOLD) is RiskLevel.MEDIUM
    assert risk.bucket(risk.HIGH_RISK_THRESHOLD) is RiskLevel.HIGH
    assert risk.bucket(100.0) is RiskLevel.HIGH


def test_flow_filter_restricts_the_assessment(baseline: Snapshot) -> None:
    """Restricting to a flow changes the outcome, proving the filter is applied."""
    full = risk.assess(baseline, "employee-workstation")
    icmp_only = risk.assess(baseline, "employee-workstation", flows=("icmp",))

    assert icmp_only.risk_score < full.risk_score
    assert icmp_only.crown_jewels_reached == ()


def test_aggregate_uses_the_worst_case_across_origins(baseline: Snapshot) -> None:
    """Aggregation returns the worst origin score and the union radius."""
    worst, level, union = risk.aggregate(
        baseline, ("employee-workstation", "perimeter-gateway")
    )
    workstation_only = risk.assess(baseline, "employee-workstation")

    assert worst >= workstation_only.risk_score
    assert level in {RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH}
    assert union > 0.0


def test_unknown_origin_raises(baseline: Snapshot) -> None:
    """An unknown origin is a programming error, not a silent zero."""
    with pytest.raises(KeyError):
        risk.assess(baseline, "no-such-node")


def test_compromise_origin_with_only_icmp_reaches_nothing_crown_jewel(baseline: Snapshot) -> None:
    """A flow spec filter that excludes application traffic yields no crown jewels."""
    assessment = risk.assess(baseline, "employee-workstation", flows=("smb",))
    assert assessment.reachable_nodes == ()


def test_flow_spec_holds_protocol_and_port() -> None:
    """Flow specs validate their port range."""
    with pytest.raises(ValueError):
        FlowSpec(name="bad", protocol="tcp", dport=70000)
