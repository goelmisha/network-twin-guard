"""Tests for the routing-aware reachability solver against the real topology."""

from __future__ import annotations

from app.core.change import apply_change
from app.core.reachability import ReachabilitySolver
from app.core.topology_loader import TwinModel
from app.models.simulation import ChangeRequest
from app.models.snapshot import Snapshot


def _path(baseline: Snapshot, src: str, dst: str, flow: str):
    """Fetch a solved path, asserting it exists."""
    found = baseline.path_index().get((src, dst, flow))
    assert found is not None, f"missing path {src}->{dst}:{flow}"
    return found


def test_matrix_covers_every_ordered_pair_and_flow(baseline: Snapshot) -> None:
    """The solver evaluates every node pair for every declared probe flow."""
    nodes = len(baseline.topology.nodes)
    flows = len(baseline.topology.probe_flows)
    assert baseline.total_pairs() == nodes * (nodes - 1) * flows


def test_permitted_application_flow_is_reachable_across_two_hops(baseline: Snapshot) -> None:
    """The approved application flow traverses the gateway and lands on the DB."""
    path = _path(baseline, "employee-workstation", "database-server", "postgres")
    assert path.reachable is True
    assert path.hops == 2
    assert path.path == ("employee-workstation", "perimeter-gateway", "database-server")
    assert path.reachable_ports == ((5432, 5432),)


def test_unapproved_service_is_blocked_at_the_transit_router(baseline: Snapshot) -> None:
    """SSH to the database is denied by the gateway's explicit reject rule."""
    path = _path(baseline, "employee-workstation", "database-server", "ssh")
    assert path.reachable is False
    assert path.blocked_at == "perimeter-gateway"
    assert path.blocked_by is not None
    assert "rule #3" in path.blocked_by


def test_unknown_service_is_blocked_by_the_forward_default_deny(baseline: Snapshot) -> None:
    """A service with no permit never leaves the gateway."""
    path = _path(baseline, "employee-workstation", "database-server", "smb")
    assert path.reachable is False
    assert path.blocked_at == "perimeter-gateway"
    assert "default policy" in (path.blocked_by or "")


def test_management_plane_is_closed_to_the_user_zone(baseline: Snapshot) -> None:
    """The gateway's SSH listener is scoped to the out-of-band subnet."""
    path = _path(baseline, "employee-workstation", "perimeter-gateway", "ssh")
    assert path.reachable is False
    assert path.blocked_at == "perimeter-gateway"


def test_icmp_health_probe_is_permitted(baseline: Snapshot) -> None:
    """The explicit ICMP permit from the user zone is honoured."""
    path = _path(baseline, "employee-workstation", "perimeter-gateway", "icmp")
    assert path.reachable is True
    assert path.hops == 1


def test_port_agnostic_flow_reports_the_intersected_port_set(baseline: Snapshot) -> None:
    """An any-port probe resolves to the single port every hop agrees on."""
    path = _path(baseline, "employee-workstation", "database-server", "any-tcp")
    assert path.reachable is True
    assert path.reachable_ports == ((5432, 5432),)


def test_connected_subnets_are_reachable_without_traversing_a_router(baseline: Snapshot) -> None:
    """The gateway reaches the database directly on its attached subnet."""
    path = _path(baseline, "perimeter-gateway", "database-server", "postgres")
    assert path.reachable is True
    assert path.hops == 1


def test_return_direction_is_blocked_by_the_asymmetric_policy(baseline: Snapshot) -> None:
    """The database cannot initiate toward the user zone."""
    path = _path(baseline, "database-server", "employee-workstation", "any-tcp")
    assert path.reachable is False


def test_severing_a_link_removes_both_the_route_and_the_path(
    model: TwinModel, baseline: Snapshot
) -> None:
    """A link-state change removes connected routes and invalidates reachability."""
    change = ChangeRequest(
        change_type="set_link_state",
        target_node="perimeter-gateway",
        neighbour="database-server",
        enabled=False,
    )
    outcome = apply_change(TwinModel(topology=baseline.topology, policy_set=baseline.policy_set), change)
    projected = ReachabilitySolver(outcome.model.topology, outcome.model.policy_set).solve_matrix()
    index = {p.key: p for p in projected}

    assert index[("employee-workstation", "database-server", "postgres")].reachable is False
    assert index[("perimeter-gateway", "database-server", "postgres")].reachable is False
    # The user zone remains reachable because its own link is untouched.
    assert index[("employee-workstation", "perimeter-gateway", "icmp")].reachable is True


def test_restoring_a_link_restores_reachability(baseline: Snapshot) -> None:
    """Bringing the link back up restores the original path."""
    down = ChangeRequest(
        change_type="set_link_state",
        target_node="perimeter-gateway",
        neighbour="database-server",
        enabled=False,
    )
    after_down = apply_change(
        TwinModel(topology=baseline.topology, policy_set=baseline.policy_set), down
    )
    restore = ChangeRequest(
        change_type="set_link_state",
        target_node="perimeter-gateway",
        neighbour="database-server",
        enabled=True,
    )
    after_up = apply_change(after_down.model, restore)
    projected = ReachabilitySolver(after_up.model.topology, after_up.model.policy_set).solve_matrix()
    index = {p.key: p for p in projected}

    assert index[("employee-workstation", "database-server", "postgres")].reachable is True


def test_solver_does_not_mutate_the_baseline(model: TwinModel, baseline: Snapshot) -> None:
    """Solving a projected state leaves the baseline snapshot untouched."""
    before_checksum = baseline.checksum()
    change = ChangeRequest(
        change_type="compromise_node",
        target_node="employee-workstation",
    )
    apply_change(TwinModel(topology=baseline.topology, policy_set=baseline.policy_set), change)
    assert baseline.checksum() == before_checksum
