"""End-to-end API tests, exercised through the real ASGI application."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.services.twin_service import TwinService
from tests.conftest import StubRuntimeGateway

API = "/api/v1"


@pytest.fixture()
def live_service_config(live_service: TwinService) -> TestClient:
    """A client wired to the fully deployed stub lab."""
    from app.api.deps import provide_twin_service

    application = create_app()
    application.dependency_overrides[provide_twin_service] = lambda: live_service
    return TestClient(application)


def _error(response: Any) -> dict[str, Any]:
    """Assert the response is an error envelope and return it."""
    body = response.json()
    assert "code" in body and "detail" in body, body
    return body


# ---------------------------------------------------------------------------
# Health and discovery
# ---------------------------------------------------------------------------


def test_root_banner_is_served(api_client: TestClient) -> None:
    """The service banner points at the API and docs."""
    response = api_client.get("/")

    assert response.status_code == 200
    assert response.json()["api"] == API


def test_health_reports_degraded_model_mode_without_docker(api_client: TestClient) -> None:
    """Health stays 200 and clearly reports model-only mode when Docker is down."""
    response = api_client.get(f"{API}/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["runtime_mode"] == "model"
    assert body["docker_available"] is False
    assert body["checks"]["docker_daemon"] is False
    assert body["lab_name"] == "corporate-twin"


def test_topology_is_served_with_zones_and_links(api_client: TestClient) -> None:
    """The topology projection carries nodes, links and zones for the map."""
    response = api_client.get(f"{API}/topology")

    assert response.status_code == 200
    body = response.json()
    assert {node["name"] for node in body["nodes"]} == {
        "perimeter-gateway",
        "employee-workstation",
        "database-server",
    }
    assert len(body["links"]) == 2
    assert {zone["name"] for zone in body["zones"]} == {"perimeter", "corp", "data"}
    assert body["entrypoints"] == ["employee-workstation"]
    assert len(body["probe_flows"]) == 6


def test_policies_list_only_noteworthy_chains(api_client: TestClient) -> None:
    """Chains that are empty and default to ACCEPT are omitted as noise."""
    response = api_client.get(f"{API}/policies")

    assert response.status_code == 200
    chains = {(chain["node"], chain["chain"]) for chain in response.json()}
    assert ("perimeter-gateway", "FORWARD") in chains
    assert ("database-server", "INPUT") in chains
    # Empty default-ACCEPT chains are filtered out.
    assert ("employee-workstation", "OUTPUT") not in chains


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


def test_snapshot_capture_creates_a_baseline(api_client: TestClient) -> None:
    """Capturing a snapshot returns 201 with counts and node state."""
    response = api_client.post(f"{API}/snapshot")

    assert response.status_code == 201
    body = response.json()
    assert body["is_baseline"] is True
    assert body["snapshot"]["runtime_mode"] == "model"
    assert body["snapshot"]["total_pairs"] == 36
    assert body["snapshot"]["reachable_count"] == 10
    assert len(body["node_states"]) == 3
    assert body["snapshot"]["warnings"]


def test_snapshot_is_retrievable_after_capture(api_client: TestClient) -> None:
    """The captured baseline is retrievable and stable."""
    captured = api_client.post(f"{API}/snapshot").json()["snapshot"]["snapshot_id"]
    response = api_client.get(f"{API}/snapshot")

    assert response.status_code == 200
    assert response.json()["snapshot_id"] == captured


def test_snapshot_nodes_are_inspectable(api_client: TestClient) -> None:
    """Per-node state exposes routes, interfaces and chain defaults."""
    api_client.post(f"{API}/snapshot")
    response = api_client.get(f"{API}/snapshot/nodes")

    assert response.status_code == 200
    nodes = {node["node"]: node for node in response.json()}
    gateway = nodes["perimeter-gateway"]
    assert gateway["default_policies"]["FORWARD"] == "DROP"
    assert any(route["protocol"] == "connected" for route in gateway["routes"])
    database = nodes["database-server"]
    assert database["default_policies"]["INPUT"] == "ACCEPT"


def test_missing_baseline_returns_404_envelope(isolated_settings: Settings) -> None:
    """Reading a baseline that was never captured yields a 404 error envelope."""
    service = TwinService(isolated_settings, StubRuntimeGateway(isolated_settings))
    from app.api.deps import provide_twin_service

    application = create_app()
    application.dependency_overrides[provide_twin_service] = lambda: service
    client = TestClient(application)

    response = client.get(f"{API}/snapshot")

    assert response.status_code == 404
    assert _error(response)["code"] == "snapshot_not_found"


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------


def test_simulate_change_reports_deltas_and_risk(api_client: TestClient) -> None:
    """The headline endpoint returns policy, reachability and risk deltas."""
    api_client.post(f"{API}/snapshot")
    response = api_client.post(
        f"{API}/simulate-change",
        json={
            "change_type": "allow_flow",
            "target_node": "perimeter-gateway",
            "chain": "FORWARD",
            "src": "10.10.10.0/24",
            "dst": "10.10.20.50",
            "protocol": "tcp",
            "description": "CHG-1042",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["applied"] is False
    assert len(body["policy_delta"]["added"]) == 1
    assert len(body["reachability_delta"]["newly_reachable"]) == 3
    assert body["reachability_delta"]["exposure_widened"]
    assert body["risk"]["baseline"]["risk_level"] == "medium"
    assert body["risk"]["projected"]["risk_level"] == "high"
    assert body["risk"]["direction"] == "regressed"
    assert "REGRESSION" in body["summary"]
    assert body["applied"] is False


def test_simulate_change_never_mutates_the_baseline(api_client: TestClient) -> None:
    """Simulating a change leaves the baseline snapshot untouched."""
    before = api_client.post(f"{API}/snapshot").json()["snapshot"]["snapshot_id"]
    api_client.post(
        f"{API}/simulate-change",
        json={
            "change_type": "allow_flow",
            "target_node": "perimeter-gateway",
            "src": "10.10.10.0/24",
            "dst": "10.10.20.50",
            "protocol": "tcp",
        },
    )
    after = api_client.get(f"{API}/snapshot").json()["snapshot_id"]

    assert before == after


def test_compromise_node_simulation(api_client: TestClient) -> None:
    """A compromise simulation reports the attacker's reach without changing policy."""
    api_client.post(f"{API}/snapshot")
    response = api_client.post(
        f"{API}/simulate-change",
        json={"change_type": "compromise_node", "target_node": "employee-workstation"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["policy_delta"]["added"] == []
    assert body["risk"]["projected"]["origin_node"] == "employee-workstation"
    assert body["risk"]["projected"]["crown_jewels_reached"] == ["database-server"]


def test_hardening_change_reports_improvement(api_client: TestClient) -> None:
    """Removing a permit reports a hardening verdict."""
    api_client.post(f"{API}/snapshot")
    response = api_client.post(
        f"{API}/simulate-change",
        json={
            "change_type": "remove_policy_rule",
            "target_node": "perimeter-gateway",
            "chain": "FORWARD",
            "rule_index": 2,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["risk"]["direction"] == "improved"
    assert body["reachability_delta"]["newly_blocked"]


def test_simulation_history_is_recorded(api_client: TestClient) -> None:
    """Every evaluation is appended to the queryable history."""
    api_client.post(f"{API}/snapshot")
    api_client.post(
        f"{API}/simulate-change",
        json={"change_type": "compromise_node", "target_node": "employee-workstation"},
    )
    response = api_client.get(f"{API}/simulations")

    assert response.status_code == 200
    history = response.json()
    assert len(history) == 1
    assert history[0]["change_type"] == "compromise_node"


def test_unknown_target_node_is_a_422_envelope(api_client: TestClient) -> None:
    """A change against an unknown node returns the standard error envelope."""
    api_client.post(f"{API}/snapshot")
    response = api_client.post(
        f"{API}/simulate-change",
        json={"change_type": "compromise_node", "target_node": "ghost-node"},
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "change_validation_error"


def test_missing_required_fields_are_a_422_validation_error(api_client: TestClient) -> None:
    """Per-change-type required fields are validated at the boundary."""
    response = api_client.post(
        f"{API}/simulate-change",
        json={"change_type": "allow_flow", "target_node": "perimeter-gateway"},
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "validation_error"


def test_unknown_change_type_is_rejected(api_client: TestClient) -> None:
    """An unrecognised change type is rejected by schema validation."""
    response = api_client.post(
        f"{API}/simulate-change",
        json={"change_type": "delete_universe", "target_node": "perimeter-gateway"},
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "validation_error"


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------


def test_blast_radius_for_configured_entrypoints(api_client: TestClient) -> None:
    """An empty request analyses every configured entry point."""
    api_client.post(f"{API}/snapshot")
    response = api_client.post(f"{API}/analyze-blast-radius", json={})

    assert response.status_code == 200
    body = response.json()
    assert body["assessments"][0]["origin_node"] == "employee-workstation"
    assert body["aggregate_risk_level"] == "medium"
    assert body["blast_radius_pct"] == pytest.approx(29.17, abs=0.1)
    assert body["attack_paths"]


def test_blast_radius_with_a_simulated_change(api_client: TestClient) -> None:
    """A candidate change can be analysed without being committed."""
    api_client.post(f"{API}/snapshot")
    response = api_client.post(
        f"{API}/analyze-blast-radius",
        json={
            "origin_node": "employee-workstation",
            "include_simulated_change": {
                "change_type": "allow_flow",
                "target_node": "perimeter-gateway",
                "src": "10.10.10.0/24",
                "dst": "10.10.20.50",
                "protocol": "tcp",
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["analysed_change"] is not None
    assert body["aggregate_risk_level"] == "high"
    assert body["blast_radius_pct"] > 29.17


def test_blast_radius_agrees_with_simulate_change(api_client: TestClient) -> None:
    """Both endpoints must score the same candidate change identically.

    They answer the same question through different routes, so a divergence would
    be a correctness bug that erodes trust in the numbers.
    """
    change = {
        "change_type": "allow_flow",
        "target_node": "perimeter-gateway",
        "src": "10.10.10.0/24",
        "dst": "10.10.20.50",
        "protocol": "tcp",
    }
    api_client.post(f"{API}/snapshot")
    simulation = api_client.post(f"{API}/simulate-change", json=change).json()
    blast = api_client.post(
        f"{API}/analyze-blast-radius", json={"include_simulated_change": change}
    ).json()

    assert blast["aggregate_risk_score"] == pytest.approx(
        simulation["risk"]["projected"]["risk_score"], abs=0.01
    )
    assert blast["blast_radius_pct"] == pytest.approx(
        simulation["risk"]["projected"]["blast_radius_pct"], abs=0.01
    )
    assert blast["aggregate_risk_level"] == simulation["risk"]["projected"]["risk_level"]


def test_blast_radius_rejects_an_unknown_origin(api_client: TestClient) -> None:
    """An unknown origin is rejected with the standard envelope."""
    api_client.post(f"{API}/snapshot")
    response = api_client.post(
        f"{API}/analyze-blast-radius", json={"origin_node": "ghost-node"}
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "change_validation_error"


def test_blast_radius_rejects_an_unknown_flow(api_client: TestClient) -> None:
    """An unknown probe flow is rejected with the standard envelope."""
    api_client.post(f"{API}/snapshot")
    response = api_client.post(
        f"{API}/analyze-blast-radius", json={"flows": ["not-a-flow"]}
    )

    assert response.status_code == 422
    assert _error(response)["code"] == "change_validation_error"


# ---------------------------------------------------------------------------
# Compliance and rollback
# ---------------------------------------------------------------------------

def test_compliance_report_is_scored(api_client: TestClient) -> None:
    """Compliance returns a score plus per-control findings."""
    api_client.post(f"{API}/snapshot")
    response = api_client.get(f"{API}/compliance")

    assert response.status_code == 200
    body = response.json()
    assert 0.0 <= body["score_pct"] <= 100.0
    assert body["failed"] >= 1
    failing = {f["control_id"] for f in body["findings"] if f["status"] == "fail"}
    assert "CTL-002" in failing
    for finding in body["findings"]:
        assert finding["remediation"]


def test_rollback_restores_the_baseline(api_client: TestClient) -> None:
    """Rollback restores the baseline and explains that nothing was pushed live."""
    api_client.post(f"{API}/snapshot")
    api_client.post(
        f"{API}/simulate-change",
        json={"change_type": "compromise_node", "target_node": "employee-workstation"},
    )
    response = api_client.post(f"{API}/rollback")

    assert response.status_code == 200
    body = response.json()
    assert body["runtime_applied"] is False
    assert any("not modified" in warning for warning in body["warnings"])
    # History is cleared by the rollback.
    assert api_client.get(f"{API}/simulations").json() == []


def test_rollback_without_a_baseline_is_404(isolated_settings: Settings) -> None:
    """Rolling back with no baseline returns a 404 envelope."""
    service = TwinService(isolated_settings, StubRuntimeGateway(isolated_settings))
    from app.api.deps import provide_twin_service

    application = create_app()
    application.dependency_overrides[provide_twin_service] = lambda: service
    client = TestClient(application)

    response = client.post(f"{API}/rollback")

    assert response.status_code == 404
    assert _error(response)["code"] == "snapshot_not_found"


def test_baseline_survives_a_service_restart(isolated_settings: Settings) -> None:
    """The baseline is persisted, so a fresh process can still roll back."""
    from app.api.deps import provide_twin_service

    first = TwinService(isolated_settings, StubRuntimeGateway(isolated_settings))
    application = create_app()
    application.dependency_overrides[provide_twin_service] = lambda: first
    client = TestClient(application)
    captured = client.post(f"{API}/snapshot").json()["snapshot"]["snapshot_id"]

    # Simulate a restart: brand new service instance over the same state dir.
    second = TwinService(isolated_settings, StubRuntimeGateway(isolated_settings))
    application.dependency_overrides[provide_twin_service] = lambda: second
    restored = TestClient(application).get(f"{API}/snapshot")

    assert restored.status_code == 200
    assert restored.json()["snapshot_id"] == captured


def test_lab_endpoints_fail_cleanly_without_containerlab(api_client: TestClient) -> None:
    """Lifecycle endpoints return a 503 envelope when the CLI is absent."""
    response = api_client.post(f"{API}/lab/deploy")

    assert response.status_code == 503
    assert _error(response)["code"] == "runtime_unavailable"


def test_deployed_lab_snapshot_reports_live_mode(live_service_config) -> None:
    """A fully deployed lab produces a snapshot in live mode with no warnings."""
    client = live_service_config
    response = client.post(f"{API}/snapshot")

    assert response.status_code == 201
    body = response.json()
    assert body["snapshot"]["runtime_mode"] == "live"
    assert body["snapshot"]["warnings"] == []
    assert all(state["running"] for state in body["node_states"])


def test_openapi_schema_is_generated(api_client: TestClient) -> None:
    """The OpenAPI document is generated and documents the four primary endpoints."""
    response = api_client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    for path in ("/api/v1/snapshot", "/api/v1/simulate-change", "/api/v1/analyze-blast-radius", "/api/v1/rollback"):
        assert path in paths
