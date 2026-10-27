"""Tests for the runtime gateway: degradation, live capture and timeouts."""

from __future__ import annotations

import pytest

from app.config import Settings
from app.core.exceptions import CommandExecutionError, RuntimeUnavailableError
from app.core.topology_loader import TwinModel
from app.models.enums import RuntimeMode
from app.services.runtime import RuntimeGateway
from tests.conftest import StubRuntimeGateway


async def test_offline_gateway_reports_model_mode(
    offline_gateway: StubRuntimeGateway, model: TwinModel
) -> None:
    """With no Docker daemon the platform reports model mode and lists every node missing."""
    status = await offline_gateway.status(model.topology)

    assert status.docker_available is False
    assert status.lab_deployed is False
    assert status.runtime_mode is RuntimeMode.MODEL
    assert set(status.missing_nodes) == set(model.topology.nodes)
    assert "model-only" in status.detail


async def test_live_gateway_reports_every_node_running(
    live_gateway: StubRuntimeGateway, model: TwinModel
) -> None:
    """A fully deployed lab reports live mode with no missing nodes."""
    status = await live_gateway.status(model.topology)

    assert status.docker_available is True
    assert status.lab_deployed is True
    assert status.runtime_mode is RuntimeMode.LIVE
    assert status.missing_nodes == ()
    assert set(status.running_nodes) == set(model.topology.nodes)


async def test_partially_deployed_lab_is_reported_as_such(
    isolated_settings: Settings, model: TwinModel
) -> None:
    """A partially running lab is not reported as fully deployed."""
    gateway = StubRuntimeGateway(
        isolated_settings,
        docker_available=True,
        containerlab_available=True,
        containers={"perimeter-gateway": True, "employee-workstation": False},
    )
    status = await gateway.status(model.topology)

    assert status.lab_deployed is False
    assert status.runtime_mode is RuntimeMode.MODEL
    assert "partially" in status.detail
    assert status.running_nodes == ("perimeter-gateway",)
    assert "database-server" in status.missing_nodes


async def test_exec_into_a_stopped_container_is_a_typed_error(
    isolated_settings: Settings, model: TwinModel
) -> None:
    """Exec into a container that exists but is not running fails with context."""
    gateway = StubRuntimeGateway(
        isolated_settings,
        docker_available=True,
        containers={"perimeter-gateway": False},
    )
    with pytest.raises(CommandExecutionError) as excinfo:
        await gateway.exec_in_node(model.topology, "perimeter-gateway", ["ip", "route"])

    assert "not running" in excinfo.value.detail


async def test_exec_into_a_container_that_does_not_exist_is_a_typed_error(
    isolated_settings: Settings, model: TwinModel
) -> None:
    """Exec into an absent container fails with the container name in context."""
    gateway = StubRuntimeGateway(isolated_settings, docker_available=True, containers={})
    with pytest.raises(CommandExecutionError) as excinfo:
        await gateway.exec_in_node(model.topology, "perimeter-gateway", ["ip", "route"])

    assert "does not exist" in excinfo.value.detail
    assert excinfo.value.context["container"] == "clab-corporate-twin-perimeter-gateway"


async def test_capture_records_a_failed_command_as_a_capture_error(
    isolated_settings: Settings, model: TwinModel
) -> None:
    """A failing capture command degrades into a recorded error, not an exception."""
    gateway = StubRuntimeGateway(
        isolated_settings,
        docker_available=True,
        containers={"employee-workstation": True},
        command_outputs={("iptables", "-S"): (1, "", "iptables: not found")},
    )
    state = await gateway.capture_node_state(model.topology, "employee-workstation")

    assert state.running is True
    assert state.observed_policy_rules == 0


async def test_live_capture_reads_interfaces_routes_and_policy(
    live_gateway: StubRuntimeGateway, model: TwinModel
) -> None:
    """Live capture collects addressing, routing table and rule counts per node."""
    states = await live_gateway.capture_all(model.topology)

    assert set(states) == set(model.topology.nodes)
    state = states["employee-workstation"]
    assert state.running is True
    assert state.capture_error is None
    assert state.observed_interfaces
    assert state.observed_routes
    # The canned `iptables -S` output has one rule after the -P lines.
    assert state.observed_policy_rules == 1


async def test_exec_into_an_offline_node_is_a_typed_error(
    offline_gateway: StubRuntimeGateway, model: TwinModel
) -> None:
    """Exec against an unavailable runtime raises a recoverable, typed error."""
    with pytest.raises(RuntimeUnavailableError) as excinfo:
        await offline_gateway.exec_in_node(model.topology, "perimeter-gateway", ["ip", "route"])

    assert excinfo.value.code == "runtime_unavailable"
    assert excinfo.value.http_status == 503


async def test_exec_into_an_unknown_node_is_rejected(
    live_gateway: StubRuntimeGateway, model: TwinModel
) -> None:
    """An unknown node name is rejected before any container call is made."""
    with pytest.raises(CommandExecutionError) as excinfo:
        await live_gateway.exec_in_node(model.topology, "ghost", ["true"])

    assert "ghost" in excinfo.value.detail


async def test_command_timeout_is_enforced_not_swallowed(isolated_settings: Settings) -> None:
    """A long-running command is killed and reported as timed out."""
    gateway = RuntimeGateway(isolated_settings)
    result = await gateway._run(["sleep", "5"], timeout=0.2)

    assert result.timed_out is True
    assert result.ok is False
    assert result.return_code == -1
    assert "timed out" in result.stderr


async def test_missing_executable_is_a_typed_error(isolated_settings: Settings) -> None:
    """A missing binary is reported as an unavailable runtime, not a crash."""
    gateway = RuntimeGateway(isolated_settings)
    with pytest.raises(RuntimeUnavailableError):
        await gateway._run(["definitely-not-a-real-binary-xyz"], timeout=1.0)


async def test_deploy_without_containerlab_is_a_typed_error(
    offline_gateway: StubRuntimeGateway,
) -> None:
    """Deploying without the containerlab CLI fails cleanly with remediation context."""
    with pytest.raises(RuntimeUnavailableError) as excinfo:
        await offline_gateway.deploy()

    assert "containerlab" in excinfo.value.detail
