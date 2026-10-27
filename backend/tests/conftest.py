"""Shared fixtures for the backend test suite.

Includes :class:`StubRuntimeGateway`, a deterministic replacement for the Docker
and Containerlab CLIs. Two variants are used:

* an *offline* gateway (no Docker daemon) proving the platform degrades to
  model-only mode instead of failing;
* a *live* gateway with canned `docker exec` output, proving the live-capture
  code path is exercised even on a machine with no lab deployed.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

# Redirect all state to a throwaway directory *before* app.config is imported, so
# the suite never writes into the repository's .twin-state directory.
_TEST_STATE_DIR: Path = Path(tempfile.mkdtemp(prefix="twin-test-state-"))
os.environ.setdefault("TWIN_STATE_DIR", str(_TEST_STATE_DIR))

from app.config import Settings  # noqa: E402
from app.core.snapshot import build_snapshot  # noqa: E402
from app.core.topology_loader import TwinModel, load_twin_model  # noqa: E402
from app.models.snapshot import Snapshot  # noqa: E402
from app.services.runtime import CommandResult, RuntimeGateway  # noqa: E402
from app.services.twin_service import TwinService  # noqa: E402


class StubRuntimeGateway(RuntimeGateway):
    """Deterministic runtime gateway used in place of the real CLIs.

    The stub fakes at the *process boundary* (:meth:`_run`) rather than replacing
    the high-level methods, so the real node validation, container-state checks
    and capture logic in :class:`RuntimeGateway` are exercised by the tests.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        docker_available: bool = False,
        containerlab_available: bool = False,
        containers: dict[str, bool] | None = None,
        command_outputs: dict[tuple[str, ...], tuple[int, str, str]] | None = None,
        lab_name: str = "corporate-twin",
    ) -> None:
        """Configure the stub's observable behaviour.

        Args:
            settings: Settings the gateway would use.
            docker_available: Value returned by :meth:`docker_available`.
            containerlab_available: Value returned by :meth:`containerlab_available`.
            containers: ``node_name -> running`` map returned by
                :meth:`list_lab_containers`.
            command_outputs: ``container command argv -> (exit_code, stdout, stderr)``
                map consulted for ``docker exec`` calls.
            lab_name: Lab name used to map container names back to nodes.
        """
        super().__init__(settings)
        self._docker = docker_available
        self._clab = containerlab_available
        self._containers = dict(containers or {})
        self._outputs = dict(command_outputs or {})
        self._lab_name = lab_name

    def _node_for_container(self, container_name: str) -> str | None:
        """Map a ``clab-<lab>-<node>`` container name back to a node."""
        prefix = f"clab-{self._lab_name}-"
        if not container_name.startswith(prefix):
            return None
        node = container_name[len(prefix) :]
        return node if node in self._containers else None

    async def docker_available(self, refresh: bool = False) -> bool:
        """Return the configured Docker availability."""
        return self._docker

    async def containerlab_available(self) -> bool:
        """Return the configured containerlab availability."""
        return self._clab

    async def list_lab_containers(self, lab_name: str) -> dict[str, bool]:
        """Return the configured container map."""
        return dict(self._containers)

    async def _run(
        self, argv: list[str], timeout: float | None = None
    ) -> CommandResult:
        """Fake ``docker inspect`` and ``docker exec`` at the process boundary."""
        if len(argv) >= 2 and argv[1] == "inspect":
            container_name = argv[-1]
            node = self._node_for_container(container_name)
            if node is None:
                return CommandResult(
                    argv=tuple(argv),
                    return_code=1,
                    stdout="",
                    stderr=f"Error: No such container: {container_name}",
                    duration_seconds=0.0,
                )
            running = self._containers.get(node, False)
            return CommandResult(
                argv=tuple(argv),
                return_code=0,
                stdout="true" if running else "false",
                stderr="",
                duration_seconds=0.0,
            )

        if len(argv) >= 3 and argv[1] == "exec":
            container_name = argv[2]
            node = self._node_for_container(container_name)
            if node is None:
                return CommandResult(
                    argv=tuple(argv),
                    return_code=1,
                    stdout="",
                    stderr=f"Error: No such container: {container_name}",
                    duration_seconds=0.0,
                )
            if not self._containers.get(node, False):
                return CommandResult(
                    argv=tuple(argv),
                    return_code=1,
                    stdout="",
                    stderr=f"Error response from daemon: container {container_name} is not running",
                    duration_seconds=0.0,
                )
            exit_code, stdout, stderr = self._outputs.get(tuple(argv[3:]), (0, "", ""))
            return CommandResult(
                argv=tuple(argv),
                return_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=0.0,
            )

        return await super()._run(argv, timeout)


@pytest.fixture(scope="session")
def settings() -> Settings:
    """Repository settings resolved from the environment."""
    return Settings.from_env()


@pytest.fixture()
def isolated_settings(settings: Settings, tmp_path: Path) -> Settings:
    """Settings whose mutable state is scoped to a per-test temp directory."""
    cfg = replace(settings, state_dir=tmp_path / "state")
    cfg.ensure_directories()
    return cfg


@pytest.fixture(scope="session")
def model(settings: Settings) -> TwinModel:
    """The validated baseline model loaded from the repository configuration."""
    return load_twin_model(settings)


@pytest.fixture()
def baseline(model: TwinModel) -> Snapshot:
    """A freshly solved baseline snapshot."""
    return build_snapshot(model)


@pytest.fixture()
def offline_gateway(isolated_settings: Settings) -> StubRuntimeGateway:
    """A gateway reporting no Docker daemon and no containerlab."""
    return StubRuntimeGateway(isolated_settings)


@pytest.fixture()
def live_gateway(isolated_settings: Settings, model: TwinModel) -> StubRuntimeGateway:
    """A gateway reporting a fully deployed lab with canned exec output."""
    containers = {name: True for name in model.topology.nodes}
    outputs: dict[tuple[str, ...], tuple[int, str, str]] = {
        ("ip", "-br", "addr", "show"): (0, "eth1@if12 UP 10.10.10.10/24\n", ""),
        ("ip", "route", "show"): (0, "default via 10.10.10.1 dev eth1\n", ""),
        ("iptables", "-S"): (
            0,
            "-P INPUT DROP\n-A INPUT -p icmp -j ACCEPT\n",
            "",
        ),
    }
    return StubRuntimeGateway(
        isolated_settings,
        docker_available=True,
        containerlab_available=True,
        containers=containers,
        command_outputs=outputs,
    )


@pytest.fixture()
def service(isolated_settings: Settings, offline_gateway: StubRuntimeGateway) -> TwinService:
    """A twin service wired to the offline gateway with isolated state."""
    return TwinService(isolated_settings, offline_gateway)


@pytest.fixture()
def live_service(isolated_settings: Settings, live_gateway: StubRuntimeGateway) -> TwinService:
    """A twin service wired to a fully deployed stub lab."""
    return TwinService(isolated_settings, live_gateway)


@pytest.fixture()
def api_client(service: TwinService) -> Any:
    """A TestClient whose service dependency is the isolated test service."""
    from fastapi.testclient import TestClient

    from app.api.deps import provide_twin_service
    from app.main import create_app

    application = create_app()
    application.dependency_overrides[provide_twin_service] = lambda: service
    # Not used as a context manager: lifespan is deliberately skipped so the
    # process-wide singleton is never replaced by the test instance.
    return TestClient(application)
