"""Runtime gateway for Docker and Containerlab.

All interaction with the container runtime is funnelled through this class so
the rest of the platform can treat "containers are not running" as an ordinary,
recoverable condition rather than an exception to handle ad hoc.

Design notes:
    * Commands are executed with an explicit timeout; every timeout and non-zero
      exit is converted into a typed :class:`~app.core.exceptions.TwinError`.
    * Every public method degrades instead of raising when the runtime is merely
      unavailable (no daemon, no CLI), because a digital twin must still be able
      to answer "what would happen if" while the lab is torn down.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import Settings
from ..core.exceptions import CommandExecutionError, RuntimeUnavailableError
from ..models.enums import RuntimeMode
from ..models.simulation import LabLifecycleResponse, RuntimeStatus
from ..models.snapshot import NodeRuntimeState
from ..models.topology import Topology

#: Containerlab labels every container it creates with the lab name.
_LAB_LABEL_PREFIX = "containerlab="


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Outcome of a single external command invocation."""

    argv: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """Whether the command completed successfully."""
        return self.return_code == 0 and not self.timed_out

    @property
    def stdout_tail(self) -> str:
        """Last 2000 characters of stdout, for operator-facing diagnostics."""
        return self.stdout[-2000:]

    @property
    def stderr_tail(self) -> str:
        """Last 2000 characters of stderr, for operator-facing diagnostics."""
        return self.stderr[-2000:]


class RuntimeGateway:
    """Async wrapper around the ``docker`` and ``containerlab`` CLIs."""

    def __init__(self, settings: Settings) -> None:
        """Bind the gateway to its settings.

        Args:
            settings: Process settings, including binary names and timeouts.
        """
        self._settings = settings
        self._docker_available: bool | None = None

    # -- Low-level execution -------------------------------------------------

    async def _run(self, argv: list[str], timeout: float | None = None) -> CommandResult:
        """Execute a command, capturing output and enforcing a timeout.

        Args:
            argv: Full argv list (no shell interpolation).
            timeout: Override for the configured command timeout.

        Returns:
            A :class:`CommandResult`; timeouts are reported, not raised, so
            callers can decide whether they are fatal.

        Raises:
            RuntimeUnavailableError: If the executable is not installed.
        """
        executable = argv[0]
        if shutil.which(executable) is None:
            raise RuntimeUnavailableError(
                f"Executable {executable!r} was not found on PATH.",
                executable=executable,
            )

        effective_timeout = timeout if timeout is not None else self._settings.command_timeout_seconds
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(process.communicate(), timeout=effective_timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            return CommandResult(
                argv=tuple(argv),
                return_code=-1,
                stdout="",
                stderr=f"Command timed out after {effective_timeout:.0f}s.",
                duration_seconds=time.monotonic() - started,
                timed_out=True,
            )

        return CommandResult(
            argv=tuple(argv),
            return_code=process.returncode or 0,
            stdout=stdout_b.decode("utf-8", errors="replace"),
            stderr=stderr_b.decode("utf-8", errors="replace"),
            duration_seconds=time.monotonic() - started,
        )

    # -- Availability --------------------------------------------------------

    async def docker_available(self, refresh: bool = False) -> bool:
        """Whether the Docker daemon currently responds.

        Args:
            refresh: Force a re-probe instead of using the cached result.

        Returns:
            ``True`` when ``docker info`` succeeds within the timeout.
        """
        if self._docker_available is not None and not refresh:
            return self._docker_available
        try:
            result = await self._run([self._settings.docker_bin, "info"], timeout=10.0)
            self._docker_available = result.ok
        except RuntimeUnavailableError:
            self._docker_available = False
        return self._docker_available

    async def containerlab_available(self) -> bool:
        """Whether the containerlab CLI is installed."""
        return shutil.which(self._settings.containerlab_bin) is not None

    async def list_lab_containers(self, lab_name: str) -> dict[str, bool]:
        """Map logical node names to running state for a lab.

        Args:
            lab_name: Containerlab lab name (the topology's ``name:`` field).

        Returns:
            ``{node_name: running}``. Returns an empty mapping when the runtime
            is unavailable, so callers can fall back to model-only mode.
        """
        if not await self.docker_available():
            return {}

        result = await self._run(
            [
                self._settings.docker_bin,
                "ps",
                "-a",
                "--filter",
                f"label={_LAB_LABEL_PREFIX}{lab_name}",
                "--format",
                "{{.Names}}\t{{.State}}",
            ]
        )
        if not result.ok:
            return {}

        prefix = f"clab-{lab_name}-"
        containers: dict[str, bool] = {}
        for line in result.stdout.splitlines():
            if "\t" not in line:
                continue
            container_name, _, state = line.partition("\t")
            container_name = container_name.strip()
            if not container_name.startswith(prefix):
                continue
            node_name = container_name[len(prefix) :]
            containers[node_name] = state.strip().lower() == "running"
        return containers

    async def status(self, topology: Topology) -> RuntimeStatus:
        """Probe overall runtime availability for a topology.

        Args:
            topology: Topology whose nodes should be checked.

        Returns:
            A :class:`RuntimeStatus`; never raises for a missing runtime.
        """
        docker_ok = await self.docker_available()
        clab_ok = await self.containerlab_available()

        if not docker_ok:
            return RuntimeStatus(
                docker_available=False,
                containerlab_available=clab_ok,
                lab_deployed=False,
                running_nodes=(),
                missing_nodes=tuple(topology.nodes),
                runtime_mode=RuntimeMode.MODEL,
                detail=(
                    "Docker daemon is not reachable; the platform is running in model-only "
                    "mode. Snapshots and simulations are resolved from config/model.yaml."
                ),
            )

        containers = await self.list_lab_containers(topology.lab_name)
        running = tuple(sorted(name for name, is_up in containers.items() if is_up))
        missing = tuple(sorted(name for name in topology.nodes if not containers.get(name)))
        lab_deployed = bool(running) and not missing

        # Only a fully deployed lab counts as live. A partially running lab would
        # otherwise let a snapshot claim live capture while two thirds of the
        # estate was never observed, which would be actively misleading.
        if not containers:
            detail = (
                f"Lab '{topology.lab_name}' is not deployed. Run "
                "'containerlab deploy -t corporate-twin.yml' for live capture."
            )
        elif not lab_deployed:
            detail = (
                f"Lab partially up: {len(running)}/{len(topology.nodes)} nodes running. "
                "Snapshots fall back to model mode until every node is up."
            )
        else:
            detail = f"Lab '{topology.lab_name}' fully deployed; live capture available."

        return RuntimeStatus(
            docker_available=True,
            containerlab_available=clab_ok,
            lab_deployed=lab_deployed,
            running_nodes=running,
            missing_nodes=missing,
            runtime_mode=RuntimeMode.LIVE if lab_deployed else RuntimeMode.MODEL,
            detail=detail,
        )

    # -- Container interaction ----------------------------------------------

    async def exec_in_node(
        self, topology: Topology, node: str, command: list[str], timeout: float | None = None
    ) -> CommandResult:
        """Execute a command inside a lab container.

        Args:
            topology: Topology supplying container names.
            node: Logical node name.
            command: Command argv to run inside the container.
            timeout: Optional timeout override.

        Returns:
            The :class:`CommandResult`.

        Raises:
            RuntimeUnavailableError: If Docker is not reachable.
            CommandExecutionError: If the node is not a known node, or the
                container is not running.
        """
        if node not in topology.nodes:
            raise CommandExecutionError(
                f"Unknown node {node!r}.",
                node=node,
                known_nodes=sorted(topology.nodes),
            )
        if not await self.docker_available():
            raise RuntimeUnavailableError(
                "Cannot exec into containers: the Docker daemon is not reachable.",
                node=node,
            )

        container_name = topology.nodes[node].container_name
        staging = await self._run(
            [self._settings.docker_bin, "inspect", "-f", "{{.State.Running}}", container_name]
        )
        if not staging.ok:
            raise CommandExecutionError(
                f"Container {container_name} does not exist.",
                node=node,
                container=container_name,
                exit_code=staging.return_code,
                stderr=staging.stderr_tail,
            )
        if staging.stdout.strip() != "true":
            raise CommandExecutionError(
                f"Container {container_name} is not running.",
                node=node,
                container=container_name,
            )

        return await self._run(
            [self._settings.docker_bin, "exec", container_name, *command], timeout=timeout
        )

    async def capture_node_state(self, topology: Topology, node: str) -> NodeRuntimeState:
        """Capture live state for one node, degrading to an error record.

        Args:
            topology: Topology supplying container names.
            node: Logical node name.

        Returns:
            A :class:`NodeRuntimeState`; capture problems are recorded in
            ``capture_error`` rather than raised, so a partial lab still yields a
            usable snapshot.
        """
        container_name = topology.nodes[node].container_name
        running = False
        interfaces: tuple[str, ...] = ()
        routes: tuple[str, ...] = ()
        policy_rule_count = 0
        capture_error: str | None = None

        try:
            containers = await self.list_lab_containers(topology.lab_name)
            running = containers.get(node, False)
            if not running:
                capture_error = "Container is not running."

            iface_result = await self.exec_in_node(topology, node, ["ip", "-br", "addr", "show"])
            if iface_result.ok:
                interfaces = tuple(line for line in iface_result.stdout.splitlines() if line.strip())
            else:
                capture_error = capture_error or iface_result.stderr_tail

            route_result = await self.exec_in_node(topology, node, ["ip", "route", "show"])
            if route_result.ok:
                routes = tuple(line for line in route_result.stdout.splitlines() if line.strip())

            policy_result = await self.exec_in_node(topology, node, ["iptables", "-S"])
            if policy_result.ok:
                policy_rule_count = sum(
                    1
                    for line in policy_result.stdout.splitlines()
                    if line.strip() and not line.startswith("-P")
                )
        except (RuntimeUnavailableError, CommandExecutionError) as exc:
            capture_error = exc.detail

        return NodeRuntimeState(
            node=node,
            container_name=container_name,
            running=running,
            observed_interfaces=interfaces,
            observed_routes=routes,
            observed_policy_rules=policy_rule_count,
            capture_error=capture_error,
        )

    async def capture_all(self, topology: Topology) -> dict[str, NodeRuntimeState]:
        """Capture runtime state for every node concurrently."""
        results = await asyncio.gather(
            *(self.capture_node_state(topology, name) for name in topology.nodes)
        )
        return {state.node: state for state in results}

    # -- Lab lifecycle -------------------------------------------------------

    async def deploy(self, timeout: float = 300.0) -> LabLifecycleResponse:
        """Deploy the Containerlab topology.

        Args:
            timeout: Deployment timeout in seconds (image pulls can be slow).

        Returns:
            A :class:`LabLifecycleResponse`.

        Raises:
            RuntimeUnavailableError: If the containerlab CLI is not installed.
        """
        return await self._lifecycle("deploy", timeout)

    async def destroy(self, timeout: float = 180.0) -> LabLifecycleResponse:
        """Tear down the Containerlab topology and clean up its resources.

        Args:
            timeout: Teardown timeout in seconds.

        Returns:
            A :class:`LabLifecycleResponse`.

        Raises:
            RuntimeUnavailableError: If the containerlab CLI is not installed.
        """
        return await self._lifecycle("destroy", timeout)

    async def _lifecycle(self, action: str, timeout: float) -> LabLifecycleResponse:
        """Run a containerlab lifecycle command."""
        if not await self.containerlab_available():
            raise RuntimeUnavailableError(
                f"Containerlab CLI {self._settings.containerlab_bin!r} is not installed.",
                binary=self._settings.containerlab_bin,
            )

        argv = [
            self._settings.containerlab_bin,
            action,
            "-t",
            str(self._settings.topology_file),
        ]
        if action == "destroy":
            argv.append("--cleanup")

        result = await self._run(argv, timeout=timeout)
        return LabLifecycleResponse(
            action=action,
            success=result.ok,
            command=result.argv,
            return_code=result.return_code,
            stdout_tail=result.stdout_tail,
            stderr_tail=result.stderr_tail,
            duration_seconds=round(result.duration_seconds, 2),
        )

    async def apply_iptables(
        self, topology: Topology, node: str, rules: list[str], timeout: float = 30.0
    ) -> CommandResult:
        """Replace a node's firewall rules with the supplied rule list.

        Used by rollback to re-push the baseline policy onto live containers.

        Args:
            topology: Topology supplying container names.
            node: Logical node name.
            rules: Rules to install (without a leading ``-A``).
            timeout: Command timeout.

        Returns:
            The final :class:`CommandResult`; the chain is flushed then rebuilt
            rule by rule.

        Raises:
            CommandExecutionError: If a rule fails to install.
        """
        flush = await self.exec_in_node(topology, node, ["iptables", "-F"], timeout=timeout)
        if not flush.ok:
            raise CommandExecutionError(
                f"Failed to flush iptables on {node}.",
                node=node,
                exit_code=flush.return_code,
                stderr=flush.stderr_tail,
            )

        last = flush
        for rulespec in rules:
            last = await self.exec_in_node(
                topology, node, ["iptables", "-A", *rulespec.split()], timeout=timeout
            )
            if not last.ok:
                raise CommandExecutionError(
                    f"Failed to install rule {rulespec!r} on {node}.",
                    node=node,
                    rule=rulespec,
                    exit_code=last.return_code,
                    stderr=last.stderr_tail,
                )
        return last

    def write_generated_scripts(self, scripts: dict[str, str]) -> tuple[Path, ...]:
        """Write rendered bootstrap scripts to the generated directory.

        Args:
            scripts: ``node_name -> shell script body``.

        Returns:
            The paths written.
        """
        self._settings.generated_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for node_name, body in scripts.items():
            target = self._settings.generated_dir / f"{node_name}.sh"
            target.write_text(body, encoding="utf-8")
            target.chmod(0o755)
            written.append(target)
        return tuple(written)


def container_state_json(raw: str) -> dict[str, object]:
    """Parse ``docker inspect`` JSON output defensively.

    Args:
        raw: JSON document emitted by ``docker inspect``.

    Returns:
        The parsed mapping, or an empty mapping when parsing fails.
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


__all__ = ["CommandResult", "RuntimeGateway", "container_state_json"]
