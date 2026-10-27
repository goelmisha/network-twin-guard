"""Twin orchestration service.

This is the single entry point the API layer talks to. It owns:

* model loading and caching;
* baseline snapshot capture and persistence (so rollback survives a restart);
* what-if evaluation (change application + differential + risk);
* blast-radius analysis;
* rollback to the captured baseline;
* optional live runtime interaction through :class:`RuntimeGateway`.

Every runtime interaction degrades gracefully: if Docker is down the service
continues in *model mode* and records a warning on the resulting artefact rather
than failing the request.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from ..config import Settings, get_settings
from ..core import risk as risk_module
from ..core.change import ChangeOutcome, apply_change
from ..core.compliance import evaluate_compliance
from ..core.diff import build_summary, diff_policy, diff_reachability, diff_risk
from ..core.exceptions import (
    ChangeValidationError,
    CommandExecutionError,
    RuntimeUnavailableError,
    SnapshotNotFoundError,
)
from ..core.reachability import ReachabilitySolver
from ..core.snapshot import build_snapshot, node_state_summaries, summarise
from ..core.topology_loader import TwinModel, load_twin_model
from ..models.enums import ChainName, InterfaceState, RuleAction, RuntimeMode
from ..models.simulation import (
    BlastRadiusRequest,
    BlastRadiusResponse,
    ChangeRequest,
    ComplianceReport,
    LabLifecycleResponse,
    RiskAssessment,
    RiskDelta,
    RollbackResponse,
    RuntimeStatus,
    SimulationResult,
    SnapshotResponse,
)
from ..models.snapshot import NodeRuntimeState, ReachabilityPath, Snapshot, SnapshotSummary
from ..models.views import (
    ChainView,
    HealthView,
    InterfaceView,
    LinkView,
    NodeView,
    SimulationHistoryEntry,
    TopologyView,
    ZoneView,
)
from .runtime import RuntimeGateway

#: Maximum number of simulation records retained on disk.
MAX_HISTORY: int = 50


class TwinService:
    """Application service coordinating the digital twin."""

    def __init__(
        self,
        settings: Settings | None = None,
        gateway: RuntimeGateway | None = None,
    ) -> None:
        """Initialise the service.

        Args:
            settings: Optional settings override.
            gateway: Optional runtime gateway override (used by tests).
        """
        self._settings = settings or get_settings()
        self._settings.ensure_directories()
        self._gateway = gateway or RuntimeGateway(self._settings)
        self._model_cache: TwinModel | None = None
        self._baseline: Snapshot | None = None
        self._history: list[SimulationHistoryEntry] = []
        self._applied_simulations: list[str] = []
        self._lock = asyncio.Lock()
        self._load_history()

    # -- Properties ----------------------------------------------------------

    @property
    def settings(self) -> Settings:
        """Active settings."""
        return self._settings

    @property
    def gateway(self) -> RuntimeGateway:
        """Runtime gateway used for live interaction."""
        return self._gateway

    # -- Model loading -------------------------------------------------------

    def load_model(self, force: bool = False) -> TwinModel:
        """Load and cache the validated twin model.

        Args:
            force: Reload from disk even if a cached model exists.

        Returns:
            The validated :class:`TwinModel`.

        Raises:
            TopologyModelError: If the topology or model file is invalid.
        """
        if self._model_cache is None or force:
            self._model_cache = load_twin_model(self._settings)
        return self._model_cache

    @property
    def model(self) -> TwinModel:
        """The cached model, loading it on first access."""
        return self.load_model()

    # -- Persistence helpers -------------------------------------------------

    @property
    def _history_path(self) -> Path:
        """Path to the persisted simulation history."""
        return self._settings.state_dir / "simulations.json"

    def _save_baseline(self, snapshot: Snapshot) -> None:
        """Persist a baseline snapshot to disk."""
        self._settings.baseline_path.write_text(
            snapshot.model_dump_json(indent=2), encoding="utf-8"
        )

    def _load_persisted_baseline(self) -> Snapshot | None:
        """Load the persisted baseline, returning ``None`` when unusable."""
        path = self._settings.baseline_path
        if not path.exists():
            return None
        try:
            snapshot = Snapshot.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if snapshot.lab_name != self.model.topology.lab_name:
            return None
        return snapshot

    def _load_history(self) -> None:
        """Load the persisted simulation history, ignoring corrupt state."""
        path = self._history_path
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            self._history = [SimulationHistoryEntry.model_validate(item) for item in raw]
        except Exception:
            self._history = []

    def _save_history(self) -> None:
        """Persist the simulation history, trimmed to :data:`MAX_HISTORY`."""
        trimmed = self._history[-MAX_HISTORY:]
        self._history_path.write_text(
            json.dumps([entry.model_dump(mode="json") for entry in trimmed], indent=2),
            encoding="utf-8",
        )

    # -- Runtime status ------------------------------------------------------

    async def runtime_status(self) -> RuntimeStatus:
        """Probe the container runtime for the current topology.

        Returns:
            A :class:`RuntimeStatus`. A missing Docker daemon is reported as
            model mode rather than raised, so the API stays usable with the lab
            torn down.
        """
        try:
            return await self._gateway.status(self.model.topology)
        except RuntimeUnavailableError as exc:
            return RuntimeStatus(
                docker_available=False,
                containerlab_available=False,
                lab_deployed=False,
                running_nodes=(),
                missing_nodes=tuple(self.model.topology.nodes),
                runtime_mode=RuntimeMode.MODEL,
                detail=exc.detail,
            )

    # -- Snapshots -----------------------------------------------------------

    async def capture_snapshot(self, capture_live: bool = True) -> Snapshot:
        """Capture a fresh snapshot of the twin.

        Args:
            capture_live: Attempt live container capture when a runtime is up.

        Returns:
            The captured :class:`Snapshot`. In model mode it carries warnings
            explaining why live state was unavailable.
        """
        model = self.model
        warnings: list[str] = []
        node_states: dict[str, NodeRuntimeState] = {}
        runtime_available = False

        if capture_live:
            try:
                status = await self._gateway.status(model.topology)
                # A snapshot only claims live mode when every node was observed.
                runtime_available = status.docker_available and status.lab_deployed
                if status.docker_available and status.running_nodes:
                    node_states = await self._gateway.capture_all(model.topology)
                if not runtime_available:
                    warnings.append(status.detail)
            except RuntimeUnavailableError as exc:
                warnings.append(
                    f"{exc.detail} Falling back to model-only capture."
                )
        else:
            warnings.append("Live capture disabled by request; model-only snapshot.")

        return build_snapshot(
            model,
            runtime_available=runtime_available,
            node_states=node_states,
            warnings=tuple(warnings),
        )

    async def ensure_baseline(self, force: bool = False) -> Snapshot:
        """Return the active baseline snapshot, capturing one if necessary.

        Args:
            force: Recapture the baseline even if one is already loaded.

        Returns:
            The baseline :class:`Snapshot`.
        """
        async with self._lock:
            if self._baseline is not None and not force:
                return self._baseline
            if not force:
                persisted = self._load_persisted_baseline()
                if persisted is not None:
                    self._baseline = persisted
                    return persisted
            snapshot = await self.capture_snapshot()
            self._baseline = snapshot
            self._save_baseline(snapshot)
            return snapshot

    async def get_baseline(self) -> Snapshot:
        """Return the active baseline, raising when none has been captured.

        Raises:
            SnapshotNotFoundError: If no baseline exists and capture was not
                requested.
        """
        if self._baseline is not None:
            return self._baseline
        persisted = self._load_persisted_baseline()
        if persisted is None:
            raise SnapshotNotFoundError(
                "No baseline snapshot exists. Call POST /api/v1/snapshot first.",
                state_dir=str(self._settings.state_dir),
            )
        self._baseline = persisted
        return persisted

    async def snapshot_response(self) -> SnapshotResponse:
        """Capture (or recapture) the baseline and return an API response."""
        snapshot = await self.ensure_baseline(force=True)
        return SnapshotResponse(
            snapshot=summarise(snapshot),
            is_baseline=True,
            node_states=tuple(node_state_summaries(snapshot)),
        )

    # -- Simulation ----------------------------------------------------------

    def _default_origin(self, model: TwinModel, change: ChangeRequest) -> str:
        """Pick the attacker origin used for risk scoring.

        Prefers an explicit origin, then the topology's configured entry points,
        then any node other than the change target.
        """
        if change.origin_node and change.origin_node in model.topology.nodes:
            return change.origin_node
        entrypoints = model.topology.entrypoints
        if entrypoints:
            return entrypoints[0]
        for name in model.topology.nodes:
            if name != change.target_node:
                return name
        return change.target_node

    def _projected_paths(self, model: TwinModel) -> tuple[ReachabilityPath, ...]:
        """Solve the full reachability matrix for a projected model."""
        solver = ReachabilitySolver(model.topology, model.policy_set)
        return solver.solve_matrix()

    async def simulate_change(
        self, change: ChangeRequest, apply_to_runtime: bool = False
    ) -> SimulationResult:
        """Evaluate a candidate change against the baseline.

        Args:
            change: Validated change request.
            apply_to_runtime: Also push the projected policy to live containers
                (only meaningful in live mode).

        Returns:
            A :class:`SimulationResult` containing the policy delta, reachability
            delta and baseline-versus-projected risk.

        Raises:
            SnapshotNotFoundError: If no baseline could be established.
            ChangeValidationError: If the change does not apply to this topology.
        """
        baseline = await self.ensure_baseline()
        baseline_model = TwinModel(topology=baseline.topology, policy_set=baseline.policy_set)

        outcome: ChangeOutcome = apply_change(baseline_model, change)
        projected_paths = self._projected_paths(outcome.model)

        policy_delta = diff_policy(baseline.policy_set, outcome.model.policy_set)
        reachability_delta = diff_reachability(baseline, projected_paths)

        origin = self._default_origin(outcome.model, change)
        risk_delta: RiskDelta = diff_risk(baseline, projected_paths, origin)

        warnings = list(outcome.warnings)
        applied = False
        if apply_to_runtime:
            applied, apply_warnings = await self._try_apply(outcome.model)
            warnings.extend(apply_warnings)
        if not baseline.runtime_available:
            warnings.append(
                "Baseline was captured in model-only mode; results are resolved from the "
                "declarative model, not live container state."
            )

        summary = build_summary(change, policy_delta, reachability_delta, risk_delta)
        simulation_id = f"sim-{uuid.uuid4().hex[:12]}"

        result = SimulationResult(
            simulation_id=simulation_id,
            lab_name=baseline.lab_name,
            runtime_mode=baseline.runtime_mode,
            runtime_available=baseline.runtime_available,
            applied=applied,
            baseline_snapshot_id=baseline.snapshot_id,
            change=change,
            policy_delta=policy_delta,
            reachability_delta=reachability_delta,
            risk=risk_delta,
            summary=summary,
            warnings=tuple(warnings),
        )

        self._record(result, origin)
        if applied:
            self._applied_simulations.append(simulation_id)
        return result

    def _record(self, result: SimulationResult, origin: str) -> None:
        """Append a simulation to the persisted history."""
        entry = SimulationHistoryEntry(
            simulation_id=result.simulation_id,
            created_at=result.created_at,
            change_type=result.change.change_type.value,
            target_node=result.change.target_node,
            description=result.change.description,
            direction=result.risk.direction,
            baseline_score=result.risk.baseline.risk_score,
            projected_score=result.risk.projected.risk_score,
            risk_level=result.risk.projected.risk_level,
            blast_radius_pct=result.risk.projected.blast_radius_pct,
            paths_opened=len(result.reachability_delta.newly_reachable),
            paths_closed=len(result.reachability_delta.newly_blocked),
            summary=result.summary,
        )
        self._history.append(entry)
        self._save_history()

    async def _try_apply(self, model: TwinModel) -> tuple[bool, list[str]]:
        """Push a projected model's policy to live containers.

        Returns:
            ``(applied, warnings)``; never raises, because an unavailable runtime
            must not fail the simulation itself.
        """
        warnings: list[str] = []
        try:
            status = await self._gateway.status(model.topology)
        except RuntimeUnavailableError as exc:
            return False, [f"Change not pushed to runtime: {exc.detail}"]

        if not status.docker_available or not status.running_nodes:
            return False, [
                (
                    "Change evaluated in model-only mode; containers are not running so "
                    "nothing was pushed to the runtime."
                )
            ]

        for node_name in model.topology.nodes:
            if node_name not in status.running_nodes:
                warnings.append(f"Skipped {node_name}: container not running.")
                continue
            try:
                await self._push_node_policy(model, node_name)
            except (CommandExecutionError, RuntimeUnavailableError) as exc:
                warnings.append(f"Failed to push policy to {node_name}: {exc.detail}")
                return False, warnings
        return True, [*warnings, "Projected policy pushed to all running containers."]

    async def _push_node_policy(self, model: TwinModel, node: str) -> None:
        """Atomically replace one node's firewall policy inside its container."""
        topology = model.topology
        for chain in ChainName:
            chain_policy = model.policy_set.chain(node, chain)
            await self._gateway.exec_in_node(topology, node, ["iptables", "-F", chain.value])
            await self._gateway.exec_in_node(
                topology, node, ["iptables", "-P", chain.value, chain_policy.default_action.value]
            )
            for rule in chain_policy.rules:
                await self._gateway.exec_in_node(
                    topology,
                    node,
                    ["iptables", "-A", chain.value, *rule.raw.split()],
                )

    async def push_baseline_to_runtime(self) -> tuple[bool, list[str]]:
        """Re-push the baseline policy to all live containers."""
        baseline = await self.get_baseline()
        baseline_model = TwinModel(topology=baseline.topology, policy_set=baseline.policy_set)
        return await self._try_apply(baseline_model)

    # -- Blast radius --------------------------------------------------------

    async def analyze_blast_radius(self, request: BlastRadiusRequest) -> BlastRadiusResponse:
        """Compute graph-based reachability risk and blast radius.

        Args:
            request: Origins, optional flow filter and optional candidate change.

        Returns:
            A :class:`BlastRadiusResponse` with per-origin assessments and the
            union blast radius.

        Raises:
            ChangeValidationError: If a requested origin or flow is unknown.
        """
        baseline = await self.ensure_baseline()
        analysed_change = request.include_simulated_change
        projected_paths = None
        novelty_by_origin: dict[str, float] = {}

        if analysed_change is not None:
            base_model = TwinModel(topology=baseline.topology, policy_set=baseline.policy_set)
            outcome = apply_change(base_model, analysed_change)
            projected_paths = self._projected_paths(outcome.model)
            analysis_snapshot = baseline.model_copy(update={"paths": projected_paths})
        else:
            analysis_snapshot = baseline

        origins: tuple[str, ...]
        if request.origin_nodes:
            origins = request.origin_nodes
        elif request.origin_node:
            origins = (request.origin_node,)
        else:
            origins = baseline.topology.entrypoints
        if not origins:
            raise ChangeValidationError(
                "No origin supplied and the topology declares no entry points.",
                topology_nodes=sorted(baseline.topology.nodes),
            )

        for origin in origins:
            if origin not in baseline.topology.nodes:
                raise ChangeValidationError(
                    f"Unknown origin node {origin!r}.",
                    origin=origin,
                    known_nodes=sorted(baseline.topology.nodes),
                )
        for flow_name in request.flows:
            if flow_name not in {f.name for f in baseline.topology.probe_flows}:
                raise ChangeValidationError(
                    f"Unknown probe flow {flow_name!r}.",
                    flow=flow_name,
                    known_flows=[f.name for f in baseline.topology.probe_flows],
                )

        if projected_paths is not None:
            # Score novelty against the baseline so this endpoint agrees exactly
            # with /simulate-change for the same candidate change.
            novelty_by_origin = {
                origin: risk_module.novelty_ratio(baseline, origin, projected_paths)
                for origin in origins
            }

        assessments: list[RiskAssessment] = [
            risk_module.assess(
                analysis_snapshot, origin, request.flows, novelty_by_origin.get(origin, 0.0)
            )
            for origin in origins
        ]
        score, level, blast = risk_module.aggregate(
            analysis_snapshot, origins, request.flows, novelty_by_origin
        )

        paths: list = []
        seen: set[tuple[str, str, str]] = set()
        for origin in origins:
            for path in risk_module.attack_paths(analysis_snapshot, origin, request.flows):
                if path.key in seen:
                    continue
                seen.add(path.key)
                paths.append(path)

        return BlastRadiusResponse(
            lab_name=analysis_snapshot.lab_name,
            runtime_mode=analysis_snapshot.runtime_mode,
            baseline_snapshot_id=baseline.snapshot_id,
            analysed_change=analysed_change,
            assessments=tuple(assessments),
            aggregate_risk_score=score,
            aggregate_risk_level=level,
            blast_radius_pct=blast,
            attack_paths=tuple(paths),
        )

    # -- Rollback ------------------------------------------------------------

    async def rollback(self, apply_to_runtime: bool = True) -> RollbackResponse:
        """Revert the twin to its captured baseline.

        Args:
            apply_to_runtime: Re-push baseline rules to live containers when a
                runtime is available.

        Returns:
            A :class:`RollbackResponse`.

        Raises:
            SnapshotNotFoundError: If no baseline exists.
            RollbackError: If the baseline could not be restored.
        """
        try:
            baseline = await self.get_baseline()
        except SnapshotNotFoundError as exc:
            raise SnapshotNotFoundError(
                "Cannot roll back: no baseline snapshot has been captured.",
                state_dir=str(self._settings.state_dir),
            ) from exc

        reverted = tuple(self._applied_simulations)
        warnings: list[str] = []
        runtime_applied = False

        if apply_to_runtime:
            try:
                runtime_applied, push_warnings = await self.push_baseline_to_runtime()
                warnings.extend(push_warnings)
            except (RuntimeUnavailableError, CommandExecutionError) as exc:
                warnings.append(f"Baseline not re-pushed to runtime: {exc.detail}")
        else:
            warnings.append("Runtime re-apply skipped by request.")

        self._applied_simulations.clear()
        self._history.clear()
        self._save_history()

        if not runtime_applied:
            warnings.append(
                "Logical rollback complete: the active baseline snapshot is restored. "
                "Container firewall state was not modified."
            )

        return RollbackResponse(
            restored_snapshot_id=baseline.snapshot_id,
            reverted_simulation_ids=reverted,
            runtime_applied=runtime_applied,
            warnings=tuple(warnings),
        )

    # -- Compliance ----------------------------------------------------------

    async def compliance(self) -> ComplianceReport:
        """Evaluate compliance controls against the current baseline."""
        baseline = await self.ensure_baseline()
        return evaluate_compliance(baseline)

    # -- Views ---------------------------------------------------------------

    async def topology_view(self) -> TopologyView:
        """Build the dashboard projection of the topology."""
        model = self.model
        status = await self.runtime_status()

        running: dict[str, bool] = {}
        if status.docker_available:
            try:
                running = await self._gateway.list_lab_containers(model.topology.lab_name)
            except RuntimeUnavailableError:
                running = {}

        nodes: list[NodeView] = []
        for name, node in model.topology.nodes.items():
            rule_count = sum(
                len(model.policy_set.chain(name, chain).rules) for chain in ChainName
            )
            nodes.append(
                NodeView(
                    name=name,
                    role=node.role,
                    zone=node.zone,
                    zone_label=model.topology.zone_of(name).label,
                    zone_tier=model.topology.zone_of(name).tier,
                    criticality=node.criticality,
                    crown_jewel=node.is_crown_jewel,
                    ip_forward=node.ip_forward,
                    container_name=node.container_name,
                    primary_ip=node.primary_ip,
                    running=running.get(name, False),
                    interfaces=tuple(
                        InterfaceView(
                            name=iface.name,
                            address=iface.address,
                            subnet=iface.subnet,
                            up=iface.state == InterfaceState.UP,
                        )
                        for iface in node.interfaces
                    ),
                    policy_rule_count=rule_count,
                    default_policies={
                        str(chain.value): str(action.value)
                        for chain, action in sorted(node.default_policies.items())
                    },
                )
            )

        links = tuple(
            LinkView(
                source=link.a_node,
                target=link.b_node,
                source_iface=link.a_iface,
                target_iface=link.b_iface,
                subnet=link.subnet,
                up=self._link_is_up(model, link.a_node, link.a_iface, link.b_node, link.b_iface),
            )
            for link in model.topology.links
        )

        zones = tuple(
            ZoneView(
                name=zone.name,
                label=zone.label,
                tier=zone.tier,
                crown_jewel=zone.crown_jewel,
                node_count=sum(1 for node in model.topology.nodes.values() if node.zone == zone.name),
            )
            for zone in sorted(model.topology.zones.values(), key=lambda z: z.tier)
        )

        return TopologyView(
            lab_name=model.topology.lab_name,
            runtime_mode=status.runtime_mode,
            runtime_detail=status.detail,
            nodes=tuple(nodes),
            links=links,
            zones=zones,
            entrypoints=model.topology.entrypoints,
            probe_flows=tuple(f.name for f in model.topology.probe_flows),
        )

    @staticmethod
    def _link_is_up(model: TwinModel, a_node: str, a_iface: str, b_node: str, b_iface: str) -> bool:
        """Whether both endpoints of a link are operationally up."""
        first = model.topology.node(a_node).interface(a_iface)
        second = model.topology.node(b_node).interface(b_iface)
        if first is None or second is None:
            return False
        return first.state == InterfaceState.UP and second.state == InterfaceState.UP

    def chain_views(self) -> tuple[ChainView, ...]:
        """Render every node chain for UI inspection.

        Chains that carry no rules and default to ACCEPT are omitted: they
        represent implicit permission and would only add noise.
        """
        model = self.model
        views: list[ChainView] = []
        for node_name in model.topology.nodes:
            for chain in ChainName:
                policy = model.policy_set.chain(node_name, chain)
                if not policy.rules and policy.default_action == RuleAction.ACCEPT:
                    continue
                views.append(
                    ChainView(
                        node=node_name,
                        chain=chain.value,
                        default_policy=policy.default_action,
                        rule_count=len(policy.rules),
                        rules=tuple(rule.raw for rule in policy.rules),
                    )
                )
        return tuple(views)

    def history(self) -> tuple[SimulationHistoryEntry, ...]:
        """Return the simulation history, newest first."""
        return tuple(reversed(self._history))

    async def health(self) -> HealthView:
        """Build the readiness payload for the dashboard and orchestrators."""
        from .. import __version__

        status = await self.runtime_status()
        baseline = self._baseline or self._load_persisted_baseline()
        docker_ok = status.docker_available

        checks = {
            "topology_loaded": True,
            "docker_daemon": docker_ok,
            "containerlab_cli": status.containerlab_available,
            "lab_deployed": status.lab_deployed,
            "baseline_captured": baseline is not None,
        }
        degraded = not docker_ok
        detail = (
            status.detail
            if docker_ok
            else f"{status.detail} Set TWIN_* environment variables to point at another lab."
        )

        return HealthView(
            status="degraded" if degraded else "ok",
            version=__version__,
            lab_name=self.model.topology.lab_name,
            runtime_mode=status.runtime_mode,
            docker_available=docker_ok,
            containerlab_available=status.containerlab_available,
            lab_deployed=status.lab_deployed,
            baseline_captured=baseline is not None,
            baseline_snapshot_id=baseline.snapshot_id if baseline else None,
            detail=detail,
            checks=checks,
        )

    # -- Lab lifecycle -------------------------------------------------------

    async def deploy_lab(self) -> LabLifecycleResponse:
        """Render bootstrap scripts and deploy the Containerlab topology."""
        from .render import render_bootstrap_scripts

        render_bootstrap_scripts(self._settings)
        return await self._gateway.deploy()

    async def destroy_lab(self) -> LabLifecycleResponse:
        """Tear down the Containerlab topology."""
        return await self._gateway.destroy()

    # -- Introspection -------------------------------------------------------

    def baseline_summary(self) -> SnapshotSummary | None:
        """Summary of the active baseline, or ``None`` when none exists."""
        snapshot = self._baseline
        return summarise(snapshot) if snapshot is not None else None

    def snapshot(self) -> Snapshot | None:
        """The in-memory baseline snapshot, if loaded."""
        return self._baseline


__all__ = ["MAX_HISTORY", "TwinService"]
