"""Multi-hop, routing-aware reachability solver.

Unlike a naive adjacency walk, this solver reproduces what a real forwarding
plane does:

* longest-prefix-match routing on every node, including synthesised connected
  routes and declared static/default routes;
* next-hop resolution by IP ownership across the topology graph;
* netfilter chains evaluated at the correct hook -- ``OUTPUT`` on the origin,
  ``FORWARD`` on every transit router (with the correct ingress *and* egress
  interface), and ``INPUT`` on the destination;
* exact port-interval intersection for port-agnostic flows, so a permit is only
  reported when *every* hop agrees on a usable port. A permit for "any port"
  therefore cannot mask an explicit ``DROP`` upstream of it.

The result is a per-flow verdict that is defensible in a change-approval
record, not just a ping-style up/down boolean.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..models.enums import ChainName, InterfaceState, RuleAction
from ..models.policy import PacketContext, PolicySet
from ..models.snapshot import ReachabilityPath
from ..models.topology import FlowSpec, Interface, IPNetwork, Topology, TopologyNode
from .policy_engine import (
    FULL_PORT_RANGE,
    NO_PORTS,
    PolicyEngine,
    PortRanges,
    Verdict,
    intersect_ranges,
    ranges_is_empty,
)

#: Hard cap on layer-3 hops to guarantee termination on pathological models.
MAX_HOPS: int = 16


@dataclass(frozen=True, slots=True)
class FlowVerdict:
    """Outcome of tracing one flow between two nodes."""

    reachable: bool
    path: tuple[str, ...]
    port_ranges: PortRanges = field(default=NO_PORTS)
    blocked_at: str | None = None
    blocked_by: str | None = None
    reason: str = ""

    @property
    def hops(self) -> int:
        """Number of layer-3 hops traversed."""
        return max(0, len(self.path) - 1)


class ReachabilitySolver:
    """Traces flows across a :class:`Topology` under a :class:`PolicySet`."""

    def __init__(self, topology: Topology, policy_set: PolicySet) -> None:
        """Bind the solver to a topology and its compiled policy.

        Args:
            topology: Validated topology graph.
            policy_set: Compiled firewall policy for the same topology.
        """
        self._topology = topology
        self._engine = PolicyEngine(policy_set)

    @property
    def topology(self) -> Topology:
        """Topology under analysis."""
        return self._topology

    # -- Internal helpers ----------------------------------------------------

    def _egress_interface(self, node: TopologyNode, route_prefix: str) -> Interface | None:
        """Resolve the egress interface a node uses to reach ``route_prefix``."""
        target_network = ipaddress.ip_network(route_prefix, strict=False)
        route = next((r for r in node.all_routes() if r.network == target_network), None)
        if route is None:
            return None
        if route.dev:
            iface = node.interface(route.dev)
            if iface is not None and iface.state == InterfaceState.UP:
                return iface
        iface = node.interface_on(route.network)
        if iface is not None:
            return iface
        if route.via:
            return node.interface_toward(route.via)
        return None

    def _block(
        self,
        trail: list[str],
        at: str,
        verdict: Verdict | None,
        reason: str,
    ) -> FlowVerdict:
        """Build a blocked verdict from the current trail."""
        return FlowVerdict(
            reachable=False,
            path=tuple(trail),
            port_ranges=NO_PORTS,
            blocked_at=at,
            blocked_by=verdict.reason if verdict else None,
            reason=reason,
        )

    def _apply_hop(
        self,
        node: str,
        chain: ChainName,
        ctx: PacketContext,
        port_agnostic: bool,
        ranges: PortRanges,
    ) -> tuple[PortRanges, Verdict | None]:
        """Evaluate one netfilter hook and update the reachable port set.

        Args:
            node: Node whose chain is traversed.
            chain: Hook to evaluate.
            ctx: Packet context; ``dport`` carries the flow's port when known.
            port_agnostic: Whether ``ctx.dport`` is ``None``.
            ranges: Port intervals accumulated so far.

        Returns:
            ``(updated_ranges, blocking_verdict)``. The verdict is ``None`` when
            the hop permits the packet.
        """
        if not port_agnostic:
            verdict = self._engine.evaluate(node, chain, ctx)
            if verdict.action != RuleAction.ACCEPT:
                return NO_PORTS, verdict
            return ranges, None

        hop_ranges = self._engine.permitted_ranges(node, chain, ctx)
        combined = intersect_ranges(ranges, hop_ranges)
        if ranges_is_empty(combined):
            return NO_PORTS, self._engine.describe_port_agnostic(node, chain, ctx)
        return combined, None

    # -- Public API ----------------------------------------------------------

    def solve_flow(self, src_node: str, dst_node: str, flow: FlowSpec) -> FlowVerdict:
        """Trace ``flow`` from ``src_node`` to ``dst_node``.

        Args:
            src_node: Source node name.
            dst_node: Destination node name.
            flow: Probe flow to evaluate.

        Returns:
            A :class:`FlowVerdict` describing reachability, the traversed path,
            and the reachable destination ports.

        Raises:
            KeyError: If either node is absent from the topology.
        """
        topology = self._topology
        source = topology.node(src_node)
        destination = topology.node(dst_node)

        src_ip = source.primary_ip
        dst_ip = destination.primary_ip
        if src_ip is None or dst_ip is None:
            return FlowVerdict(
                reachable=False,
                path=(src_node,),
                port_ranges=NO_PORTS,
                blocked_at=src_node,
                reason="Source or destination has no usable data-plane address.",
            )

        port_agnostic = flow.dport is None
        if flow.dport is None:
            ranges: PortRanges = FULL_PORT_RANGE
        else:
            ranges = ((flow.dport, flow.dport),)

        trail: list[str] = [src_node]
        visited: set[str] = {src_node}
        current = src_node

        for _ in range(MAX_HOPS):
            node = topology.node(current)
            route = node.resolve_route(dst_ip)
            if route is None:
                return self._block(
                    trail,
                    current,
                    None,
                    f"No route to {dst_ip} on {current} (unroutable destination).",
                )

            egress = self._egress_interface(node, str(route.network))
            if egress is None:
                return self._block(
                    trail,
                    current,
                    None,
                    f"No usable egress interface on {current} toward {route.prefix}.",
                )

            # --- Origin stack: OUTPUT ---------------------------------------
            if current == src_node:
                out_ctx = PacketContext(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=flow.protocol,
                    dport=flow.dport,
                    in_iface=None,
                    out_iface=egress.name,
                )
                ranges, blocking = self._apply_hop(
                    current, ChainName.OUTPUT, out_ctx, port_agnostic, ranges
                )
                if blocking is not None:
                    return self._block(
                        trail,
                        current,
                        blocking,
                        f"Blocked by OUTPUT policy on {current}: {blocking.reason}.",
                    )

            # --- Destination directly attached to `current` ------------------
            # A connected route means the destination must be a layer-2 peer of
            # `current` on that subnet: the node owning dst_ip has to be cabled
            # to the interface the packet egresses from.
            if route.is_connected:
                if ipaddress.ip_address(dst_ip) not in route.network:
                    return self._block(
                        trail,
                        current,
                        None,
                        f"{current} has a connected route for {route.prefix} but {dst_ip} "
                        "is not on that subnet.",
                    )
                owner = topology.node_owning_ip(dst_ip)
                if owner is None:
                    return self._block(
                        trail, current, None, f"{dst_ip} is not owned by any modelled node."
                    )
                if owner[0].name != dst_node:
                    return self._block(
                        trail,
                        current,
                        None,
                        f"{dst_ip} belongs to {owner[0].name}, not {dst_node}.",
                    )
                peers = {peer for peer, *_ in topology.neighbours(current)}
                if dst_node not in peers:
                    return self._block(
                        trail,
                        current,
                        None,
                        f"{dst_node} is not directly attached to {current} "
                        "(link down or unmodelled).",
                    )
                return self._deliver(destination, trail, ranges, route.network, flow, port_agnostic)

            if route.via is None:  # pragma: no cover - defensive
                return self._block(
                    trail,
                    current,
                    None,
                    f"Route {route.prefix} on {current} has no next hop and the "
                    "destination is not on-link.",
                )

            if ipaddress.ip_address(route.via) not in egress.network:
                return self._block(
                    trail,
                    current,
                    None,
                    f"Next hop {route.via} is not on-link for {egress.name} on {current}.",
                )

            next_hop = topology.node_owning_ip(route.via)
            if next_hop is None:
                return self._block(
                    trail,
                    current,
                    None,
                    f"Next hop {route.via} is not owned by any node (link down or unmodelled).",
                )
            router, ingress_iface = next_hop

            # --- Destination *is* the next hop -------------------------------
            if router.name == dst_node:
                return self._deliver(destination, trail, ranges, egress.network, flow, port_agnostic)

            # --- Transit router: FORWARD ------------------------------------
            if not router.ip_forward:
                return self._block(
                    trail, router.name, None, f"IP forwarding is disabled on {router.name}."
                )

            router_route = router.resolve_route(dst_ip)
            if router_route is None:
                return self._block(
                    trail, router.name, None, f"{router.name} has no route to {dst_ip}."
                )
            router_egress = self._egress_interface(router, str(router_route.network))
            if router_egress is None:
                return self._block(
                    trail,
                    router.name,
                    None,
                    f"{router.name} has no usable egress interface toward {router_route.prefix}.",
                )

            forward_ctx = PacketContext(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=flow.protocol,
                dport=flow.dport,
                in_iface=ingress_iface.name,
                out_iface=router_egress.name,
            )
            ranges, blocking = self._apply_hop(
                router.name, ChainName.FORWARD, forward_ctx, port_agnostic, ranges
            )
            if blocking is not None:
                return self._block(
                    trail,
                    router.name,
                    blocking,
                    f"Blocked at transit router {router.name}: {blocking.reason}.",
                )

            if router.name in visited:
                return self._block(trail, router.name, None, "Routing loop detected.")
            visited.add(router.name)
            trail.append(router.name)
            current = router.name
            continue

        return self._block(trail, current, None, f"Exceeded {MAX_HOPS} hops.")

    def _deliver(
        self,
        destination: TopologyNode,
        trail: list[str],
        ranges: PortRanges,
        ingress_network: IPNetwork,
        flow: FlowSpec,
        port_agnostic: bool,
    ) -> FlowVerdict:
        """Apply the destination's ``INPUT`` policy and finalise the verdict."""
        ingress_iface = destination.interface_on(ingress_network)
        dst_ip = destination.primary_ip
        src_ip = self._topology.node(trail[0]).primary_ip
        if dst_ip is None or src_ip is None:  # pragma: no cover - guarded by caller
            return self._block(trail, destination.name, None, "Missing address.")

        ctx = PacketContext(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=flow.protocol,
            dport=flow.dport,
            in_iface=ingress_iface.name if ingress_iface is not None else None,
            out_iface=None,
        )
        final_ranges, blocking = self._apply_hop(
            destination.name, ChainName.INPUT, ctx, port_agnostic, ranges
        )
        if blocking is not None:
            return self._block(
                trail,
                destination.name,
                blocking,
                f"Blocked by INPUT policy on {destination.name}: {blocking.reason}.",
            )

        final_trail = [*trail, destination.name]
        return FlowVerdict(
            reachable=True,
            path=tuple(final_trail),
            port_ranges=final_ranges,
            reason=f"Permitted end to end across {max(0, len(final_trail) - 1)} hop(s).",
        )

    def solve_matrix(self, flows: tuple[FlowSpec, ...] | None = None) -> tuple[ReachabilityPath, ...]:
        """Solve every ordered node pair for every probe flow.

        Args:
            flows: Flows to evaluate; defaults to the topology's probe flows.

        Returns:
            A tuple of :class:`ReachabilityPath` records, ordered by source,
            destination and flow name for deterministic output.
        """
        topology = self._topology
        flow_specs = flows if flows is not None else topology.probe_flows
        results: list[ReachabilityPath] = []

        for src_name in topology.ordered_node_names():
            for dst_name in topology.ordered_node_names():
                if src_name == dst_name:
                    continue
                for flow in flow_specs:
                    verdict = self.solve_flow(src_name, dst_name, flow)
                    results.append(
                        ReachabilityPath(
                            src_node=src_name,
                            dst_node=dst_name,
                            src_ip=topology.node(src_name).primary_ip or "",
                            dst_ip=topology.node(dst_name).primary_ip or "",
                            flow_name=flow.name,
                            protocol=flow.protocol,
                            dport=flow.dport,
                            reachable=verdict.reachable,
                            hops=verdict.hops,
                            path=verdict.path,
                            reachable_ports=verdict.port_ranges,
                            blocked_at=verdict.blocked_at,
                            blocked_by=verdict.blocked_by,
                            reason=verdict.reason,
                        )
                    )
        return tuple(results)


__all__ = ["MAX_HOPS", "FlowVerdict", "ReachabilitySolver"]
