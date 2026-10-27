"""Topology domain model.

The twin's topology is assembled from two artefacts that must agree:

* ``corporate-twin.yml`` -- the Containerlab wiring (which node owns which
  interface, and how interfaces are cabled together).
* ``config/model.yaml`` -- the declarative intent (addressing, routing, zones,
  criticality and firewall policy).

:class:`Topology` is the merged, validated result and is the object every solver
in :mod:`app.core` operates on. It is deliberately immutable-friendly: solvers
copy it before applying a candidate change so the baseline is never mutated.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enums import ChainName, InterfaceState, NodeRole, RuleAction

#: Network object as returned by the stdlib helpers. The model is IPv4-only in
#: practice; the union keeps the annotations honest without pretending otherwise.
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class Interface(BaseModel):
    """A layer-3 interface attached to a subnet."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Interface name inside the container, e.g. 'eth1'.")
    address: str = Field(description="CIDR address, e.g. '10.10.10.1/24'.")
    state: InterfaceState = Field(default=InterfaceState.UP, description="Operational state.")

    @field_validator("address")
    @classmethod
    def _validate_address(cls, value: str) -> str:
        """Reject addresses that are not valid CIDR interface notation."""
        ipaddress.ip_interface(value)
        return value

    @property
    def ip(self) -> str:
        """Host portion of the address, without the prefix length."""
        return str(ipaddress.ip_interface(self.address).ip)

    @property
    def prefix_len(self) -> int:
        """Prefix length of the attached subnet."""
        return ipaddress.ip_interface(self.address).network.prefixlen

    @property
    def network(self) -> IPNetwork:
        """Subnet this interface sits on."""
        return ipaddress.ip_interface(self.address).network

    @property
    def subnet(self) -> str:
        """Subnet in CIDR string form."""
        return str(self.network)


class RouteEntry(BaseModel):
    """A single entry in a node's IPv4 routing table."""

    model_config = ConfigDict(frozen=True)

    prefix: str = Field(description="Destination prefix in CIDR form.")
    via: str | None = Field(
        default=None,
        description="Next-hop IP address. ``None`` marks a directly connected route.",
    )
    dev: str | None = Field(default=None, description="Egress interface name.")
    protocol: str = Field(default="static", description="Origin: connected|static|default.")
    metric: int = Field(default=100, ge=0, description="Administrative distance/metric.")
    description: str | None = Field(default=None, description="Operator-facing note.")

    @field_validator("prefix")
    @classmethod
    def _validate_prefix(cls, value: str) -> str:
        """Reject prefixes that are not valid CIDR networks."""
        ipaddress.ip_network(value, strict=False)
        return value

    @property
    def network(self) -> IPNetwork:
        """Destination prefix as a network object."""
        return ipaddress.ip_network(self.prefix, strict=False)

    @property
    def is_connected(self) -> bool:
        """Whether the route is a directly attached subnet."""
        return self.via is None


class Zone(BaseModel):
    """A security zone used for defence-in-depth scoring."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Zone identifier referenced by nodes.")
    label: str = Field(description="Human-readable zone label.")
    tier: int = Field(ge=0, description="Sensitivity tier; higher is more sensitive.")
    crown_jewel: bool = Field(
        default=False, description="Whether the zone hosts crown-jewel assets."
    )
    user_facing: bool = Field(
        default=False,
        description=(
            "Whether the zone contains end-user endpoints. User-facing zones are held "
            "to a stricter standard than infrastructure zones, which legitimately route "
            "toward sensitive segments."
        ),
    )


class TopologyNode(BaseModel):
    """A twin node with its addressing, routing table and firewall defaults."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Logical node name (matches the Containerlab node).")
    role: NodeRole = Field(description="Router, host or firewall.")
    zone: str = Field(description="Security zone this node belongs to.")
    criticality: int = Field(ge=1, le=5, description="Business criticality, 1-5.")
    crown_jewel: bool = Field(
        default=False,
        description=(
            "Whether this node is a crown-jewel asset. Defaults to the containing "
            "zone's flag, and can be overridden per node. Kept separate from "
            "criticality so a high-value infrastructure node such as a branch "
            "gateway is not misfiled as a data asset."
        ),
    )
    ip_forward: bool = Field(default=False, description="Whether the kernel forwards packets.")
    description: str | None = Field(default=None, description="Operator-facing note.")
    container_name: str = Field(description="Runtime container name, e.g. clab-corporate-twin-x.")
    interfaces: tuple[Interface, ...] = Field(default_factory=tuple, description="L3 interfaces.")
    routes: tuple[RouteEntry, ...] = Field(default_factory=tuple, description="Routing table.")
    default_policies: dict[ChainName, RuleAction] = Field(
        default_factory=dict,
        description="Chain default verdicts; chains without an entry are treated as ACCEPT.",
    )

    def interface(self, name: str) -> Interface | None:
        """Return the interface called ``name``, or ``None`` when absent."""
        return next((i for i in self.interfaces if i.name == name), None)

    def interface_on(self, network: IPNetwork) -> Interface | None:
        """Return the *up* interface attached to ``network``, or ``None``."""
        return next((i for i in self.up_interfaces if i.network == network), None)

    @property
    def up_interfaces(self) -> tuple[Interface, ...]:
        """Interfaces that are administratively and operationally up.

        A link-state change marks both endpoints down, which removes their
        connected routes and makes them ineligible for next-hop selection.
        """
        return tuple(i for i in self.interfaces if i.state == InterfaceState.UP)

    def interface_toward(self, address: str) -> Interface | None:
        """Return the interface whose subnet covers ``address``.

        Used to resolve the egress interface for a static/default route, where
        the model does not pin ``dev`` explicitly.
        """
        try:
            target = ipaddress.ip_address(address)
        except ValueError:
            return None
        return next((i for i in self.up_interfaces if target in i.network), None)

    @property
    def primary_interface(self) -> Interface | None:
        """First (and for hosts, only) data-plane interface.

        Source-address selection is resolved to this interface so policy
        matching in the solver is deterministic.
        """
        candidates = self.up_interfaces or self.interfaces
        return candidates[0] if candidates else None

    @property
    def primary_ip(self) -> str | None:
        """Primary data-plane address, used as the simulated source address."""
        iface = self.primary_interface
        return iface.ip if iface else None

    @property
    def is_crown_jewel(self) -> bool:
        """Whether this node is a crown-jewel asset."""
        return self.crown_jewel

    def all_routes(self) -> tuple[RouteEntry, ...]:
        """Routing table including synthesised connected routes.

        The model only declares static/default routes; connected routes are
        derived from interface addressing so the decLaration stays DRY.
        """
        connected = tuple(
            RouteEntry(
                prefix=iface.subnet,
                via=None,
                dev=iface.name,
                protocol="connected",
                metric=0,
                description="Directly connected subnet.",
            )
            for iface in self.up_interfaces
        )
        return connected + tuple(self.routes)

    def resolve_route(self, destination: str) -> RouteEntry | None:
        """Longest-prefix-match lookup for ``destination``.

        Args:
            destination: Target IPv4 address.

        Returns:
            The winning :class:`RouteEntry`, or ``None`` when the address is
            unroutable (no default route and no covering prefix).
        """
        dst = ipaddress.ip_address(destination)
        candidates = [r for r in self.all_routes() if dst in r.network]
        if not candidates:
            return None
        # Longest prefix wins; ties broken by lowest metric.
        return min(candidates, key=lambda r: (-r.network.prefixlen, r.metric))


class TopologyLink(BaseModel):
    """A point-to-point cable between two node interfaces."""

    model_config = ConfigDict(frozen=True)

    a_node: str = Field(description="First endpoint node name.")
    a_iface: str = Field(description="First endpoint interface name.")
    b_node: str = Field(description="Second endpoint node name.")
    b_iface: str = Field(description="Second endpoint interface name.")
    subnet: str = Field(description="Shared subnet in CIDR form.")

    def other_end(self, node: str) -> tuple[str, str]:
        """Return ``(peer_node, peer_iface)`` for the given endpoint.

        Raises:
            KeyError: If ``node`` is not part of this link.
        """
        if node == self.a_node:
            return self.b_node, self.b_iface
        if node == self.b_node:
            return self.a_node, self.a_iface
        raise KeyError(f"Node {node!r} is not attached to this link.")


class FlowSpec(BaseModel):
    """A probe flow evaluated by the snapshot engine.

    ``dport is None`` denotes an unrestricted-port flow: the solver then
    computes the *intersection* of the port sets each hop permits, which is what
    an attacker could actually reach end to end.
    """

    model_config = ConfigDict(
        frozen=True,
        json_schema_extra={"example": {"name": "ssh", "protocol": "tcp", "dport": 22}},
    )

    name: str = Field(description="Short flow label, e.g. 'postgres'.")
    protocol: str = Field(default="tcp", description="IP protocol: tcp|udp|icmp.")
    dport: int | None = Field(
        default=None, ge=0, le=65535, description="Destination port, or None for any port."
    )


class Topology(BaseModel):
    """The merged, validated network model every solver consumes."""

    model_config = ConfigDict(frozen=True)

    lab_name: str = Field(description="Containerlab lab name.")
    zones: dict[str, Zone] = Field(default_factory=dict, description="Zones by name.")
    nodes: dict[str, TopologyNode] = Field(default_factory=dict, description="Nodes by name.")
    links: tuple[TopologyLink, ...] = Field(default_factory=tuple, description="Cables.")
    entrypoints: tuple[str, ...] = Field(
        default_factory=tuple, description="Nodes assumed externally reachable/compromisable."
    )
    probe_flows: tuple[FlowSpec, ...] = Field(
        default_factory=tuple, description="Flows evaluated during snapshotting."
    )

    # -- Lookups -------------------------------------------------------------

    def node(self, name: str) -> TopologyNode:
        """Return a node by name.

        Raises:
            KeyError: If the node does not exist in the model.
        """
        try:
            return self.nodes[name]
        except KeyError as exc:  # pragma: no cover - defensive
            raise KeyError(f"Unknown node {name!r}. Known nodes: {sorted(self.nodes)}") from exc

    def flow(self, name: str) -> FlowSpec:
        """Return a probe flow by name.

        Raises:
            KeyError: If the flow is not defined in the model.
        """
        for spec in self.probe_flows:
            if spec.name == name:
                return spec
        raise KeyError(f"Unknown flow {name!r}. Known flows: {[f.name for f in self.probe_flows]}")

    def zone(self, name: str) -> Zone:
        """Return a zone by name, raising :class:`KeyError` when absent."""
        return self.zones[name]

    def zone_of(self, node_name: str) -> Zone:
        """Return the zone a node belongs to."""
        return self.zones[self.node(node_name).zone]

    def crown_jewels(self) -> list[TopologyNode]:
        """All nodes at or above crown-jewel criticality."""
        return [n for n in self.nodes.values() if n.is_crown_jewel]

    def node_owning_ip(self, address: str) -> tuple[TopologyNode, Interface] | None:
        """Find the node and *up* interface that own ``address``.

        Interfaces whose link is down are excluded so a severed cable also
        invalidates the next-hop that depended on it.
        """
        for node in self.nodes.values():
            for iface in node.up_interfaces:
                if iface.ip == address:
                    return node, iface
        return None

    def node_on_network(self, network: IPNetwork) -> tuple[TopologyNode, Interface] | None:
        """Find the node and interface attached to ``network``."""
        for node in self.nodes.values():
            iface = node.interface_on(network)
            if iface is not None:
                return node, iface
        return None

    def link_for(self, node: str, iface: str) -> TopologyLink | None:
        """Return the link terminating on ``node:iface``."""
        for link in self.links:
            if (link.a_node, link.a_iface) == (node, iface):
                return link
            if (link.b_node, link.b_iface) == (node, iface):
                return link
        return None

    def neighbours(self, node_name: str) -> list[tuple[str, Interface, Interface, str]]:
        """Return L2-adjacent peers of ``node_name``.

        Returns:
            A list of ``(peer_node, local_interface, peer_interface, subnet)``
            tuples, one per cabled interface.
        """
        node = self.node(node_name)
        peers: list[tuple[str, Interface, Interface, str]] = []
        for link in self.links:
            if node_name not in (link.a_node, link.b_node):
                continue
            peer_name, peer_iface_name = link.other_end(node_name)
            local_iface = node.interface(
                link.b_iface if link.a_node == node_name else link.a_iface
            )
            peer_iface = self.node(peer_name).interface(peer_iface_name)
            if local_iface is None or peer_iface is None:  # pragma: no cover - validated at load
                continue
            peers.append((peer_name, local_iface, peer_iface, link.subnet))
        return peers

    def ordered_node_names(self) -> list[str]:
        """Node names in declaration order for stable iteration."""
        return list(self.nodes.keys())

    def node_pairs(self, include_self: bool = False) -> Iterator[tuple[str, str]]:
        """Yield ordered ``(source, destination)`` node pairs for probing."""
        names = self.ordered_node_names()
        for src in names:
            for dst in names:
                if src == dst and not include_self:
                    continue
                yield src, dst

    def iter_nodes(self) -> Iterable[TopologyNode]:
        """Iterate over nodes in declaration order."""
        return self.nodes.values()
