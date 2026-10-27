"""Topology and model loader.

Merges two artefacts into one validated:class:`~app.models.topology.Topology`:

* ``corporate-twin.yml`` -- Containerlab wiring (nodes, images, cabled
  interfaces).
* ``config/model.yaml`` -- declaring intent (addressing, routes, zones,
  criticality, firewall policy, probe flows).

Validation is strict and fails fast with actionable messages: a twin that
silently disagrees with what gets deployed is worse than no twin at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..config import Settings, get_settings
from ..models.enums import ChainName, InterfaceState, NodeRole, RuleAction
from ..models.policy import ChainPolicy, PolicySet
from ..models.topology import (
    FlowSpec,
    Interface,
    RouteEntry,
    Topology,
    TopologyLink,
    TopologyNode,
    Zone,
)
from .exceptions import TopologyModelError
from .policy_engine import compile_policy_set


@dataclass(frozen=True, slots=True)
class TwinModel:
    """A validated topology paired with its compiled firewall policy."""

    topology: Topology
    policy_set: PolicySet

    def with_updates(
        self, topology: Topology | None = None, policy_set: PolicySet | None = None
    ) -> TwinModel:
        """Return a copy with either member replaced.

        Used by the what-if engine so candidate changes never mutate the
        baseline model.
        """
        return TwinModel(
            topology=topology if topology is not None else self.topology,
            policy_set=policy_set if policy_set is not None else self.policy_set,
        )


def _read_yaml(path: Path, label: str) -> dict[str, Any]:
    """Read a YAML document, raising a domain error on any failure.

    Args:
        path: File to read.
        label: Human-readable label used in error messages.

    Returns:
        The parsed document as a mapping.

    Raises:
        TopologyModelError: If the file is missing, unreadable, invalid YAML,
            or does not contain a mapping.
    """
    if not path.exists():
        raise TopologyModelError(f"{label} not found at {path}.", path=str(path))
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise TopologyModelError(f"{label} is not valid YAML: {exc}", path=str(path)) from exc
    if not isinstance(raw, dict):
        raise TopologyModelError(
            f"{label} must contain a YAML mapping at the top level.", path=str(path)
        )
    return raw


def _require(mapping: dict[str, Any], key: str, label: str) -> Any:
    """Fetch a required key from a mapping or raise a domain error."""
    if key not in mapping:
        raise TopologyModelError(f"{label} is missing required key {key!r}.", key=key)
    return mapping[key]


def _parse_endpoint(endpoint: str, label: str) -> tuple[str, str]:
    """Split a Containerlab ``"node:iface"`` endpoint string.

    Raises:
        TopologyModelError: If the endpoint is malformed.
    """
    node, separator, iface = endpoint.partition(":")
    if not separator or not node or not iface:
        raise TopologyModelError(
            f"{label}: malformed link endpoint {endpoint!r}; expected 'node:iface'.",
            endpoint=endpoint,
        )
    return node, iface


def load_twin_model(settings: Settings | None = None) -> TwinModel:
    """Load, merge and validate the topology and declarative model.

    Args:
        settings: Optional settings override (defaults to the process singleton).

    Returns:
        A validated :class:`TwinModel`.

    Raises:
        TopologyModelError: If either artefact is missing, malformed, or the two
            disagree about nodes, interfaces, coupling or zones.
    """
    cfg = settings or get_settings()
    lab = _read_yaml(cfg.topology_file, "Containerlab topology")
    model = _read_yaml(cfg.model_file, "Declarative model")

    lab_name = str(_require(lab, "name", "Containerlab topology"))
    lab_topology = _require(lab, "topology", "Containerlab topology")
    if not isinstance(lab_topology, dict):
        raise TopologyModelError("Containerlab 'topology' must be a mapping.")

    lab_nodes: dict[str, Any] = _require(lab_topology, "nodes", "Containerlab topology") or {}
    lab_links: list[Any] = _require(lab_topology, "links", "Containerlab topology") or []
    if not isinstance(lab_nodes, dict) or not lab_nodes:
        raise TopologyModelError("Containerlab topology must declare at least one node.")

    model_nodes: dict[str, Any] = _require(model, "nodes", "Declarative model") or {}
    if not isinstance(model_nodes, dict) or not model_nodes:
        raise TopologyModelError("Declarative model must declare at least one node.")

    missing_in_model = sorted(set(lab_nodes) - set(model_nodes))
    missing_in_lab = sorted(set(model_nodes) - set(lab_nodes))
    if missing_in_model or missing_in_lab:
        raise TopologyModelError(
            "Containerlab topology and declarative model disagree on nodes.",
            only_in_topology=missing_in_model,
            only_in_model=missing_in_lab,
        )

    # --- Zones --------------------------------------------------------------
    zones: dict[str, Zone] = {}
    for zone_name, zone_data in (_require(model, "zones", "Declarative model") or {}).items():
        if not isinstance(zone_data, dict):
            raise TopologyModelError(f"Zone {zone_name!r} must be a mapping.")
        zones[zone_name] = Zone(
            name=zone_name,
            label=str(zone_data.get("label", zone_name)),
            tier=int(zone_data.get("tier", 0)),
            crown_jewel=bool(zone_data.get("crown_jewel", False)),
            user_facing=bool(zone_data.get("user_facing", False)),
        )

    # --- Links --------------------------------------------------------------
    links: list[TopologyLink] = []
    endpoint_owner: dict[tuple[str, str], str] = {}
    for link in lab_links:
        if not isinstance(link, dict) or "endpoints" not in link:
            raise TopologyModelError("Each Containerlab link requires an 'endpoints' list.")
        endpoints = link["endpoints"]
        if not isinstance(endpoints, list) or len(endpoints) != 2:
            raise TopologyModelError(
                "Each Containerlab link requires exactly two endpoints.",
                endpoints=endpoints,
            )
        first_node, first_iface = _parse_endpoint(str(endpoints[0]), "link")
        second_node, second_iface = _parse_endpoint(str(endpoints[1]), "link")
        links.append(
            TopologyLink(
                a_node=first_node,
                a_iface=first_iface,
                b_node=second_node,
                b_iface=second_iface,
                subnet="0.0.0.0/0",  # replaced once addressing is known
            )
        )
        endpoint_owner[(first_node, first_iface)] = second_node
        endpoint_owner[(second_node, second_iface)] = first_node

    # --- Nodes --------------------------------------------------------------
    nodes: dict[str, TopologyNode] = {}
    interfaces_by_node: dict[str, list[Interface]] = {}

    for node_name, node_data in model_nodes.items():
        if not isinstance(node_data, dict):
            raise TopologyModelError(f"Node {node_name!r} must be a mapping.")

        role_raw = str(node_data.get("role", "host"))
        try:
            role = NodeRole(role_raw)
        except ValueError as exc:
            raise TopologyModelError(
                f"Node {node_name!r} has unknown role {role_raw!r}.",
                node=node_name,
                role=role_raw,
            ) from exc

        zone_name = str(_require(node_data, "zone", f"Node {node_name!r}"))
        if zone_name not in zones:
            raise TopologyModelError(
                f"Node {node_name!r} references undefined zone {zone_name!r}.",
                node=node_name,
                zone=zone_name,
                known_zones=sorted(zones),
            )

        raw_interfaces = _require(node_data, "interfaces", f"Node {node_name!r}")
        if not isinstance(raw_interfaces, list) or not raw_interfaces:
            raise TopologyModelError(f"Node {node_name!r} must declare at least one interface.")

        interfaces: list[Interface] = []
        for iface_data in raw_interfaces:
            if not isinstance(iface_data, dict):
                raise TopologyModelError(
                    f"Node {node_name!r} has a malformed interface entry."
                )
            iface = Interface(
                name=str(_require(iface_data, "name", f"Interface of {node_name!r}")),
                address=str(_require(iface_data, "address", f"Interface of {node_name!r}")),
                state=InterfaceState.UP,
            )
            if (node_name, iface.name) not in endpoint_owner:
                raise TopologyModelError(
                    f"Node {node_name!r} declares interface {iface.name!r} that is not cabled "
                    "in corporate-twin.yml.",
                    node=node_name,
                    interface=iface.name,
                )
            interfaces.append(iface)
        interfaces_by_node[node_name] = interfaces

        routes: list[RouteEntry] = []
        for route_data in node_data.get("routes", []) or []:
            if not isinstance(route_data, dict):
                raise TopologyModelError(f"Node {node_name!r} has a malformed route entry.")
            routes.append(
                RouteEntry(
                    prefix=str(_require(route_data, "prefix", f"Route of {node_name!r}")),
                    via=str(route_data["via"]) if route_data.get("via") else None,
                    dev=str(route_data["dev"]) if route_data.get("dev") else None,
                    protocol=str(route_data.get("protocol", "static")),
                    metric=int(route_data.get("metric", 100)),
                    description=route_data.get("description"),
                )
            )

        defaults_raw = node_data.get("default_policies", {}) or {}
        defaults: dict[ChainName, RuleAction] = {}
        for chain_key, action_value in defaults_raw.items():
            try:
                chain = ChainName(chain_key)
            except ValueError as exc:
                raise TopologyModelError(
                    f"Node {node_name!r} declares unknown chain {chain_key!r}.",
                    node=node_name,
                    chain=chain_key,
                ) from exc
            try:
                defaults[chain] = RuleAction(str(action_value).upper())
            except ValueError as exc:
                raise TopologyModelError(
                    f"Node {node_name!r} declares unknown verdict {action_value!r} for {chain_key}.",
                    node=node_name,
                    verdict=str(action_value),
                ) from exc

        nodes[node_name] = TopologyNode(
            name=node_name,
            role=role,
            zone=zone_name,
            criticality=int(node_data.get("criticality", 3)),
            # Crown-jewel status is inherited from the zone unless overridden.
            crown_jewel=bool(
                node_data.get("crown_jewel", zones[zone_name].crown_jewel)
            ),
            ip_forward=bool(node_data.get("ip_forward", False)),
            description=node_data.get("description"),
            container_name=f"clab-{lab_name}-{node_name}",
            interfaces=tuple(interfaces),
            routes=tuple(routes),
            default_policies=defaults,
        )

    # --- Link subnets -------------------------------------------------------
    validated_links: list[TopologyLink] = []
    for link in links:
        first = next(
            (i for i in interfaces_by_node[link.a_node] if i.name == link.a_iface), None
        )
        second = next(
            (i for i in interfaces_by_node[link.b_node] if i.name == link.b_iface), None
        )
        if first is None or second is None:  # pragma: no cover - endpoint check above
            raise TopologyModelError(
                f"Link {link.a_node}:{link.a_iface} <-> {link.b_node}:{link.b_iface} "
                "references an interface the model does not declare."
            )
        if first.network != second.network:
            raise TopologyModelError(
                f"Coupling {link.a_node}:{link.a_iface} <-> {link.b_node}:{link.b_iface} "
                f"joins {first.subnet} to {second.subnet}; the two ends must share a subnet.",
                first_subnet=first.subnet,
                second_subnet=second.subnet,
            )
        validated_links.append(link.model_copy(update={"subnet": first.subnet}))

    # --- Entry points and probe flows ---------------------------------------
    entrypoints = tuple(str(name) for name in (model.get("entrypoints") or []))
    unknown_entrypoints = [name for name in entrypoints if name not in nodes]
    if unknown_entrypoints:
        raise TopologyModelError(
            "Entry points reference unknown nodes.",
            unknown=unknown_entrypoints,
        )

    probe_flows: list[FlowSpec] = []
    for flow_data in model.get("probe_flows", []) or []:
        if not isinstance(flow_data, dict):
            raise TopologyModelError("Each probe flow must be a mapping.")
        probe_flows.append(
            FlowSpec(
                name=str(_require(flow_data, "name", "Probe flow")),
                protocol=str(flow_data.get("protocol", "tcp")).lower(),
                dport=int(flow_data["dport"]) if flow_data.get("dport") is not None else None,
            )
        )
    if not probe_flows:
        raise TopologyModelError("At least one probe flow must be declared.")

    # --- Policy -------------------------------------------------------------
    declarations: dict[str, dict[str, list[str]]] = {
        node_name: {
            str(chain_key): [str(rule) for rule in (rules or [])]
            for chain_key, rules in (per_chain or {}).items()
        }
        for node_name, per_chain in (model.get("policies") or {}).items()
    }
    unknown_policy_nodes = sorted(set(declarations) - set(nodes))
    if unknown_policy_nodes:
        raise TopologyModelError(
            "Policy declarations reference unknown nodes.",
            unknown=unknown_policy_nodes,
        )

    default_policies = {name: dict(node.default_policies) for name, node in nodes.items()}
    policy_set = compile_policy_set(declarations, default_policies)

    # Materialise every chain of every node so the API can report defaults even
    # for chains with no rules of their own (a missing entry would otherwise be
    # indistinguishable from an implicit ACCEPT).
    for node_name, node in nodes.items():
        configured = policy_set.chains.get(node_name, {})
        for chain in ChainName:
            if chain in configured:
                continue
            policy_set = policy_set.with_chain(
                ChainPolicy(
                    node=node_name,
                    chain=chain,
                    default_action=node.default_policies.get(chain, RuleAction.ACCEPT),
                    rules=(),
                )
            )

    topology = Topology(
        lab_name=lab_name,
        zones=zones,
        nodes=nodes,
        links=tuple(validated_links),
        entrypoints=entrypoints,
        probe_flows=tuple(probe_flows),
    )
    return TwinModel(topology=topology, policy_set=policy_set)


__all__ = ["TwinModel", "load_twin_model"]
