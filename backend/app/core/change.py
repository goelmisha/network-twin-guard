"""Candidate-change application.

Translates a validated :class:`~app.models.simulation.ChangeRequest` into a
*new* :class:`~app.core.topology_loader.TwinModel`. The baseline is never
mutated, which is what makes the differential engine trustworthy and rollback
trivial.

Flow-level changes use ``iptables -I`` semantics: the generated rule is inserted
at position 1 so it takes precedence over existing policy, exactly as an
operator running ``iptables -I`` would experience.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..models.enums import ChainName, ChangeType, InterfaceState, RuleAction
from ..models.policy import ChainPolicy, PolicySet
from ..models.simulation import ChangeRequest
from ..models.topology import Topology
from .exceptions import ChangeValidationError
from .policy_engine import parse_rule
from .topology_loader import TwinModel


@dataclass(frozen=True, slots=True)
class ChangeOutcome:
    """The result of applying a candidate change.

    Attributes:
        model: The projected model (baseline untouched).
        affected_nodes: Nodes whose configuration or cabling changed.
        warnings: Non-fatal observations worth surfacing to the operator.
        origin_node: Compromise origin when the change is an attacker
            simulation, otherwise ``None``.
    """

    model: TwinModel
    affected_nodes: tuple[str, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)
    origin_node: str | None = None


def _normalise_prefix(value: str) -> str:
    """Normalise a bare address or CIDR into strict network notation.

    Raises:
        ChangeValidationError: If the value is not a valid address or prefix.
    """
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ChangeValidationError(
            f"{value!r} is not a valid IPv4 address or prefix.", value=value
        ) from exc


def _require_node(model: TwinModel, node: str) -> None:
    """Validate that ``node`` exists in the topology.

    Raises:
        ChangeValidationError: If the node is unknown.
    """
    if node not in model.topology.nodes:
        raise ChangeValidationError(
            f"Unknown target node {node!r}.",
            node=node,
            known_nodes=sorted(model.topology.nodes),
        )


def _insert_rule(policy_set: PolicySet, node: str, chain: ChainName, raw: str) -> PolicySet:
    """Insert a rule at position 1 of a chain (``iptables -I`` semantics)."""
    compiled = parse_rule(node=node, chain=chain, index=1, raw=raw)
    chain_policy = policy_set.chain(node, chain)
    return policy_set.with_chain(chain_policy.with_rules([compiled, *chain_policy.rules]))


def _remove_rule(
    policy_set: PolicySet, node: str, chain: ChainName, index: int
) -> tuple[PolicySet, object]:
    """Remove a rule by 1-based index.

    Returns:
        ``(new_policy_set, removed_rule)``.

    Raises:
        ChangeValidationError: If no rule occupies ``index``.
    """
    chain_policy = policy_set.chain(node, chain)
    target = next((r for r in chain_policy.rules if r.index == index), None)
    if target is None:
        raise ChangeValidationError(
            f"No rule at index {index} in {node}:{chain.value}.",
            node=node,
            chain=chain.value,
            index=index,
            available_indexes=[r.index for r in chain_policy.rules],
        )
    remaining = [r for r in chain_policy.rules if r.index != index]
    return policy_set.with_chain(chain_policy.with_rules(remaining)), target


def _flow_rule_string(change: ChangeRequest, action: RuleAction) -> str:
    """Render a flow-level change as an iptables argument string."""
    parts: list[str] = []
    if change.src:
        parts += ["-s", _normalise_prefix(change.src)]
    if change.dst:
        parts += ["-d", _normalise_prefix(change.dst)]
    if change.protocol:
        parts += ["-p", change.protocol.lower()]
    if change.dport is not None:
        parts += ["--dport", str(change.dport)]
    parts += ["-j", action.value]
    return " ".join(parts)


def _toggle_link(topology: Topology, node_a: str, node_b: str, up: bool) -> tuple[Topology, tuple[str, ...]]:
    """Bring a point-to-point link up or down.

    Marks both endpoint interfaces up/down, which removes their connected routes
    and makes them ineligible for next-hop resolution -- the same effect a
    severed cable has on a real forwarding plane.

    Returns:
        ``(new_topology, affected_nodes)``.

    Raises:
        ChangeValidationError: If no link connects the two nodes.
    """
    link = next(
        (
            candidate
            for candidate in topology.links
            if {candidate.a_node, candidate.b_node} == {node_a, node_b}
        ),
        None,
    )
    if link is None:
        raise ChangeValidationError(
            f"No link connects {node_a!r} and {node_b!r}.",
            node=node_a,
            neighbour=node_b,
            links=[f"{link.a_node}<->{link.b_node}" for link in topology.links],
        )

    state = InterfaceState.UP if up else InterfaceState.DOWN
    endpoints = {link.a_node: link.a_iface, link.b_node: link.b_iface}

    updated_nodes = dict(topology.nodes)
    for endpoint_node, endpoint_iface in endpoints.items():
        current = updated_nodes[endpoint_node]
        updated_nodes[endpoint_node] = current.model_copy(
            update={
                "interfaces": tuple(
                    iface.model_copy(update={"state": state}) if iface.name == endpoint_iface else iface
                    for iface in current.interfaces
                )
            }
        )

    return topology.model_copy(update={"nodes": updated_nodes}), tuple(endpoint for endpoint in endpoints)


def apply_change(model: TwinModel, change: ChangeRequest) -> ChangeOutcome:
    """Apply a candidate change and return the projected model.

    Args:
        model: The baseline twin model. Never mutated.
        change: Validated change request.

    Returns:
        A :class:`ChangeOutcome` holding the projected model.

    Raises:
        ChangeValidationError: If the change cannot be applied to this topology.
        PolicyParseError: If a raw rule supplied by the caller fails to compile.
    """
    _require_node(model, change.target_node)

    if change.change_type in (ChangeType.ALLOW_FLOW, ChangeType.DENY_FLOW):
        action = RuleAction.ACCEPT if change.change_type == ChangeType.ALLOW_FLOW else RuleAction.DROP
        raw = _flow_rule_string(change, action)
        projected = _insert_rule(model.policy_set, change.target_node, change.chain, raw)
        warnings: list[str] = []
        if change.dport is None and action == RuleAction.ACCEPT:
            warnings.append(
                "Rule permits every destination port; downstream restrictions alone "
                "determine the effective exposure."
            )
        if not change.src or _normalise_prefix(change.src or "") == "0.0.0.0/0":
            warnings.append("Rule is not source-restricted; it permits traffic from any network.")
        return ChangeOutcome(
            model=model.with_updates(policy_set=projected),
            affected_nodes=(change.target_node,),
            warnings=tuple(warnings),
        )

    if change.change_type == ChangeType.ADD_POLICY_RULE:
        assert change.rule is not None  # guaranteed by ChangeRequest validation
        projected = _insert_rule(model.policy_set, change.target_node, change.chain, change.rule)
        return ChangeOutcome(
            model=model.with_updates(policy_set=projected),
            affected_nodes=(change.target_node,),
            warnings=(
                (
                    f"Raw rule inserted at position 1 of {change.target_node}:"
                    f"{change.chain.value} (iptables -I semantics)."
                ),
            ),
        )

    if change.change_type == ChangeType.REMOVE_POLICY_RULE:
        assert change.rule_index is not None  # guaranteed by ChangeRequest validation
        projected, removed = _remove_rule(
            model.policy_set, change.target_node, change.chain, change.rule_index
        )
        return ChangeOutcome(
            model=model.with_updates(policy_set=projected),
            affected_nodes=(change.target_node,),
            warnings=(f"Removed rule: {getattr(removed, 'raw', 'unknown')}",),
        )

    if change.change_type == ChangeType.SET_LINK_STATE:
        assert change.neighbour is not None and change.enabled is not None
        _require_node(model, change.neighbour)
        topology, affected = _toggle_link(
            model.topology, change.target_node, change.neighbour, change.enabled
        )
        state = "up" if change.enabled else "down"
        return ChangeOutcome(
            model=model.with_updates(topology=topology),
            affected_nodes=affected,
            warnings=(f"Link {change.target_node}<->{change.neighbour} set {state}.",),
        )

    if change.change_type == ChangeType.COMPROMISE_NODE:
        origin = change.origin_node or change.target_node
        _require_node(model, origin)
        return ChangeOutcome(
            model=model,
            affected_nodes=(origin,),
            warnings=(f"Modelling {origin} as attacker-controlled; no policy was modified.",),
            origin_node=origin,
        )

    raise ChangeValidationError(  # pragma: no cover - exhaustiveness guard
        f"Unsupported change type {change.change_type!r}.",
        change_type=str(change.change_type),
    )


def chain_snapshot(policy_set: PolicySet, node: str, chain: ChainName) -> ChainPolicy:
    """Convenience accessor used by the API for rule listings."""
    return policy_set.chain(node, chain)


__all__ = ["ChainPolicy", "ChangeOutcome", "apply_change", "chain_snapshot"]
