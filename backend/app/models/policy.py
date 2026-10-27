"""Firewall policy domain model.

Rules are authored as real ``iptables`` argument strings (see
``config/model.yaml``). :func:`app.core.policy_engine.parse_rule` compiles them
into the structured :class:`PolicyRule` objects defined here, which the solver
evaluates with genuine first-match-wins semantics.
"""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, ConfigDict, Field

from .enums import ChainName, RuleAction

#: Inclusive ``(low, high)`` port interval.
PortRange = tuple[int, int]

#: Sorted, non-overlapping set of inclusive port intervals.
#: An empty tuple means "no port", ``((0, 65535),)`` means "every port".
PortRanges = tuple[PortRange, ...]

#: Every port, 0-65535 inclusive.
FULL_PORT_RANGE: PortRanges = ((0, 65535),)

#: No port at all.
NO_PORTS: PortRanges = ()


class PacketContext(BaseModel):
    """The packet 5-tuple plus interfaces, as netfilter would see it."""

    model_config = ConfigDict(frozen=True)

    src_ip: str = Field(description="Original source address.")
    dst_ip: str = Field(description="Original destination address.")
    protocol: str = Field(default="tcp", description="tcp|udp|icmp.")
    dport: int | None = Field(
        default=None, description="Destination port; ``None`` when the flow is port-agnostic."
    )
    in_iface: str | None = Field(default=None, description="Ingress interface.")
    out_iface: str | None = Field(default=None, description="Egress interface.")


class PolicyRule(BaseModel):
    """A single compiled firewall rule."""

    model_config = ConfigDict(frozen=True)

    node: str = Field(description="Node the rule is installed on.")
    chain: ChainName = Field(description="Netfilter chain the rule lives in.")
    index: int = Field(ge=1, description="1-based position within the chain.")
    action: RuleAction = Field(description="Terminal verdict.")
    raw: str = Field(description="Original iptables argument string, for audit.")
    protocol: str | None = Field(default=None, description="Matched protocol, or None for any.")
    src: str = Field(default="0.0.0.0/0", description="Matched source prefix.")
    dst: str = Field(default="0.0.0.0/0", description="Matched destination prefix.")
    dport: int | None = Field(default=None, description="Matched destination port, or None for any.")
    dport_range: tuple[int, int] | None = Field(
        default=None, description="Inclusive destination port range when matched by range."
    )
    in_iface: str | None = Field(default=None, description="Matched ingress interface.")
    out_iface: str | None = Field(default=None, description="Matched egress interface.")
    stateful_only: bool = Field(
        default=False,
        description=(
            "True when the rule only matches established/related traffic. Such rules "
            "cannot open a new connection and are excluded from new-flow reachability."
        ),
    )
    description: str | None = Field(default=None, description="Operator-facing note.")

    # -- Matching ------------------------------------------------------------

    def _port_match(self, ctx: PacketContext) -> bool:
        """Whether the rule's port constraints admit the packet's destination port."""
        if self.dport is None and self.dport_range is None:
            return True
        if self.dport_range is not None:
            # A port-agnostic context is expanded by the engine before matching,
            # so a concrete port is always available here.
            if ctx.dport is None:
                return True
            return self.dport_range[0] <= ctx.dport <= self.dport_range[1]
        return ctx.dport is None or ctx.dport == self.dport

    def matches(self, ctx: PacketContext) -> bool:
        """Evaluate whether this rule matches ``ctx``.

        Note:
            Port matching is intentionally permissive when ``ctx.dport`` is
            ``None``; the reachability engine expands port-agnostic flows into
            concrete candidate ports before calling this method, so the
            permissive branch only affects coverage detection.
        """
        if self.protocol is not None and self.protocol != ctx.protocol:
            return False
        if self.in_iface is not None and self.in_iface != ctx.in_iface:
            return False
        if self.out_iface is not None and self.out_iface != ctx.out_iface:
            return False
        if ipaddress.ip_address(ctx.src_ip) not in ipaddress.ip_network(self.src, strict=False):
            return False
        if ipaddress.ip_address(ctx.dst_ip) not in ipaddress.ip_network(self.dst, strict=False):
            return False
        return self._port_match(ctx)

    # -- Port coverage -------------------------------------------------------

    def port_ranges(self) -> PortRanges:
        """The destination ports this rule matches, as inclusive intervals.

        Returns:
            ``FULL_PORT_RANGE`` for a port-agnostic rule, otherwise the rule's
            ``--dport`` or ``--dport`` range as a single interval.
        """
        if self.dport_range is not None:
            low, high = self.dport_range
            return ((low, high),)
        if self.dport is None:
            return FULL_PORT_RANGE
        return ((self.dport, self.dport),)


class ChainPolicy(BaseModel):
    """Ordered rules plus the default verdict for one chain of one node."""

    model_config = ConfigDict(frozen=True)

    node: str = Field(description="Owning node.")
    chain: ChainName = Field(description="Chain name.")
    default_action: RuleAction = Field(
        default=RuleAction.ACCEPT, description="Verdict when no rule matches."
    )
    rules: tuple[PolicyRule, ...] = Field(default_factory=tuple, description="Ordered rules.")

    def with_rules(self, rules: list[PolicyRule]) -> ChainPolicy:
        """Return a copy carrying a new ordered rule list.

        Args:
            rules: Replacement rules; indexes are renumbered from 1.

        Returns:
            A new :class:`ChainPolicy`; the original is left untouched.
        """
        renumbered = tuple(rule.model_copy(update={"index": i + 1}) for i, rule in enumerate(rules))
        return self.model_copy(update={"rules": renumbered})


class PolicySet(BaseModel):
    """Every chain of every node: ``chain_index[node][chain] -> ChainPolicy``."""

    model_config = ConfigDict(frozen=True)

    chains: dict[str, dict[ChainName, ChainPolicy]] = Field(
        default_factory=dict, description="Nested map of node -> chain -> policy."
    )

    def chain(self, node: str, chain: ChainName) -> ChainPolicy:
        """Return a chain's policy, defaulting to an empty ACCEPT chain."""
        return self.chains.get(node, {}).get(
            chain, ChainPolicy(node=node, chain=chain, default_action=RuleAction.ACCEPT, rules=())
        )

    def node_chains(self, node: str) -> dict[ChainName, ChainPolicy]:
        """All chains configured for ``node``."""
        return self.chains.get(node, {})

    def all_rules(self) -> list[PolicyRule]:
        """Every rule across every node and chain, in stable order."""
        out: list[PolicyRule] = []
        for node in sorted(self.chains):
            for chain in (ChainName.INPUT, ChainName.FORWARD, ChainName.OUTPUT):
                out.extend(self.chain(node, chain).rules)
        return out

    def with_chain(self, policy: ChainPolicy) -> PolicySet:
        """Return a copy with one chain replaced.

        Args:
            policy: The replacement chain policy.

        Returns:
            A new :class:`PolicySet`; the original is left untouched so baseline
            snapshots remain valid after a candidate change is simulated.
        """
        updated = {node: dict(chains) for node, chains in self.chains.items()}
        updated.setdefault(policy.node, {})[policy.chain] = policy
        return self.model_copy(update={"chains": updated})
