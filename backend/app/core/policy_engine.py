"""Firewall policy compiler and evaluator.

Two responsibilities live here:

1. **Parsing** -- compile real ``iptables`` argument strings into structured
   :class:`~app.models.policy.PolicyRule` objects.
2. **Evaluation** -- reproduce netfilter's first-match-wins semantics for a given
   packet context, including correct handling of port-agnostic flows (an
   ``ACCEPT`` with no ``--dport`` permits every port only if no earlier rule
   intercepts it, so the permitted set must be derived by evaluation rather than
   by inspecting a single rule).
"""

from __future__ import annotations

import ipaddress
import shlex
from collections.abc import Iterable
from dataclasses import dataclass

from ..models.enums import ChainName, RuleAction
from ..models.policy import ChainPolicy, PacketContext, PolicyRule, PolicySet
from .exceptions import PolicyParseError

#: Inclusive ``(low, high)`` destination-port interval.
PortRange = tuple[int, int]

#: Sorted, non-overlapping inclusive port intervals.
#: An empty tuple means "no port is reachable"; ``FULL_PORT_RANGE`` means every port.
PortRanges = tuple[PortRange, ...]

#: Every port, 0-65535 inclusive.
FULL_PORT_RANGE: PortRanges = ((0, 65535),)

#: No port at all.
NO_PORTS: PortRanges = ()

#: Probe port used to obtain a descriptive verdict for a port-agnostic flow.
WILDCARD_PROBE_PORT: int = 65535


# ---------------------------------------------------------------------------
# Interval algebra over destination ports.
#
# Ports are modelled as sets of inclusive intervals rather than enumerated
# values. This is exact (a permit for "every port except 5432" is representable),
# bounded in memory, and free of the false positives an enumeration would
# produce when a wildcard ACCEPT follows an explicit DROP.
# ---------------------------------------------------------------------------


def merge_ranges(ranges: Iterable[PortRange]) -> PortRanges:
    """Sort and coalesce a collection of intervals into a normalised set.

    Args:
        ranges: Possibly overlapping, unordered intervals.

    Returns:
        Sorted, non-overlapping intervals.
    """
    ordered = sorted(ranges)
    if not ordered:
        return NO_PORTS
    merged: list[PortRange] = [ordered[0]]
    for low, high in ordered[1:]:
        last_low, last_high = merged[-1]
        if low <= last_high + 1:
            merged[-1] = (last_low, max(last_high, high))
        else:
            merged.append((low, high))
    return tuple(merged)


def subtract_range(ranges: PortRanges, low: int, high: int) -> PortRanges:
    """Remove ``[low, high]`` from a normalised interval set."""
    remaining: list[PortRange] = []
    for range_low, range_high in ranges:
        if high < range_low or low > range_high:
            remaining.append((range_low, range_high))
            continue
        if range_low < low:
            remaining.append((range_low, low - 1))
        if range_high > high:
            remaining.append((high + 1, range_high))
    return tuple(remaining)


def subtract_ranges(base: PortRanges, remove: PortRanges) -> PortRanges:
    """Remove every interval in ``remove`` from ``base``."""
    result = base
    for low, high in remove:
        result = subtract_range(result, low, high)
    return result


def intersect_ranges(left: PortRanges, right: PortRanges) -> PortRanges:
    """Intersect two normalised interval sets.

    Intersecting per-hop permitted sets is what makes port-agnostic analysis
    sound: only ports every hop on the path agrees on are actually reachable.
    """
    result: list[PortRange] = []
    index_left = index_right = 0
    while index_left < len(left) and index_right < len(right):
        left_low, left_high = left[index_left]
        right_low, right_high = right[index_right]
        low, high = max(left_low, right_low), min(left_high, right_high)
        if low <= high:
            result.append((low, high))
        if left_high < right_high:
            index_left += 1
        else:
            index_right += 1
    return tuple(result)


def ranges_is_empty(ranges: PortRanges) -> bool:
    """Whether an interval set permits nothing."""
    return not ranges


def ranges_span_every_port(ranges: PortRanges) -> bool:
    """Whether an interval set permits every destination port."""
    return ranges == FULL_PORT_RANGE

#: Tokens that constrain nothing we model and are therefore skipped.
_IGNORED_FLAGS: frozenset[str] = frozenset(
    {
        "-m",
        "-t",
        "--ctstate",
        "--state",
        "--sport",
        "--sports",
        "--icmp-type",
        "--syn",
        "--comment",
        "--set",
        "--clamp-mss-to-pmtu",
        "--tcp-flags",
        "--helper",
    }
)

_ACTIONS: dict[str, RuleAction] = {
    "ACCEPT": RuleAction.ACCEPT,
    "DROP": RuleAction.DROP,
    "REJECT": RuleAction.REJECT,
    "LOG": RuleAction.LOG,
}

_TERMINAL_ACTIONS: frozenset[RuleAction] = frozenset(
    action for action in RuleAction if action.is_terminal
)


def _normalise_prefix(value: str) -> str:
    """Normalise a bare IP or CIDR into strict network notation.

    Args:
        value: ``10.0.0.1``, ``10.0.0.0/8`` or ``any``.

    Returns:
        A CIDR string such as ``10.0.0.1/32``.

    Raises:
        PolicyParseError: If the value is not a valid address or network.
    """
    if value in {"any", "anywhere", "0.0.0.0/0"}:
        return "0.0.0.0/0"
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise PolicyParseError(f"Invalid address or prefix: {value!r}", value=value) from exc


def parse_rule(node: str, chain: ChainName, index: int, raw: str) -> PolicyRule:
    """Compile an iptables argument string into a structured rule.

    Recognises ``-j``, ``-p``, ``-s``, ``-d``, ``-i``, ``-o``, ``--dport`` and
    ``--ctstate``. Unknown non-constraining flags are ignored so the model can
    carry comments and match extensions.

    Args:
        node: Node the rule is installed on.
        chain: Netfilter chain the rule belongs to.
        index: 1-based position within the chain (drives first-match-wins order).
        raw: iptables argument string, e.g. ``'-i eth1 -p tcp --dport 22 -j ACCEPT'``.

    Returns:
        The compiled :class:`PolicyRule`.

    Raises:
        PolicyParseError: If the rule has no terminal target or contains an
            invalid protocol, prefix, port or action.
    """
    try:
        tokens = shlex.split(raw)
    except ValueError as exc:
        raise PolicyParseError(f"Unbalanced quoting in rule: {raw!r}", rule=raw) from exc

    if not tokens:
        raise PolicyParseError("Empty firewall rule.", rule=raw)

    # Tolerate full `iptables -A CHAIN <args>` strings.
    if tokens[0] in {"-A", "--append"} and len(tokens) > 2:
        tokens = tokens[2:]

    action: RuleAction | None = None
    protocol: str | None = None
    src = "0.0.0.0/0"
    dst = "0.0.0.0/0"
    in_iface: str | None = None
    out_iface: str | None = None
    dport: int | None = None
    dport_range: tuple[int, int] | None = None
    ctstate: set[str] = set()

    position = 0
    while position < len(tokens):
        token = tokens[position]

        def _value(flag: str = token) -> str:
            """Consume and return the argument following the current flag.

            ``flag`` is bound as a default so the closure captures the current
            token by value rather than reading the loop variable later.
            """
            nonlocal position
            if position + 1 >= len(tokens):
                raise PolicyParseError(f"Flag {flag!r} requires a value.", rule=raw)
            position += 1
            return tokens[position]


        if token == "-j" or token == "--jump":
            raw_action = _value().upper()
            if raw_action not in _ACTIONS:
                raise PolicyParseError(f"Unsupported target {raw_action!r}.", rule=raw)
            action = _ACTIONS[raw_action]
        elif token == "-p" or token == "--protocol":
            protocol = _value().lower()
        elif token in {"-s", "--source"}:
            src = _normalise_prefix(_value())
        elif token in {"-d", "--destination"}:
            dst = _normalise_prefix(_value())
        elif token in {"-i", "--in-interface"}:
            in_iface = _value()
        elif token in {"-o", "--out-interface"}:
            out_iface = _value()
        elif token in {"--dport", "--destination-port"}:
            port_value = _value()
            if ":" in port_value:
                low_s, _, high_s = port_value.partition(":")
                try:
                    low, high = int(low_s), int(high_s or low_s)
                except ValueError as exc:
                    raise PolicyParseError(f"Invalid port range {port_value!r}.", rule=raw) from exc
                dport_range = (min(low, high), max(low, high))
            else:
                try:
                    dport = int(port_value)
                except ValueError as exc:
                    raise PolicyParseError(f"Invalid port {port_value!r}.", rule=raw) from exc
                if not 0 <= dport <= 65535:
                    raise PolicyParseError(f"Port out of range: {dport}.", rule=raw)
        elif token in _IGNORED_FLAGS:
            # Only consume a value when the flag actually takes one.
            if token in {"-m", "-t", "--ctstate", "--state", "--sport", "--sports",
                         "--icmp-type", "--comment", "--set", "--tcp-flags", "--helper"}:
                value = _value()
                if token in {"--ctstate", "--state"}:
                    ctstate.update(part.strip().upper() for part in value.split(",") if part.strip())
        elif token.startswith("-"):
            # Unknown flag: ignore silently to stay forward-compatible.
            pass
        position += 1

    if action is None:
        raise PolicyParseError(f"Rule has no terminal target (-j): {raw!r}", rule=raw)

    # A rule matching only established/related traffic cannot open a new
    # connection, so it is excluded from new-flow reachability.
    stateful_only = bool(ctstate) and "NEW" not in ctstate and bool(
        ctstate & {"ESTABLISHED", "RELATED", "INVALID"}
    )

    return PolicyRule(
        node=node,
        chain=chain,
        index=index,
        action=action,
        raw=raw,
        protocol=protocol,
        src=src,
        dst=dst,
        dport=dport,
        dport_range=dport_range,
        in_iface=in_iface,
        out_iface=out_iface,
        stateful_only=stateful_only,
    )


def compile_policy_set(
    declarations: dict[str, dict[str, list[str]]],
    default_policies: dict[str, dict[ChainName, RuleAction]],
) -> PolicySet:
    """Compile the model's rule declarations into a :class:`PolicySet`.

    Args:
        declarations: ``node -> chain -> [raw iptables args]``.
        default_policies: ``node -> chain -> default verdict``.

    Returns:
        A fully compiled, immutable policy set.

    Raises:
        PolicyParseError: If any rule fails to compile.
    """
    chains: dict[str, dict[ChainName, ChainPolicy]] = {}
    for node, per_chain in declarations.items():
        for chain_key, raws in per_chain.items():
            try:
                chain = ChainName(chain_key)
            except ValueError as exc:
                raise PolicyParseError(
                    f"Unknown chain {chain_key!r} declared for node {node!r}.",
                    node=node,
                    chain=chain_key,
                ) from exc
            rules = tuple(
                parse_rule(node=node, chain=chain, index=position + 1, raw=raw)
                for position, raw in enumerate(raws)
            )
            chains.setdefault(node, {})[chain] = ChainPolicy(
                node=node,
                chain=chain,
                default_action=default_policies.get(node, {}).get(chain, RuleAction.ACCEPT),
                rules=rules,
            )
    return PolicySet(chains=chains)


@dataclass(frozen=True, slots=True)
class Verdict:
    """Result of evaluating one chain for one packet context."""

    action: RuleAction
    matched_rule: PolicyRule | None
    reason: str

    @property
    def permitted(self) -> bool:
        """Whether the packet is allowed to continue."""
        return self.action == RuleAction.ACCEPT


class PolicyEngine:
    """Evaluates a compiled :class:`PolicySet` with netfilter semantics."""

    def __init__(self, policy_set: PolicySet) -> None:
        """Bind the engine to a policy set.

        Args:
            policy_set: Compiled rules to evaluate against.
        """
        self._policy = policy_set

    @property
    def policy_set(self) -> PolicySet:
        """The policy set this engine evaluates."""
        return self._policy

    def evaluate(self, node: str, chain: ChainName, ctx: PacketContext) -> Verdict:
        """Apply first-match-wins evaluation to ``ctx``.

        Args:
            node: Node whose chain is being traversed.
            chain: Chain to evaluate.
            ctx: Packet context. ``ctx.dport`` must be concrete for
                port-sensitive matching; use :meth:`permitted_ports` for
                port-agnostic flows.

        Returns:
            The terminal :class:`Verdict`.
        """
        for rule in self._policy.chain(node, chain).rules:
            if rule.stateful_only or not rule.matches(ctx):
                continue
            if not rule.action.is_terminal:
                # LOG and similar targets record the packet and fall through.
                continue
            return Verdict(
                action=rule.action,
                matched_rule=rule,
                reason=f"{chain.value} rule #{rule.index} on {node} -> {rule.action.value}",
            )

        default_action = self._policy.chain(node, chain).default_action
        if default_action in _TERMINAL_ACTIONS:
            return Verdict(
                action=default_action,
                matched_rule=None,
                reason=f"{chain.value} default policy on {node} -> {default_action.value}",
            )
        return Verdict(
            action=RuleAction.ACCEPT,
            matched_rule=None,
            reason=f"{chain.value} has no configured policy on {node}; treated as ACCEPT",
        )

    def permitted_ranges(
        self, node: str, chain: ChainName, ctx: PacketContext
    ) -> PortRanges:
        """Derive the destination ports a port-agnostic flow may actually use.

        Reproduces first-match-wins semantics in the port dimension exactly:
        each matching rule governs only the ports not already decided by an
        earlier matching rule, so a later wildcard ``ACCEPT`` cannot resurrect a
        port an earlier ``DROP`` removed.

        Args:
            node: Node whose chain is being traversed.
            chain: Chain to evaluate.
            ctx: Packet context. ``ctx.dport`` must be ``None``; the port
                dimension is derived from the rules rather than the context.

        Returns:
            Sorted, non-overlapping permitted intervals; empty when nothing is
            permitted, ``FULL_PORT_RANGE`` when every port is.
        """
        chain_policy = self._policy.chain(node, chain)
        decided: PortRanges = NO_PORTS
        permitted: PortRanges = NO_PORTS

        for rule in chain_policy.rules:
            if rule.stateful_only or not rule.matches(ctx):
                continue
            coverage = rule.port_ranges()
            fresh = intersect_ranges(coverage, subtract_ranges(FULL_PORT_RANGE, decided))
            if fresh and rule.action == RuleAction.ACCEPT:
                permitted = merge_ranges([*permitted, *fresh])
            decided = merge_ranges([*decided, *coverage])
            if ranges_span_every_port(decided):
                break

        undecided = subtract_ranges(FULL_PORT_RANGE, decided)
        if chain_policy.default_action == RuleAction.ACCEPT and undecided:
            permitted = merge_ranges([*permitted, *undecided])
        return permitted

    def describe_port_agnostic(
        self, node: str, chain: ChainName, ctx: PacketContext
    ) -> Verdict:
        """Return a descriptive verdict for a port-agnostic flow.

        Used only to explain *why* a port-agnostic path was blocked; the
        authoritative answer comes from :meth:`permitted_ranges`.
        """
        return self.evaluate(
            node, chain, ctx.model_copy(update={"dport": WILDCARD_PROBE_PORT})
        )


__all__ = [
    "FULL_PORT_RANGE",
    "NO_PORTS",
    "WILDCARD_PROBE_PORT",
    "PolicyEngine",
    "PortRange",
    "PortRanges",
    "Verdict",
    "compile_policy_set",
    "intersect_ranges",
    "merge_ranges",
    "parse_rule",
    "ranges_is_empty",
    "ranges_span_every_port",
    "subtract_ranges",
]
