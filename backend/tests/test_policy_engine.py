"""Unit tests for the firewall policy compiler and evaluator."""

from __future__ import annotations

import pytest

from app.core.exceptions import PolicyParseError
from app.core.policy_engine import (
    FULL_PORT_RANGE,
    PolicyEngine,
    compile_policy_set,
    intersect_ranges,
    merge_ranges,
    parse_rule,
    subtract_ranges,
)
from app.models.enums import ChainName, RuleAction
from app.models.policy import PacketContext


def test_parses_interfaces_prefixes_protocol_and_port() -> None:
    """A fully specified rule is decomposed into structured fields."""
    rule = parse_rule(
        "perimeter-gateway",
        ChainName.FORWARD,
        2,
        "-i eth1 -o eth2 -s 10.10.10.0/24 -d 10.10.20.50/32 -p tcp --dport 5432 -j ACCEPT",
    )

    assert rule.action is RuleAction.ACCEPT
    assert rule.protocol == "tcp"
    assert rule.in_iface == "eth1"
    assert rule.out_iface == "eth2"
    assert rule.src == "10.10.10.0/24"
    assert rule.dst == "10.10.20.50/32"
    assert rule.dport == 5432
    assert rule.stateful_only is False


def test_bare_host_address_is_normalised_to_a_host_prefix() -> None:
    """A bare IP is treated as a /32, matching iptables semantics."""
    rule = parse_rule("n", ChainName.INPUT, 1, "-s 10.0.0.5 -j ACCEPT")
    assert rule.src == "10.0.0.5/32"
    assert rule.dst == "0.0.0.0/0"


def test_port_range_is_parsed() -> None:
    """Ranges populate ``dport_range`` rather than ``dport``."""
    rule = parse_rule("n", ChainName.INPUT, 1, "-p tcp --dport 8000:8010 -j ACCEPT")
    assert rule.dport_range == (8000, 8010)
    assert rule.dport is None
    assert rule.port_ranges() == ((8000, 8010),)


def test_established_only_rule_cannot_open_a_new_connection() -> None:
    """A conntrack rule without NEW is flagged and excluded from new flows."""
    rule = parse_rule("n", ChainName.FORWARD, 1, "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    assert rule.stateful_only is True


def test_new_connection_rule_is_not_treated_as_stateful() -> None:
    """A rule that explicitly matches NEW is a real permit."""
    rule = parse_rule("n", ChainName.FORWARD, 1, "-m conntrack --ctstate NEW -j ACCEPT")
    assert rule.stateful_only is False


def test_rule_without_a_target_is_rejected() -> None:
    """A rule with no ``-j`` cannot be compiled."""
    with pytest.raises(PolicyParseError) as excinfo:
        parse_rule("n", ChainName.INPUT, 1, "-p tcp --dport 22")
    assert "terminal target" in excinfo.value.detail


def test_invalid_prefix_is_rejected() -> None:
    """A malformed address produces an actionable parse error."""
    with pytest.raises(PolicyParseError):
        parse_rule("n", ChainName.INPUT, 1, "-s 10.0.0.999 -j ACCEPT")


def test_invalid_action_is_rejected() -> None:
    """An unsupported target is rejected rather than silently ignored."""
    with pytest.raises(PolicyParseError):
        parse_rule("n", ChainName.INPUT, 1, "-j TELEPORT")


def test_empty_rule_is_rejected() -> None:
    """An empty rule string is rejected."""
    with pytest.raises(PolicyParseError):
        parse_rule("n", ChainName.INPUT, 1, "   ")


def test_unknown_extension_flags_are_tolerated() -> None:
    """Match extensions that do not constrain the modelled fields are ignored."""
    rule = parse_rule(
        "n", ChainName.INPUT, 1, "-m tcp -p tcp --dport 443 --syn -m comment --comment 'web' -j ACCEPT"
    )
    assert rule.dport == 443
    assert rule.action is RuleAction.ACCEPT


def test_first_matching_rule_wins() -> None:
    """Evaluation stops at the first match, honouring rule order."""
    policy = compile_policy_set(
        {"n": {"INPUT": ["-s 10.0.0.0/24 -j DROP", "-s 10.0.0.0/24 -j ACCEPT"]}},
        {"n": {ChainName.INPUT: RuleAction.ACCEPT}},
    )
    engine = PolicyEngine(policy)
    verdict = engine.evaluate(
        "n",
        ChainName.INPUT,
        PacketContext(src_ip="10.0.0.9", dst_ip="10.0.0.1", protocol="tcp", dport=22),
    )
    assert verdict.action is RuleAction.DROP
    assert verdict.matched_rule is not None
    assert verdict.matched_rule.index == 1


def test_chain_default_applies_when_no_rule_matches() -> None:
    """The chain's default verdict governs unmatched traffic."""
    policy = compile_policy_set(
        {"n": {"INPUT": ["-p tcp --dport 22 -j ACCEPT"]}},
        {"n": {ChainName.INPUT: RuleAction.DROP}},
    )
    verdict = PolicyEngine(policy).evaluate(
        "n",
        ChainName.INPUT,
        PacketContext(src_ip="10.0.0.9", dst_ip="10.0.0.1", protocol="tcp", dport=443),
    )
    assert verdict.action is RuleAction.DROP
    assert "default policy" in verdict.reason


def test_log_rules_fall_through() -> None:
    """A non-terminal LOG target does not decide the verdict."""
    policy = compile_policy_set(
        {"n": {"INPUT": ["-p tcp --dport 22 -j LOG", "-p tcp --dport 22 -j DROP"]}},
        {"n": {ChainName.INPUT: RuleAction.ACCEPT}},
    )
    verdict = PolicyEngine(policy).evaluate(
        "n",
        ChainName.INPUT,
        PacketContext(src_ip="10.0.0.9", dst_ip="10.0.0.1", protocol="tcp", dport=22),
    )
    assert verdict.action is RuleAction.DROP


def _permitted(declarations: list[str], default: RuleAction, chain: ChainName = ChainName.FORWARD):
    """Compile a chain and return its permitted port intervals for a tcp flow."""
    policy = compile_policy_set({"n": {chain.value: declarations}}, {"n": {chain: default}})
    return PolicyEngine(policy).permitted_ranges(
        "n",
        chain,
        PacketContext(src_ip="10.0.0.9", dst_ip="10.0.0.1", protocol="tcp"),
    )


def test_permitted_ranges_detects_a_wildcard_permit() -> None:
    """A port-agnostic ACCEPT permits every port."""
    assert _permitted(["-p tcp -j ACCEPT"], RuleAction.DROP) == FULL_PORT_RANGE


def test_permitted_ranges_is_empty_when_everything_is_dropped() -> None:
    """A default-deny chain with no permits yields no reachable port."""
    assert _permitted([], RuleAction.DROP) == ()


def test_wildcard_permit_cannot_resurrect_a_dropped_port() -> None:
    """A later catch-all permit must not mask an earlier explicit DROP.

    This is the case a naive port enumeration gets wrong, and it is exactly the
    shape of a rule an operator adds when tightening a host firewall.
    """
    assert _permitted(
        ["-p tcp --dport 5432 -j DROP", "-p tcp -j ACCEPT"], RuleAction.DROP
    ) == ((0, 5431), (5433, 65535))


def test_first_matching_rule_governs_the_port_dimension() -> None:
    """Ports decided by an earlier rule are not revisited by a later one."""
    assert _permitted(["-p tcp --dport 22 -j ACCEPT", "-p tcp -j DROP"], RuleAction.DROP) == (
        (22, 22),
    )


def test_chain_default_is_folded_into_the_permitted_ranges() -> None:
    """Undecided ports fall through to the chain default verdict."""
    # Default ACCEPT: the explicit permit adds nothing the default would not.
    assert _permitted(["-p tcp --dport 22 -j ACCEPT"], RuleAction.ACCEPT) == FULL_PORT_RANGE
    # Default ACCEPT with an explicit drop: everything except the dropped port.
    assert _permitted(["-p tcp --dport 22 -j DROP"], RuleAction.ACCEPT) == (
        (0, 21),
        (23, 65535),
    )


def test_intersect_ranges_keeps_only_agreed_ports() -> None:
    """Intersection is sound: only ports every hop agrees on survive."""
    assert intersect_ranges(FULL_PORT_RANGE, ((5432, 5432),)) == ((5432, 5432),)
    assert intersect_ranges(((22, 22), (5432, 5432)), ((80, 80), (5432, 5432))) == (
        (5432, 5432),
    )
    assert intersect_ranges(((22, 22),), ((80, 80),)) == ()
    assert intersect_ranges(((0, 100),), ((50, 200),)) == ((50, 100),)


def test_merge_ranges_coalesces_touching_intervals() -> None:
    """Adjacent and overlapping intervals are normalised into one."""
    assert merge_ranges([(0, 21), (22, 22), (23, 65535)]) == FULL_PORT_RANGE
    assert merge_ranges([(80, 90), (10, 20)]) == ((10, 20), (80, 90))
    assert merge_ranges([]) == ()


def test_subtract_ranges_removes_the_intersection() -> None:
    """Subtraction removes precisely the supplied intervals."""
    assert subtract_ranges(FULL_PORT_RANGE, ((0, 1000),)) == ((1001, 65535),)
    assert subtract_ranges(((0, 100),), ((200, 300),)) == ((0, 100),)
    assert subtract_ranges(((0, 100),), ((0, 100),)) == ()
