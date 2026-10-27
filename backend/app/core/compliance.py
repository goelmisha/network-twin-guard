"""Compliance control evaluation.

Each control is an independent, explainable predicate over a solved snapshot.
The report is designed to be attached to a change ticket: every finding names
what was observed, why it matters, and how to fix it.
"""

from __future__ import annotations

import ipaddress

from ..models.enums import ChainName, ComplianceStatus, RiskLevel, RuleAction
from ..models.simulation import ComplianceFinding, ComplianceReport
from ..models.snapshot import Snapshot
from . import risk as risk_module

#: Controls that model a cleartext or legacy management protocol.
LEGACY_MANAGEMENT_PORTS: frozenset[int] = frozenset({21, 23, 512, 513, 514})

#: Exposure above which a reachable path into a crown jewel is a failure.
SENSITIVE_EXPOSURE_THRESHOLD: float = 0.70


def _control_default_deny_forward(snapshot: Snapshot) -> ComplianceFinding:
    """CTL-001: every forwarding node must default-deny the FORWARD chain."""
    offenders = sorted(
        name
        for name, node in snapshot.topology.nodes.items()
        if node.ip_forward
        and snapshot.policy_set.chain(name, ChainName.FORWARD).default_action == RuleAction.ACCEPT
    )
    return ComplianceFinding(
        control_id="CTL-001",
        title="Forwarding nodes default-deny inter-zone traffic",
        status=ComplianceStatus.PASS if not offenders else ComplianceStatus.FAIL,
        severity=RiskLevel.HIGH,
        detail=(
            "All forwarding nodes default to DROP in the FORWARD chain."
            if not offenders
            else f"FORWARD chain defaults to ACCEPT on: {', '.join(offenders)}."
        ),
        remediation="Set the FORWARD chain default policy to DROP and permit flows explicitly.",
        affected_nodes=tuple(offenders),
    )


def _control_default_deny_input(snapshot: Snapshot) -> ComplianceFinding:
    """CTL-002: every node must default-deny inbound traffic."""
    offenders = sorted(
        name
        for name, node in snapshot.topology.nodes.items()
        if snapshot.policy_set.chain(name, ChainName.INPUT).default_action == RuleAction.ACCEPT
    )
    return ComplianceFinding(
        control_id="CTL-002",
        title="Host firewalls default-deny inbound traffic",
        status=ComplianceStatus.PASS if not offenders else ComplianceStatus.FAIL,
        severity=RiskLevel.HIGH,
        detail=(
            "All nodes default to DROP in the INPUT chain."
            if not offenders
            else (
                f"INPUT chain defaults to ACCEPT on: {', '.join(offenders)}. These hosts rely "
                "entirely on upstream filtering, so any single gateway misconfiguration is "
                "directly exploitable."
            )
        ),
        remediation="Set each host's INPUT default policy to DROP and allow only required services.",
        affected_nodes=tuple(offenders),
    )


def _control_no_unrestricted_permit(snapshot: Snapshot) -> ComplianceFinding:
    """CTL-003: no rule may permit any protocol from any source to any destination.

    A protocol-restricted rule (for example an ICMP diagnostic permit) is not an
    unrestricted permit, so the protocol must also be unconstrained for a rule to
    trip this control.
    """
    offenders: list[str] = []
    for rule in snapshot.policy_set.all_rules():
        if rule.stateful_only or rule.action != RuleAction.ACCEPT:
            continue
        if rule.src != "0.0.0.0/0" or rule.dst != "0.0.0.0/0":
            continue
        if rule.protocol is not None:
            continue
        if rule.dport is None and rule.dport_range is None:
            offenders.append(f"{rule.node}:{rule.chain.value}#{rule.index}")

    return ComplianceFinding(
        control_id="CTL-003",
        title="No unrestricted any-to-any permit exists",
        status=ComplianceStatus.PASS if not offenders else ComplianceStatus.FAIL,
        severity=RiskLevel.HIGH,
        detail=(
            "No rule permits any source to any destination on every port."
            if not offenders
            else f"Unrestricted permits found at: {', '.join(offenders)}."
        ),
        remediation="Scope each permit to a source prefix, destination and port.",
        affected_nodes=tuple(sorted({entry.split(":")[0] for entry in offenders})),
    )


def _control_crown_jewel_services(snapshot: Snapshot) -> ComplianceFinding:
    """CTL-004: no crown-jewel service is reachable from a user-facing zone.

    Infrastructure zones are excluded: a branch gateway legitimately forwards
    toward the data zone, so the meaningful question is whether an *endpoint*
    zone can reach a crown-jewel service on an exploitable port.
    """
    violations: list[str] = []
    affected: set[str] = set()
    for path in snapshot.reachable_paths():
        destination = snapshot.topology.node(path.dst_node)
        if not destination.is_crown_jewel:
            continue
        source_zone = snapshot.topology.zone_of(path.src_node)
        destination_zone = snapshot.topology.zone_of(path.dst_node)
        if source_zone.name == destination_zone.name or not source_zone.user_facing:
            continue
        exposure = risk_module.path_exposure(path)
        if exposure >= SENSITIVE_EXPOSURE_THRESHOLD:
            violations.append(
                f"{path.src_node} -> {path.dst_node} ({path.flow_name}, exposure {exposure:.2f})"
            )
            affected.update({path.src_node, path.dst_node})

    return ComplianceFinding(
        control_id="CTL-004",
        title="Crown-jewel services are not exposed cross-zone",
        status=ComplianceStatus.PASS if not violations else ComplianceStatus.FAIL,
        severity=RiskLevel.HIGH,
        detail=(
            "No high-sensitivity service on a crown-jewel asset is reachable from another zone."
            if not violations
            else "High-sensitivity cross-zone reachability: " + "; ".join(sorted(violations)) + "."
        ),
        remediation=(
            "Restrict crown-jewel services to the specific application port and source subnet, "
            "and add a host-level default-deny as defence in depth."
        ),
        affected_nodes=tuple(sorted(affected)),
    )


def _control_management_plane(snapshot: Snapshot) -> ComplianceFinding:
    """CTL-005: SSH must not be reachable from user-facing zones."""
    # Construct IPv4 networks explicitly: the control compares prefixes and the
    # platform models IPv4 exclusively, so an IPv6 literal should raise rather
    # than silently compare across families.
    user_networks: list[ipaddress.IPv4Network] = [
        ipaddress.IPv4Network(iface.subnet)
        for name, node in snapshot.topology.nodes.items()
        if snapshot.topology.zone_of(name).user_facing
        for iface in node.interfaces
    ]

    offenders: list[str] = []
    affected: set[str] = set()
    for rule in snapshot.policy_set.all_rules():
        if rule.stateful_only or rule.action != RuleAction.ACCEPT or rule.dport != 22:
            continue
        if rule.chain != ChainName.INPUT:
            continue
        rule_network = ipaddress.IPv4Network(rule.src)
        if rule_network.prefixlen == 0:
            offenders.append(f"{rule.node}:{rule.chain.value}#{rule.index} (any source)")
            affected.add(rule.node)
            continue
        if any(network.subnet_of(rule_network) for network in user_networks):
            offenders.append(
                f"{rule.node}:{rule.chain.value}#{rule.index} (source {rule.src} covers a user zone)"
            )
            affected.add(rule.node)

    return ComplianceFinding(
        control_id="CTL-005",
        title="Management access is restricted to out-of-band sources",
        status=ComplianceStatus.PASS if not offenders else ComplianceStatus.FAIL,
        severity=RiskLevel.HIGH,
        detail=(
            "No management service is reachable from a user-facing zone subnet."
            if not offenders
            else f"Management exposure found at: {', '.join(offenders)}."
        ),
        remediation="Restrict management protocols to a dedicated out-of-band subnet or jump host.",
        affected_nodes=tuple(sorted(affected)),
    )


def _control_no_blanket_into_crown_jewels(snapshot: Snapshot) -> ComplianceFinding:
    """CTL-006: no rule may permit an entire subnet into a crown jewel on all ports."""
    offenders: list[str] = []
    affected: set[str] = set()
    for rule in snapshot.policy_set.all_rules():
        if rule.stateful_only or rule.action != RuleAction.ACCEPT:
            continue
        if rule.dport is not None or rule.dport_range is not None:
            continue
        # Only transport-protocol permits are "every port"; an ICMP diagnostic
        # permit does not expose a port range.
        if rule.protocol is not None and rule.protocol not in {"tcp", "udp"}:
            continue
        rule_dest = ipaddress.IPv4Network(rule.dst)
        for name, node in snapshot.topology.nodes.items():
            if not node.is_crown_jewel:
                continue
            for iface in node.interfaces:
                # The rule applies to the crown-jewel host if it covers its address.
                if ipaddress.ip_address(iface.ip) in rule_dest:
                    offenders.append(
                        f"{rule.node}:{rule.chain.value}#{rule.index} permits {rule.src} -> "
                        f"{rule.dst} on every port"
                    )
                    affected.update({rule.node, name})

    return ComplianceFinding(
        control_id="CTL-006",
        title="Crown-jewel zones are not reachable on all ports",
        status=ComplianceStatus.PASS if not offenders else ComplianceStatus.FAIL,
        severity=RiskLevel.HIGH,
        detail=(
            "Every permit into a crown-jewel zone is port-scoped."
            if not offenders
            else "Blanket permits into crown-jewel zones: " + "; ".join(sorted(set(offenders))) + "."
        ),
        remediation="Replace blanket permits with explicit protocol and port restrictions.",
        affected_nodes=tuple(sorted(affected)),
    )


def _control_no_legacy_protocols(snapshot: Snapshot) -> ComplianceFinding:
    """CTL-007: no cleartext legacy management protocol may be permitted."""
    offenders: list[str] = []
    affected: set[str] = set()
    for rule in snapshot.policy_set.all_rules():
        if rule.stateful_only or rule.action != RuleAction.ACCEPT:
            continue
        ports: set[int] = set()
        if rule.dport is not None:
            ports.add(rule.dport)
        if rule.dport_range is not None:
            low, high = rule.dport_range
            if high - low <= 1024:
                ports.update(range(low, high + 1))
        if ports & LEGACY_MANAGEMENT_PORTS:
            offenders.append(f"{rule.node}:{rule.chain.value}#{rule.index}")
            affected.add(rule.node)

    return ComplianceFinding(
        control_id="CTL-007",
        title="No cleartext legacy management protocols are permitted",
        status=ComplianceStatus.PASS if not offenders else ComplianceStatus.FAIL,
        severity=RiskLevel.MEDIUM,
        detail=(
            "No permit allows Telnet, FTP or legacy r-services."
            if not offenders
            else f"Legacy protocol permits found at: {', '.join(offenders)}."
        ),
        remediation="Remove the permit and use SSH or a managed jump host instead.",
        affected_nodes=tuple(sorted(affected)),
    )


_CONTROLS = (
    _control_default_deny_forward,
    _control_default_deny_input,
    _control_no_unrestricted_permit,
    _control_crown_jewel_services,
    _control_management_plane,
    _control_no_blanket_into_crown_jewels,
    _control_no_legacy_protocols,
)


def evaluate_compliance(snapshot: Snapshot) -> ComplianceReport:
    """Evaluate every compliance control against a solved snapshot.

    Args:
        snapshot: Snapshot to assess.

    Returns:
        A :class:`ComplianceReport` with a percentage score and per-control
        findings.
    """
    findings = tuple(control(snapshot) for control in _CONTROLS)
    passed = sum(1 for f in findings if f.status == ComplianceStatus.PASS)
    failed = sum(1 for f in findings if f.status == ComplianceStatus.FAIL)
    warned = sum(1 for f in findings if f.status == ComplianceStatus.WARN)
    total = len(findings) or 1

    return ComplianceReport(
        lab_name=snapshot.lab_name,
        score_pct=round(100.0 * passed / total, 2),
        passed=passed,
        failed=failed,
        warned=warned,
        findings=findings,
    )


__all__ = [
    "LEGACY_MANAGEMENT_PORTS",
    "SENSITIVE_EXPOSURE_THRESHOLD",
    "evaluate_compliance",
]
