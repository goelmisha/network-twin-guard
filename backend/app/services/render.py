"""Bootstrap script renderer.

Turns ``config/model.yaml`` into the per-node shell scripts that Containerlab
executes inside each container at deploy time. Because the renderer and the
solver consume the *same* validated model, the lab that gets deployed is exactly
the lab the platform simulates -- the compiled firewall rules inside the
containers are byte-for-byte the rules the reachability engine evaluates.

Scripts are written to ``config/generated/<node>.sh`` and referenced by
``corporate-twin.yml``.
"""

from __future__ import annotations

from pathlib import Path

from ..config import Settings, get_settings
from ..core.topology_loader import TwinModel, load_twin_model
from ..models.enums import ChainName, RuleAction
from ..models.topology import TopologyNode

_HEADER = """#!/bin/sh
# ---------------------------------------------------------------------------
# GENERATED FILE - DO NOT EDIT.
# Source of truth: config/model.yaml
# Regenerate with:  python3 scripts/render_policies.py
# ---------------------------------------------------------------------------
set -e

"""


def _render_node(node: TopologyNode, model: TwinModel) -> str:
    """Render the bootstrap script for a single node.

    Args:
        node: Node to render.
        model: Validated model supplying policy.

    Returns:
        The complete shell script body.
    """
    lines: list[str] = [_HEADER, f'echo "[corporate-twin] bootstrapping {node.name}"\n']

    # --- Layer 2 / layer 3 addressing ---------------------------------------
    for iface in node.interfaces:
        lines.append(f"ip link set {iface.name} up")
        lines.append(f"ip addr replace {iface.address} dev {iface.name}")
    lines.append("")

    # --- Forwarding ---------------------------------------------------------
    if node.ip_forward:
        lines.append("sysctl -qw net.ipv4.ip_forward=1")
        lines.append("")

    # --- Static routing -----------------------------------------------------
    static_routes = [route for route in node.routes if route.via]
    for route in static_routes:
        destination = "default" if route.prefix == "0.0.0.0/0" else route.prefix
        lines.append(f"ip route replace {destination} via {route.via}")
    if static_routes:
        lines.append("")

    # --- Firewall -----------------------------------------------------------
    lines.append("# Firewall policy compiled from config/model.yaml")
    for chain in ChainName:
        policy = model.policy_set.chain(node.name, chain)
        default_action = policy.default_action or RuleAction.ACCEPT
        lines.append(f"iptables -F {chain.value}")
        lines.append(f"iptables -P {chain.value} {default_action.value}")
        for rule in policy.rules:
            lines.append(f"iptables -A {chain.value} {rule.raw}")
    lines.append("")

    lines.append(f'echo "[corporate-twin] {node.name} ready"')
    return "\n".join(lines) + "\n"


def render_bootstrap_scripts(
    settings: Settings | None = None, model: TwinModel | None = None
) -> tuple[Path, ...]:
    """Render bootstrap scripts for every node in the model.

    Args:
        settings: Optional settings override (supplies the output directory).
        model: Optional pre-loaded model, avoiding a redundant YAML parse.

    Returns:
        The paths written, in node order.
    """
    cfg = settings or get_settings()
    twin = model or load_twin_model(cfg)
    cfg.generated_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for node in twin.topology.iter_nodes():
        target = cfg.generated_dir / f"{node.name}.sh"
        target.write_text(_render_node(node, twin), encoding="utf-8")
        target.chmod(0o755)
        written.append(target)
    return tuple(written)


__all__ = ["render_bootstrap_scripts"]
