"""Interactive topology map.

Renders the twin as a zone-ordered graph. Every edge is drawn as a straight line
between node positions; when a simulation result is supplied, newly opened paths
are drawn in red (new exposure), newly closed paths in green (hardening), and
nodes that a compromise origin can reach are outlined and annotated with their
exploitability weight.

The layout is deterministic (zones ordered by sensitivity tier, nodes stacked
within a zone) so the map does not reshuffle between Streamlit reruns.
"""

from __future__ import annotations

from typing import Any

import plotly.graph_objects as go

#: Zone fill colours, keyed by zone name with a fallback for custom models.
ZONE_COLOURS: dict[str, str] = {
    "perimeter": "#f0a202",
    "corp": "#2f6fed",
    "data": "#8e44ad",
}

FALLBACK_COLOURS: tuple[str, ...] = ("#2f6fed", "#16a085", "#e74c3c", "#8e44ad", "#f0a202")

NEW_EXPOSURE_COLOUR = "#e63946"
HARDENED_COLOUR = "#2a9d8f"
LINK_COLOUR = "#9aa5b1"

#: Vertical spacing between nodes inside a zone, and horizontal spacing per zone.
NODE_SPACING = 2.2
ZONE_SPACING = 2.6


def _zone_colour(zone_name: str, index: int) -> str:
    """Return a stable colour for a zone."""
    return ZONE_COLOURS.get(zone_name, FALLBACK_COLOURS[index % len(FALLBACK_COLOURS)])


def _positions(topology: dict[str, Any]) -> dict[str, tuple[float, float]]:
    """Compute deterministic (x, y) coordinates for every node.

    Args:
        topology: Topology payload from ``GET /api/v1/topology``.

    Returns:
        ``node_name -> (x, y)``.
    """
    zones = sorted(topology.get("zones", []), key=lambda zone: (zone["tier"], zone["name"]))
    zone_order = {zone["name"]: index for index, zone in enumerate(zones)}

    grouped: dict[str, list[dict[str, Any]]] = {zone["name"]: [] for zone in zones}
    for node in topology.get("nodes", []):
        grouped.setdefault(node["zone"], []).append(node)

    positions: dict[str, tuple[float, float]] = {}
    for zone_name, nodes in grouped.items():
        column = zone_order.get(zone_name, 0)
        ordered = sorted(nodes, key=lambda node: node["name"])
        span = (len(ordered) - 1) * NODE_SPACING
        for row, node in enumerate(ordered):
            y = (row * NODE_SPACING) - (span / 2.0)
            positions[node["name"]] = (column * ZONE_SPACING, y)
    return positions


def build_topology_figure(
    topology: dict[str, Any],
    delta: dict[str, Any] | None = None,
    reachable_nodes: set[str] | None = None,
    exposure_by_node: dict[str, float] | None = None,
) -> go.Figure:
    """Build the Plotly topology figure.

    Args:
        topology: Topology payload from ``GET /api/v1/topology``.
        delta: Optional ``reachability_delta`` from a simulation result.
        reachable_nodes: Nodes an attacker can reach; drawn with a red outline.
        exposure_by_node: Exploitability weight per reached node, used as an
            annotation so an operator can see *how* exposed a node is.

    Returns:
        A configured :class:`plotly.graph_objects.Figure`.
    """
    positions = _positions(topology)
    figure = go.Figure()
    exposure_by_node = exposure_by_node or {}
    reachable_nodes = reachable_nodes or set()

    opened_edges: set[tuple[str, str]] = set()
    closed_edges: set[tuple[str, str]] = set()
    if delta:
        opened_edges = {
            (path["src_node"], path["dst_node"]) for path in delta.get("newly_reachable", [])
        }
        closed_edges = {
            (path["src_node"], path["dst_node"]) for path in delta.get("newly_blocked", [])
        }

    # --- Edges --------------------------------------------------------------
    for link in topology.get("links", []):
        source, target = link["source"], link["target"]
        if source not in positions or target not in positions:
            continue
        pair = (source, target)
        reverse = (target, source)

        if pair in opened_edges or reverse in opened_edges:
            colour, dash, width = NEW_EXPOSURE_COLOUR, "dash", 4
        elif pair in closed_edges or reverse in closed_edges:
            colour, dash, width = HARDENED_COLOUR, "dash", 4
        else:
            colour, dash, width = (LINK_COLOUR, "solid", 2) if link.get("up", True) else (
                "#d0d4d9",
                "dot",
                1,
            )

        x0, y0 = positions[source]
        x1, y1 = positions[target]
        figure.add_trace(
            go.Scatter(
                x=[x0, x1],
                y=[y0, y1],
                mode="lines+text",
                line={"color": colour, "width": width, "dash": dash},
                text=["", link.get("subnet", "")],
                textposition="middle center",
                textfont={"size": 9, "color": "#6b7280"},
                hoverinfo="text",
                hovertext=f"{source} ⇄ {target}<br>subnet {link.get('subnet')}<br>"
                f"{'up' if link.get('up', True) else 'down'}",
                showlegend=False,
            )
        )

    # --- Nodes grouped by zone so the legend is meaningful -------------------
    zones = sorted(topology.get("zones", []), key=lambda zone: (zone["tier"], zone["name"]))
    for index, zone in enumerate(zones):
        members = [node for node in topology.get("nodes", []) if node["zone"] == zone["name"]]
        if not members:
            continue

        figure.add_trace(
            go.Scatter(
                x=[positions[node["name"]][0] for node in members],
                y=[positions[node["name"]][1] for node in members],
                mode="markers+text",
                name=zone["label"] + (" (crown jewel)" if zone["crown_jewel"] else ""),
                marker={
                    "size": [
                        34 if node["name"] in reachable_nodes else 26 for node in members
                    ],
                    "color": _zone_colour(zone["name"], index),
                    "symbol": ["star" if node["crown_jewel"] else "circle" for node in members],
                    "line": {
                        "width": [4 if node["name"] in reachable_nodes else 1 for node in members],
                        "color": [
                            NEW_EXPOSURE_COLOUR
                            if node["name"] in reachable_nodes
                            else "#1f2933"
                            for node in members
                        ],
                    },
                },
                text=[
                    node["name"]
                    + (
                        f"<br><span style='font-size:9px'>{exposure_by_node[node['name']]:.2f}</span>"
                        if node["name"] in exposure_by_node
                        else ""
                    )
                    for node in members
                ],
                textposition="bottom center",
                textfont={"size": 10},
                hovertext=[
                    f"<b>{node['name']}</b><br>"
                    f"role: {node['role']}<br>"
                    f"zone: {node['zone_label']} (tier {node['zone_tier']})<br>"
                    f"criticality: {node['criticality']}/5<br>"
                    f"primary IP: {node.get('primary_ip') or '-'}<br>"
                    f"container: {node['container_name']}<br>"
                    f"running: {'yes' if node['running'] else 'no'}<br>"
                    f"firewall rules: {node['policy_rule_count']}<br>"
                    f"entry point: {'yes' if node['name'] in topology.get('entrypoints', []) else 'no'}"
                    for node in members
                ],
                hoverinfo="text",
            )
        )

    figure.update_layout(
        height=460,
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "x": 0},
        xaxis={"visible": False, "range": [-1.2, max(1, len(zones)) * ZONE_SPACING]},
        yaxis={"visible": False},
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        hovermode="closest",
    )
    return figure


def render_topology_map(streamlit_module: Any, *args: Any, **kwargs: Any) -> None:
    """Render the topology figure inside Streamlit.

    Args:
        streamlit_module: The ``streamlit`` module (injected so this component
            stays importable without Streamlit installed).
        *args: Forwarded to :func:`build_topology_figure`.
        **kwargs: Forwarded to :func:`build_topology_figure`.
    """
    streamlit_module.plotly_chart(build_topology_figure(*args, **kwargs), width="stretch")


__all__ = ["build_topology_figure", "render_topology_map"]
