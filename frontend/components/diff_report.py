"""Before/after differential reporting components.

Presents a simulation result as an operator reads it:

* a colour-coded risk banner (green = hardened, amber = no net change, red =
  regression) with baseline and projected scores side by side;
* the plain-language summary the backend generated;
* tabular detail of what opened, what closed, and what stayed open but became
  more exploitable;
* the firewall rule delta and the compliance findings implicated by the change.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

#: Verdict -> (label, hex colour) used for the banner and status chips.
VERDICT_STYLES: dict[str, tuple[str, str]] = {
    "regressed": ("🔴 REGRESSION — do not deploy", "#e63946"),
    "improved": ("🟢 HARDENING — exposure reduced", "#2a9d8f"),
    "neutral": ("🟡 NO NET CHANGE", "#f0a202"),
}

#: Risk level -> (label, hex colour).
RISK_STYLES: dict[str, tuple[str, str]] = {
    "high": ("HIGH", "#e63946"),
    "medium": ("MEDIUM", "#f0a202"),
    "low": ("LOW", "#2a9d8f"),
}


def format_ports(ranges: list[list[int]] | None) -> str:
    """Render reachable port intervals as a short human-readable string.

    Args:
        ranges: Inclusive ``[low, high]`` intervals from the API.

    Returns:
        ``"all ports"``, a compact list such as ``"22, 445"``, or ``"none"``.
    """
    if not ranges:
        return "none"
    if ranges == [[0, 65535]]:
        return "all ports"
    parts: list[str] = []
    for low, high in ranges:
        parts.append(str(low) if low == high else f"{low}-{high}")
    return ", ".join(parts)


def paths_frame(paths: list[dict[str, Any]]) -> pd.DataFrame:
    """Convert solved paths into a display table.

    Args:
        paths: Path records from a delta.

    Returns:
        A pandas DataFrame ordered by destination, ready for ``st.dataframe``.
    """
    rows = [
        {
            "Source": path["src_node"],
            "Destination": path["dst_node"],
            "Flow": path["flow_name"],
            "Reachable ports": format_ports(path.get("reachable_ports")),
            "Hops": path["hops"],
            "Path": " → ".join(path["path"]),
        }
        for path in paths
    ]
    frame = pd.DataFrame(rows)
    if not frame.empty:
        frame = frame.sort_values(["Destination", "Flow"]).reset_index(drop=True)
    return frame


def render_risk_banner(st: Any, risk: dict[str, Any]) -> None:
    """Render the baseline-versus-projected risk banner.

    Args:
        st: The ``streamlit`` module.
        risk: The ``risk`` block of a simulation result.
    """
    direction = risk["direction"]
    label, colour = VERDICT_STYLES.get(direction, ("UNKNOWN", "#6b7280"))
    baseline = risk["baseline"]
    projected = risk["projected"]

    st.markdown(
        f"<div style='padding:12px 16px;border-radius:8px;border-left:6px solid {colour};"
        f"background:rgba(0,0,0,0.03);margin-bottom:12px'>"
        f"<span style='font-size:1.05rem;font-weight:600;color:{colour}'>{label}</span>"
        f"<div style='margin-top:6px;color:#6b7280;font-size:0.9rem'>"
        f"Risk {baseline['risk_score']:.1f} → <b>{projected['risk_score']:.1f}</b> "
        f"({risk['risk_level_transition']}) &nbsp;·&nbsp; "
        f"Blast radius {baseline['blast_radius_pct']:.1f}% → "
        f"<b>{projected['blast_radius_pct']:.1f}%</b>"
        f"</div></div>",
        unsafe_allow_html=True,
    )

    columns = st.columns(4)
    baseline_label = RISK_STYLES.get(baseline["risk_level"], ("?", "#6b7280"))[0]
    columns[0].metric("Baseline risk", f"{baseline['risk_score']:.1f}", baseline_label)
    columns[1].metric(
        "Projected risk",
        f"{projected['risk_score']:.1f}",
        f"{risk['score_delta']:+.1f}",
        delta_color="inverse",
    )
    columns[2].metric(
        "Blast radius",
        f"{projected['blast_radius_pct']:.1f}%",
        f"{risk['blast_radius_delta']:+.1f} pp",
        delta_color="inverse",
    )
    columns[3].metric(
        "Crown jewels reached",
        str(len(projected["crown_jewels_reached"])),
        ", ".join(projected["crown_jewels_reached"]) or "none",
        delta_color="off",
    )

    if projected["findings"]:
        with st.expander("Why this score", expanded=direction == "regressed"):
            for finding in projected["findings"]:
                st.markdown(f"- {finding}")


def render_diff_report(st: Any, simulation: dict[str, Any]) -> None:
    """Render the complete before/after report for a simulation.

    Args:
        st: The ``streamlit`` module.
        simulation: A ``SimulationResult`` payload.
    """
    st.subheader("Pre-change validation report")
    st.caption(simulation["summary"])

    render_risk_banner(st, simulation["risk"])

    delta = simulation["reachability_delta"]
    opened = delta["newly_reachable"]
    closed = delta["newly_blocked"]
    widened = delta.get("exposure_widened", [])

    st.markdown("#### Reachability impact")
    counts = st.columns(4)
    counts[0].metric("Paths opened", len(opened))
    counts[1].metric("Paths closed", len(closed))
    counts[2].metric("Paths widened", len(widened))
    counts[3].metric("Still open", delta["unchanged_reachable"])

    if opened:
        st.error(f"**{len(opened)} new exposure path(s)** — traffic that is currently blocked "
                 f"would succeed after this change.", icon="🚨")
        st.dataframe(paths_frame(opened), hide_index=True, width="stretch")
    else:
        st.success("No previously blocked path becomes reachable.", icon="✅")

    if widened:
        st.warning(
            f"**{len(widened)} existing path(s) become more exploitable** without changing "
            "reachability. This is the failure mode binary checks miss.",
            icon="⚠️",
        )
        st.dataframe(paths_frame(widened), hide_index=True, width="stretch")

    if closed:
        st.success(f"**{len(closed)} path(s) would be closed** — this change hardens the estate.",
                   icon="🛡️")
        st.dataframe(paths_frame(closed), hide_index=True, width="stretch")

    st.markdown("#### Firewall rule delta")
    policy_delta = simulation["policy_delta"]
    added = policy_delta["added"]
    removed = policy_delta["removed"]

    added_tab, removed_tab = st.tabs([f"Added ({len(added)})", f"Removed ({len(removed)})"])
    with added_tab:
        if added:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Node": rule["node"],
                            "Chain": rule["chain"],
                            "Position": rule["index"],
                            "Rule": rule["raw"],
                        }
                        for rule in added
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
        else:
            st.caption("No rules added.")
    with removed_tab:
        if removed:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Node": rule["node"],
                            "Chain": rule["chain"],
                            "Was at": rule["index"],
                            "Rule": rule["raw"],
                        }
                        for rule in removed
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
        else:
            st.caption("No rules removed.")

    for key, change in policy_delta.get("chain_defaults_changed", {}).items():
        st.warning(f"Chain default changed on **{key}**: {change['from']} → {change['to']}")

    if simulation.get("warnings"):
        with st.expander("Warnings and degraded-mode notes"):
            for warning in simulation["warnings"]:
                st.markdown(f"- {warning}")


def render_blast_radius(st: Any, blast: dict[str, Any]) -> None:
    """Render a blast-radius analysis response.

    Args:
        st: The ``streamlit`` module.
        blast: A ``BlastRadiusResponse`` payload.
    """
    label, colour = RISK_STYLES.get(blast["aggregate_risk_level"], ("?", "#6b7280"))
    st.markdown(
        f"<div style='padding:12px 16px;border-radius:8px;border-left:6px solid {colour};"
        f"background:rgba(0,0,0,0.03);margin-bottom:12px'>"
        f"<span style='font-size:1.05rem;font-weight:600;color:{colour}'>"
        f"Aggregate risk {blast['aggregate_risk_score']:.1f} ({label})</span>"
        f"<div style='margin-top:6px;color:#6b7280;font-size:0.9rem'>"
        f"Union blast radius {blast['blast_radius_pct']:.1f}% of weighted asset value"
        f"</div></div>",
        unsafe_allow_html=True,
    )

    rows = []
    for assessment in blast["assessments"]:
        rows.append(
            {
                "Origin": assessment["origin_node"],
                "Risk score": assessment["risk_score"],
                "Level": assessment["risk_level"].upper(),
                "Blast radius %": assessment["blast_radius_pct"],
                "Zones penetrated": ", ".join(assessment["zones_penetrated"]) or "—",
                "Crown jewels reached": ", ".join(assessment["crown_jewels_reached"]) or "—",
                "Nodes reached": len(assessment["reachable_nodes"]),
            }
        )
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

    for assessment in blast["assessments"]:
        with st.expander(f"Attack paths from {assessment['origin_node']}"):
            for finding in assessment["findings"]:
                st.markdown(f"- {finding}")
            st.markdown("**Exposure by reached asset**")
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Asset": name, "Exploitability (0-1)": value}
                        for name, value in assessment["exposure_by_node"].items()
                    ]
                ),
                hide_index=True,
                width="stretch",
            )

    if blast["attack_paths"]:
        st.markdown("#### Concrete attack paths")
        st.dataframe(paths_frame(list(blast["attack_paths"])), hide_index=True, width="stretch")


__all__ = [
    "RISK_STYLES",
    "VERDICT_STYLES",
    "format_ports",
    "paths_frame",
    "render_blast_radius",
    "render_diff_report",
    "render_risk_banner",
]
