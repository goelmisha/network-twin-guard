"""Corporate Twin — Streamlit validation dashboard.

A thin presentation layer over the REST API. All analysis happens in the
backend, so the dashboard can never disagree with the product's own engine, and
the same endpoints can be driven from CI or a change-approval workflow.

Run with::

    scripts/run_frontend.sh
    # or
    streamlit run frontend/app.py
"""

from __future__ import annotations

import sys
from ipaddress import ip_network
from pathlib import Path
from typing import Any

import streamlit as st

# Streamlit executes this file directly, so make the sibling modules importable.
FRONTEND_ROOT = Path(__file__).resolve().parent
if str(FRONTEND_ROOT) not in sys.path:
    sys.path.insert(0, str(FRONTEND_ROOT))

from api_client import DEFAULT_BASE_URL, TwinAPIError, call
from components import (
    render_blast_radius,
    render_diff_report,
    render_topology_map,
    render_validation_panel,
)
from components.diff_report import RISK_STYLES

st.set_page_config(
    page_title="Corporate Twin — Pre-Change Validation",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded",
)

STATE_DEFAULTS: dict[str, Any] = {
    "base_url": DEFAULT_BASE_URL,
    "health": None,
    "topology": None,
    "baseline": None,
    "baseline_nodes": [],
    "policies": [],
    "simulation": None,
    "blast": None,
    "compliance": None,
    "history": [],
    "error": None,
}


def _init_state() -> None:
    """Seed session state with defaults."""
    for key, value in STATE_DEFAULTS.items():
        st.session_state.setdefault(key, value)


def _fetch(method_name: str, **kwargs: Any) -> tuple[bool, Any]:
    """Call the API, recording failures in session state instead of raising.

    Args:
        method_name: Client method name.
        **kwargs: Arguments forwarded to the method.

    Returns:
        ``(ok, result)``. On failure ``result`` is the error message.
    """
    try:
        return True, call(method_name, st.session_state["base_url"], **kwargs)
    except TwinAPIError as exc:
        return False, exc
    except Exception as exc:
        return False, TwinAPIError(f"Unexpected client error: {exc}")


def _report_error(error: TwinAPIError) -> None:
    """Render an API failure with its structured context."""
    if error.is_connectivity_error:
        st.error(
            f"**Cannot reach the backend.** {error}\n\n"
            "Start it with `scripts/run_backend.sh`, then reload this page.",
            icon="🔌",
        )
    else:
        st.error(f"**{error.code}** — {error}", icon="🚫")
    if error.context:
        with st.expander("Error detail"):
            st.json(error.context)


def refresh_core() -> None:
    """Reload health, topology, baseline and compliance."""
    ok, health = _fetch("health")
    if not ok:
        _report_error(health)
        st.session_state["health"] = None
        return
    st.session_state["health"] = health
    st.session_state["error"] = None

    for method, key in (
        ("topology", "topology"),
        ("get_snapshot", "baseline"),
        ("snapshot_nodes", "baseline_nodes"),
        ("policies", "policies"),
        ("compliance", "compliance"),
        ("simulations", "history"),
    ):
        ok, result = _fetch(method)
        st.session_state[key] = result if ok else None


def capture_baseline() -> None:
    """Capture a new baseline snapshot."""
    with st.spinner("Capturing baseline (routing, reachability and firewall policy)…"):
        ok, result = _fetch("capture_snapshot")
    if not ok:
        _report_error(result)
        return
    st.session_state["simulation"] = None
    st.session_state["blast"] = None
    refresh_core()
    snapshot = result["snapshot"]
    st.success(
        f"Baseline captured: {snapshot['snapshot_id']} "
        f"({snapshot['reachable_count']}/{snapshot['total_pairs']} reachable pairs, "
        f"{snapshot['runtime_mode']} mode).",
        icon="📸",
    )


def rollback() -> None:
    """Revert the twin to the captured baseline."""
    ok, result = _fetch("rollback", apply_to_runtime=True)
    if not ok:
        _report_error(result)
        return
    st.session_state["simulation"] = None
    st.session_state["blast"] = None
    refresh_core()
    note = "baseline re-pushed to live containers" if result["runtime_applied"] else (
        "logical rollback only"
    )
    st.success(f"Rolled back to {result['restored_snapshot_id']} ({note}).", icon="↩️")


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------


def render_sidebar() -> None:
    """Render the sidebar: connectivity, runtime mode and baseline actions."""
    with st.sidebar:
        st.markdown("## 🛰️ Corporate Twin")
        st.caption("Pre-change network digital twin & attack-path risk analysis")

        base_url = st.text_input(
            "Backend URL",
            value=st.session_state["base_url"],
            help="FastAPI origin. Override the default with TWIN_API_BASE_URL.",
        )
        if base_url != st.session_state["base_url"]:
            st.session_state["base_url"] = base_url

        if st.button("Refresh from backend", width="stretch"):
            refresh_core()

        health = st.session_state.get("health")
        if not health:
            st.warning("Not connected.", icon="⚠️")
            return

        st.divider()
        if health["status"] == "ok":
            st.success("Backend healthy", icon="✅")
        else:
            st.warning("Running in model-only mode", icon="🧪")
        st.caption(health["detail"])

        mode_label = "🟢 live containers" if health["runtime_mode"] == "live" else "🧪 model only"
        st.markdown(
            f"""
            - Runtime: **{mode_label}**
            - Docker: {'available' if health['docker_available'] else 'unavailable'}
            - containerlab: {'installed' if health['containerlab_available'] else 'missing'}
            - Lab deployed: {'yes' if health['lab_deployed'] else 'no'}
            - Baseline: {'captured' if health['baseline_captured'] else 'not captured'}
            - Version: {health['version']}
            """
        )

        st.divider()
        st.markdown("### Baseline")
        if st.button("📸 Capture baseline", width="stretch", type="primary"):
            capture_baseline()
        if st.button("↩️ Roll back to baseline", width="stretch"):
            rollback()

        baseline = st.session_state.get("baseline")
        if baseline:
            st.caption(
                f"id `{baseline['snapshot_id']}` · {baseline['total_pairs']} pairs · "
                f"{baseline['reachable_count']} reachable"
            )
            for warning in baseline.get("warnings", []):
                st.info(warning, icon="ℹ️")

        compliance = st.session_state.get("compliance")
        if compliance:
            st.divider()
            st.markdown("### Compliance")
            score = compliance["score_pct"]
            st.progress(min(1.0, score / 100.0), text=f"{score:.1f}% of controls pass")
            st.caption(
                f"{compliance['passed']} pass · {compliance['failed']} fail · "
                f"{compliance['warned']} warn"
            )


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------


def render_topology_tab() -> None:
    """Render the live topology map."""
    topology = st.session_state.get("topology")
    if not topology:
        st.info("Connect to the backend to load the topology.")
        return

    simulation = st.session_state.get("simulation")
    blast = st.session_state.get("blast")

    reachable: set[str] = set()
    exposure: dict[str, float] = {}
    delta = None

    if simulation:
        delta = simulation["reachability_delta"]
        origin = simulation["risk"]["projected"]["origin_node"]
        exposure = simulation["risk"]["projected"]["exposure_by_node"]
        reachable = set(simulation["risk"]["projected"]["reachable_nodes"])
        st.caption(f"Showing the projected state for a change on **{origin}**'s blast radius.")
    elif blast and blast.get("assessments"):
        origin = blast["assessments"][0]["origin_node"]
        exposure = blast["assessments"][0]["exposure_by_node"]
        reachable = set(blast["assessments"][0]["reachable_nodes"])
        st.caption(f"Showing exposure from **{origin}**.")

    legend = st.columns(4)
    legend[0].markdown("🔵 user zone &nbsp; 🟠 perimeter &nbsp; 🟣 data")
    legend[1].markdown("⭐ crown-jewel asset")
    legend[2].markdown("🔴 red outline = reachable from the origin")
    legend[3].markdown("🔴 dashed = newly opened &nbsp; 🟢 dashed = closed")

    render_topology_map(st, topology, delta=delta, reachable_nodes=reachable, exposure_by_node=exposure)


def _subnet_of(address: str) -> str:
    """Derive the attached subnet from an interface address.

    Args:
        address: CIDR address such as ``10.10.10.1/24``.

    Returns:
        The subnet in CIDR form, or the original value when unparseable.
    """
    try:
        return str(ip_network(address, strict=False))
    except ValueError:
        return "—"


def render_baseline_tab() -> None:
    """Render the captured baseline: nodes, routes and firewall policy."""
    baseline = st.session_state.get("baseline")
    nodes = st.session_state.get("baseline_nodes") or []

    if not baseline:
        st.info("No baseline captured yet. Use **Capture baseline** in the sidebar.")
        return

    st.markdown(
        f"**Snapshot `{baseline['snapshot_id']}`** · captured {baseline['created_at']} · "
        f"{baseline['runtime_mode']} mode · {baseline['node_count']} nodes · "
        f"{baseline['reachable_count']} of {baseline['total_pairs']} pairs reachable"
    )

    for node in nodes:
        title = (
            f"{node['node']} · {node['zone']} · criticality {node['criticality']}/5 "
            f"· {node['policy_rule_count']} rules"
            + (" · ⭐ crown jewel" if node.get("crown_jewel") else "")
        )
        with st.expander(title):
            left, right = st.columns(2)
            with left:
                st.markdown("**Interfaces**")
                st.table(
                    [
                        {
                            "Interface": iface["name"],
                            "Address": iface["address"],
                            "Subnet": _subnet_of(iface["address"]),
                            "State": iface["state"],
                        }
                        for iface in node["interfaces"]
                    ]
                )
                st.markdown("**Chain defaults**")
                st.json(node["default_policies"])
            with right:
                st.markdown("**Routing table**")
                st.table(
                    [
                        {
                            "Prefix": route["prefix"],
                            "Next hop": route["via"] or "connected",
                            "Dev": route["dev"] or "—",
                            "Source": route["protocol"],
                        }
                        for route in node["routes"]
                    ]
                )

    st.markdown("### Compiled firewall policy")
    st.caption(
        "Rendered from the same model the containers run, so what is simulated is what is deployed."
    )
    policies = st.session_state.get("policies") or []
    for chain in policies:
        with st.expander(
            f"{chain['node']} — {chain['chain']} "
            f"(default {chain['default_policy']}, {chain['rule_count']} rules)"
        ):
            if chain["rules"]:
                for rule in chain["rules"]:
                    st.code(f"-A {chain['chain']} {rule}", language="text")
            else:
                st.caption("No rules; the default policy applies.")


def render_validation_tab() -> None:
    """Render the pre-change validation panel and its blast-radius companion."""
    topology = st.session_state.get("topology")
    if not topology:
        st.info("Connect to the backend to use the validation panel.")
        return

    if not st.session_state.get("baseline"):
        st.warning("Capture a baseline first — changes are validated against it.", icon="📸")

    st.markdown("### Pre-change validation")
    payload = render_validation_panel(st, topology)

    if payload:
        apply_to_runtime = bool(payload.pop("apply_to_runtime", False))
        with st.spinner("Re-solving multi-hop reachability across the topology…"):
            ok, result = _fetch("simulate_change", change=payload, apply_to_runtime=apply_to_runtime)
        if not ok:
            _report_error(result)
        else:
            st.session_state["simulation"] = result
            ok_blast, blast = _fetch(
                "analyze_blast_radius", request={"include_simulated_change": payload}
            )
            st.session_state["blast"] = blast if ok_blast else None
            ok_comp, compliance = _fetch("compliance")
            if ok_comp:
                st.session_state["compliance"] = compliance

    if st.session_state.get("simulation"):
        st.divider()
        render_diff_report(st, st.session_state["simulation"])
    else:
        st.caption("Submit a candidate change to see the before/after differential.")


def render_blast_tab() -> None:
    """Render blast-radius analysis controls and results."""
    topology = st.session_state.get("topology")
    if not topology:
        st.info("Connect to the backend to run blast-radius analysis.")
        return

    if not st.session_state.get("baseline"):
        st.warning("Capture a baseline first.", icon="📸")
        return

    node_names = [node["name"] for node in topology["nodes"]]
    entrypoints = topology.get("entrypoints") or node_names
    flows = topology.get("probe_flows", [])

    with st.form("blast_radius"):
        columns = st.columns(3)
        with columns[0]:
            use_entrypoints = st.checkbox("Use configured entry points", value=True)
            origin = st.selectbox(
                "Origin node",
                node_names,
                index=node_names.index(entrypoints[0]) if entrypoints and entrypoints[0] in node_names else 0,
                disabled=use_entrypoints,
            )
        with columns[1]:
            selected_flows = st.multiselect(
                "Probe flows (all when empty)", flows, default=[]
            )
        with columns[2]:
            st.caption(
                "Blast radius weights each reached asset by its business criticality and the "
                "exploitability of the most dangerous service reachable on it."
            )
        submitted = st.form_submit_button("Analyse blast radius", type="primary")

    if submitted:
        request: dict[str, Any] = {"flows": selected_flows}
        if not use_entrypoints:
            request["origin_node"] = origin
        with st.spinner("Fanning out across the reachability graph…"):
            ok, result = _fetch("analyze_blast_radius", request=request)
        if not ok:
            _report_error(result)
        else:
            st.session_state["blast"] = result

    blast = st.session_state.get("blast")
    if blast:
        st.divider()
        render_blast_radius(st, blast)
    else:
        st.caption("Run the analysis to see attack paths and the weighted blast radius.")


def render_compliance_tab() -> None:
    """Render the compliance report."""
    compliance = st.session_state.get("compliance")
    if not compliance:
        st.info("Capture a baseline to evaluate compliance controls.")
        return

    columns = st.columns(3)
    columns[0].metric("Controls passing", f"{compliance['score_pct']:.1f}%")
    columns[1].metric("Failures", compliance["failed"])
    columns[2].metric("Warnings", compliance["warned"])

    status_icon = {"pass": "✅", "fail": "❌", "warn": "⚠️"}
    for finding in compliance["findings"]:
        level_label, colour = RISK_STYLES.get(finding["severity"], ("?", "#6b7280"))
        header = (
            f"{status_icon.get(finding['status'], '•')} {finding['control_id']} — "
            f"{finding['title']}  ·  severity {level_label}"
        )
        with st.expander(header, expanded=finding["status"] == "fail"):
            st.markdown(f"**Observed:** {finding['detail']}")
            st.markdown(f"**Remediation:** {finding['remediation']}")
            if finding["affected_nodes"]:
                st.caption("Affected: " + ", ".join(finding["affected_nodes"]))
            st.markdown(f"<span style='color:{colour}'>status: {finding['status']}</span>", unsafe_allow_html=True)


def render_history_tab() -> None:
    """Render the simulation history."""
    history = st.session_state.get("history") or []
    if not history:
        st.info("No changes have been validated yet.")
        return

    import pandas as pd

    frame = pd.DataFrame(
        [
            {
                "Simulation": entry["simulation_id"],
                "When": entry["created_at"],
                "Change": entry["change_type"],
                "Target": entry["target_node"],
                "Verdict": entry["direction"].upper(),
                "Risk before": entry["baseline_score"],
                "Risk after": entry["projected_score"],
                "Level": entry["risk_level"].upper(),
                "Blast radius %": entry["blast_radius_pct"],
                "Opened": entry["paths_opened"],
                "Closed": entry["paths_closed"],
                "Reference": entry.get("description") or "—",
            }
            for entry in history
        ]
    )
    st.dataframe(frame, hide_index=True, width="stretch")

    st.markdown("#### Summaries")
    for entry in history:
        st.markdown(f"- `{entry['simulation_id']}` · {entry['summary']}")


def main() -> None:
    """Render the dashboard."""
    _init_state()
    render_sidebar()

    if not st.session_state.get("topology"):
        st.title("Corporate Twin — Pre-Change Network Validation")
        st.markdown(
            """
            Validate a network security change **before** it reaches production.

            1. Start the backend: `scripts/run_backend.sh`
            2. Click **Refresh from backend** in the sidebar
            3. Click **Capture baseline**
            4. Use **Validate change** to test a candidate rule

            The platform works with or without the Containerlab lab deployed: with the lab up it
            captures live container state, and with it down it resolves everything from
            `config/model.yaml` and tells you so.
            """
        )
        ok, health = _fetch("health")
        if not ok:
            _report_error(health)
        elif not st.session_state.get("topology"):
            refresh_core()
        return

    st.title("Corporate Twin — Pre-Change Network Validation")

    health = st.session_state.get("health") or {}
    if health.get("runtime_mode") != "live":
        st.info(
            "Running in **model-only mode**. Capture and simulation results are resolved from "
            "`config/model.yaml` rather than live containers. Deploy the lab with "
            "`scripts/deploy.sh` for live capture.",
            icon="🧪",
        )

    tabs = st.tabs(
        [
            "🗺️ Topology",
            "📸 Baseline",
            "🧪 Validate change",
            "🎯 Blast radius",
            "📋 Compliance",
            "🕓 History",
        ]
    )
    with tabs[0]:
        render_topology_tab()
    with tabs[1]:
        render_baseline_tab()
    with tabs[2]:
        render_validation_tab()
    with tabs[3]:
        render_blast_tab()
    with tabs[4]:
        render_compliance_tab()
    with tabs[5]:
        render_history_tab()


main()
