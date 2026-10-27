"""Pre-change validation panel.

Renders a form that maps the operator's intent onto the backend's
``ChangeRequest`` schema, and returns a ready-to-post payload. The panel only
composes the request; evaluation happens server-side so the dashboard can never
disagree with the API about what a change means.
"""

from __future__ import annotations

from typing import Any

#: Display label -> backend change_type value.
CHANGE_TYPE_LABELS: dict[str, str] = {
    "Allow a flow (new permit)": "allow_flow",
    "Deny a flow (new block)": "deny_flow",
    "Add a raw firewall rule": "add_policy_rule",
    "Remove a firewall rule": "remove_policy_rule",
    "Change a link state": "set_link_state",
    "Assume a node is compromised": "compromise_node",
}

CHAIN_CHOICES: tuple[str, ...] = ("FORWARD", "INPUT", "OUTPUT")
PROTOCOL_CHOICES: tuple[str, ...] = ("tcp", "udp", "icmp")


def render_validation_panel(st: Any, topology: dict[str, Any]) -> dict[str, Any] | None:
    """Render the validation form.

    Args:
        st: The ``streamlit`` module.
        topology: Topology payload supplying node and flow choices.

    Returns:
        A ``ChangeRequest`` payload dict when the form was submitted, otherwise
        ``None``.
    """
    nodes: list[dict[str, Any]] = topology.get("nodes", [])
    node_names = [node["name"] for node in nodes]
    node_by_name = {node["name"]: node for node in nodes}
    zone_by_node = {node["name"]: node["zone_label"] for node in nodes}

    if not node_names:
        st.warning("No nodes are available from the backend; cannot compose a change.")
        return None

    defaults = {"change_label": "", "target": node_names[0]}
    state_key = "validation_defaults"
    if state_key not in st.session_state:
        st.session_state[state_key] = defaults
    current = st.session_state[state_key]

    if not current.get("change_label"):
        st.info(
            "Every change is simulated against the captured baseline. Nothing is written to "
            "the lab unless you explicitly tick *push to live containers*.",
            icon="ℹ️",
        )

    with st.form("pre_change_validation", clear_on_submit=False):
        change_label = st.selectbox(
            "Candidate change",
            list(CHANGE_TYPE_LABELS),
            help="What are you about to deploy?",
        )
        change_type = CHANGE_TYPE_LABELS[change_label]

        target_index = node_names.index(current["target"]) if current["target"] in node_names else 0
        target_node = st.selectbox(
            "Target node (the enforcing device)",
            node_names,
            index=target_index,
            format_func=lambda name: f"{name} — {zone_by_node.get(name, '?')}",
            help="For flow changes this is the device that enforces the rule.",
        )

        payload: dict[str, Any] = {"change_type": change_type, "target_node": target_node}

        if change_type in {"allow_flow", "deny_flow"}:
            left, right = st.columns(2)
            with left:
                source_prefix = st.text_input(
                    "Source prefix",
                    value="10.10.10.0/24",
                    help="Traffic origin, in CIDR form. Use 0.0.0.0/0 for any source.",
                )
            with right:
                destination_choices = [name for name in node_names if name != target_node] or node_names
                destination_node = st.selectbox(
                    "Destination node",
                    destination_choices,
                    format_func=lambda name: f"{name} ({node_by_name[name].get('primary_ip') or 'no IP'})",
                )
            payload["dst"] = node_by_name[destination_node].get("primary_ip") or destination_node

            chain_col, proto_col, port_col = st.columns(3)
            with chain_col:
                payload["chain"] = st.selectbox("Chain", CHAIN_CHOICES, index=0)
            with proto_col:
                payload["protocol"] = st.selectbox("Protocol", PROTOCOL_CHOICES, index=0)
            with port_col:
                all_ports = st.checkbox(
                    "All ports",
                    value=True,
                    help="Tick to model an unrestricted permit, which is the classic "
                    "over-permissive change.",
                )
                payload["dport"] = None if all_ports else int(
                    st.number_input("Port", min_value=1, max_value=65535, value=5432, step=1)
                )
            payload["src"] = source_prefix
            payload["description"] = st.text_input(
                "Change reference (optional)", placeholder="CHG-1042: reporting integration"
            )

        elif change_type == "add_policy_rule":
            payload["chain"] = st.selectbox("Chain", CHAIN_CHOICES, index=0)
            payload["rule"] = st.text_input(
                "iptables rule arguments",
                value="-s 10.0.0.0/8 -j ACCEPT",
                help="Without a leading -A; inserted at position 1 of the chain.",
            )
            payload["description"] = st.text_input("Change reference (optional)")

        elif change_type == "remove_policy_rule":
            payload["chain"] = st.selectbox("Chain", CHAIN_CHOICES, index=0)
            payload["rule_index"] = int(
                st.number_input("Rule index to remove", min_value=1, value=1, step=1)
            )
            payload["description"] = st.text_input("Change reference (optional)")

        elif change_type == "set_link_state":
            neighbours = [
                link["target"] if link["source"] == target_node else link["source"]
                for link in topology.get("links", [])
                if target_node in {link["source"], link["target"]}
            ]
            if not neighbours:
                st.warning(f"{target_node} has no links to toggle.")
                neighbours = node_names
            payload["neighbour"] = st.selectbox("Linked peer", neighbours)
            payload["enabled"] = (
                st.radio("Desired link state", ("up", "down"), index=1, horizontal=True) == "up"
            )
            payload["description"] = st.text_input("Change reference (optional)")

        else:  # compromise_node
            origins = topology.get("entrypoints") or node_names
            origin_index = origins.index(target_node) if target_node in origins else 0
            payload["origin_node"] = st.selectbox(
                "Assumed-compromised node",
                sorted(set(origins) | {target_node}),
                index=origin_index,
                help="The attacker origin fanned out from during risk scoring.",
            )
            payload["description"] = st.text_input("Change reference (optional)")

        push_live = st.checkbox(
            "Also push the projected policy to running containers",
            value=False,
            help="Requires the lab to be deployed. Ignored with a warning in model-only mode.",
        )
        submitted = st.form_submit_button("Validate change", type="primary")

    st.session_state[state_key] = {"change_label": change_label, "target": target_node}

    if not submitted:
        return None

    if not payload.get("description"):
        payload["description"] = change_label
    payload["apply_to_runtime"] = push_live
    return payload


__all__ = ["CHAIN_CHOICES", "CHANGE_TYPE_LABELS", "PROTOCOL_CHOICES", "render_validation_panel"]
