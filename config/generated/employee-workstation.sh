#!/bin/sh
# ---------------------------------------------------------------------------
# GENERATED FILE - DO NOT EDIT.
# Source of truth: config/model.yaml
# Regenerate with:  python3 scripts/render_policies.py
# ---------------------------------------------------------------------------
set -e


echo "[corporate-twin] bootstrapping employee-workstation"

ip link set eth1 up
ip addr replace 10.10.10.10/24 dev eth1

ip route replace default via 10.10.10.1

# Firewall policy compiled from config/model.yaml
iptables -F INPUT
iptables -P INPUT DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -F FORWARD
iptables -P FORWARD DROP
iptables -F OUTPUT
iptables -P OUTPUT ACCEPT

echo "[corporate-twin] employee-workstation ready"
