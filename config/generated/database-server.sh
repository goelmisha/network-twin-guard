#!/bin/sh
# ---------------------------------------------------------------------------
# GENERATED FILE - DO NOT EDIT.
# Source of truth: config/model.yaml
# Regenerate with:  python3 scripts/render_policies.py
# ---------------------------------------------------------------------------
set -e


echo "[corporate-twin] bootstrapping database-server"

ip link set eth1 up
ip addr replace 10.10.20.50/24 dev eth1

ip route replace default via 10.10.20.1

# Firewall policy compiled from config/model.yaml
iptables -F INPUT
iptables -P INPUT ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -s 10.10.10.0/24 -p tcp --dport 5432 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -F FORWARD
iptables -P FORWARD DROP
iptables -F OUTPUT
iptables -P OUTPUT ACCEPT

echo "[corporate-twin] database-server ready"
