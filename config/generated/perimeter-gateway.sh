#!/bin/sh
# ---------------------------------------------------------------------------
# GENERATED FILE - DO NOT EDIT.
# Source of truth: config/model.yaml
# Regenerate with:  python3 scripts/render_policies.py
# ---------------------------------------------------------------------------
set -e


echo "[corporate-twin] bootstrapping perimeter-gateway"

ip link set eth1 up
ip addr replace 10.10.10.1/24 dev eth1
ip link set eth2 up
ip addr replace 10.10.20.1/24 dev eth2

sysctl -qw net.ipv4.ip_forward=1

# Firewall policy compiled from config/model.yaml
iptables -F INPUT
iptables -P INPUT DROP
iptables -A INPUT -p tcp --dport 22 -s 10.10.99.0/24 -j ACCEPT
iptables -A INPUT -i eth1 -p icmp -j ACCEPT
iptables -F FORWARD
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth1 -o eth2 -s 10.10.10.0/24 -d 10.10.20.50/32 -p tcp --dport 5432 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth2 -s 10.10.10.0/24 -d 10.10.20.50/32 -p tcp --dport 22 -j REJECT
iptables -F OUTPUT
iptables -P OUTPUT ACCEPT

echo "[corporate-twin] perimeter-gateway ready"
