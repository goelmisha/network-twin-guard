# Low-Power, Offline-Capable Network Monitoring for Remote Offices

**Problem:** How can a low-power physical device deployed locally at a remote office monitor network health and security status without relying on constant cloud connectivity?

---

## Core principle: local-first, cloud-optional

Design the device so the cloud is a **sync peer**, not a dependency. Everything that can be decided or stored locally should be; the WAN link is an optimization, never a precondition for correct operation. Concretely, that means inverting the usual SaaS agent: collect, analyze, alert, and store on-site; upload summaries opportunistically.

---

## 1. Collect cheap, high-signal data

A low-power box (Pi Zero class, 1–2 W) cannot do line-rate deep packet inspection. Don't try. The best signal-per-byte sources are:

- **Flow records** (NetFlow/IPFIX/sFlow from switches/routers, or Zeek/eBPF flow export) — O(flows), not O(packets). Sampling is fine.
- **DNS query logs** — typically the single highest-value, lowest-volume feed. Detect tunneling, DGA patterns, beaconing, first-seen domains.
- **DHCP leases / ARP tables** — free device inventory; new-MAC detection and rogue device alerts.
- **SNMP polling** of APs and switches — interface errors, uplink flaps, PoE faults, client counts.
- **Syslog** from local infrastructure.
- **TLS/JA3 fingerprints** and flow periodicity for beaconing detection, without decrypting anything.
- **Active probes** — ICMP/TCP reachability and latency to a small target set, so you can distinguish "WAN is down" from "site is down."

Passive capture should come from a **mirror port or TAP**, never inline, unless you have a hardware bypass.

---

## 2. Analytics that fit the power budget

Use eBPF or libpcap with a ring buffer for extraction, then run rules plus small models:

- EWMA / seasonal baselines per host and per interface (business-hours vs. off-hours traffic shape).
- Streaming anomaly detection: isolation forest, logistic regression, tiny quantized TFLite models. No transformers.
- Deterministic rules for things that don't need threat intel (port scans, ARP spoofing, deauth floods, cleartext credentials, unexpected outbound ports).

Enrichment from a threat-intel feed is **best-effort** — cache IOCs with TTLs and degrade gracefully. Many useful features (domain entropy, domain-age proxies, flow regularity) are computable with zero connectivity.

---

## 3. Store-and-forward that survives a week offline

Tier your data and give it an explicit eviction policy:

```
alerts      -> never dropped, tiny, sent first
rollups     -> 1m -> 1h -> 1d, bounded retention, zstd + batch
raw samples -> first to be evicted, dropped by design
```

- Local time-series store (SQLite + WAL, embedded Prometheus) or a circular-file logger.
- Queue uploads in a durable WAL with idempotent, resumable transfers (content-addressed objects; MQTT QoS 1 against a local Mosquitto broker so producers are decoupled from the WAN).
- Never let a full buffer block collection — shed raw data under backpressure.

---

## 4. Autonomy, with a fail-open safety rail

Local enforcement is valuable (block a switch port via SNMP/SSH, bounce 802.1X/CoA, quarantine a VLAN) but a low-power single board must not become a chokepoint.

- Prefer **out-of-band control of the managed switch** over inline filtering.
- If inline, require a bypass NIC + hardware watchdog that fails open on power loss, crash, or process hang.
- Send alerts locally too: syslog/SNMP trap, LED or small display for on-site staff, optional modem fallback.

---

## 5. The two things that actually break offline

These are the real engineering problems, not connectivity:

1. **Time.** No NTP means clock drift, which corrupts every correlation. Use a TCXO/RTC with holdover or GNSS/PTP if there's sky view. Record monotonic time plus last-known-UTC and a drift estimate so cloud-side timestamps can be reconciled.
2. **Identity.** Certificates, revocation, and key rotation all assume an online CA. Pre-provision keys in a TPM/secure element, pin the CA, use long-lived certs, and treat rotation as a file-based signed operation applied offline.

---

## 6. Harden the monitor itself

It is now an unattended box on an untrusted LAN.

- Secure boot; signed A/B firmware with rollback.
- Read-only root filesystem; TPM-sealed disk encryption.
- No inbound listeners; egress-only firewall.
- mTLS with per-device credentials; unique keys per unit.
- Disabled JTAG/UART debug ports; tamper switch.
- **Silence is itself a signal:** implement a dead-man's-switch heartbeat so the cloud escalates when a site goes dark rather than assuming "quiet."

---

## 7. What the cloud keeps doing

Fleet management (signed config / rule / model / intel bundles), cross-site correlation, long-term retention, dashboards, and human workflow. That's a much smaller, cheaper, more intermittent workload than streaming telemetry.

---

## 8. Minimum viable version

Pi Zero 2 W + PoE, mirror port, DNS-log and flow collection, SQLite rollups, a handful of deterministic rules, a local web dashboard for on-site staff, syslog/SNMP alerting, and a nightly delta sync. That covers the majority of remote-office monitoring value while tolerating days of WAN loss.

---

## Caveat

No offline design gives you current global threat intel. Treat the device as a **detector and evidence collector** that flags "this is weird for us," and let the cloud decide whether "weird" is malicious once the link returns.

---

## Sizing reference

| Platform | Idle power | Fits |
| --- | --- | --- |
| Pi Zero 2 W | ~0.7–2 W | Flow + DNS collection, light rules |
| Pi 4/5 (or similar ARM SBC) | ~3–6 W | Adds local capture, dashboards |
| N100 mini-PC | ~6–15 W | Full Zeek, heavier local models |

Prefer **Power over Ethernet** to keep the deployment to a single cable, and plan for thermal headroom — remote wiring closets get hot.
