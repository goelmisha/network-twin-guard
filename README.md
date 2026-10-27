# Corporate Twin — Pre-Change Network Digital Twin & Attack-Path Risk Analysis

Validate a network security change **before** it reaches production.

Corporate Twin runs an enterprise branch office as a lightweight, ARM64-friendly
Containerlab lab, captures a baseline of its routing, reachability and firewall
policy, applies a candidate change to a *copy* of that model, re-solves multi-hop
reachability across the topology graph, and reports exactly what opened, what
closed, and how far an attacker could travel.

> **The core insight:** binary "is it blocked?" checks are not enough. A change
> can leave every path *reachable* while making one of them vastly more
> exploitable — which is exactly the class of change this platform is built to
> catch.

---

## Table of contents

- [The problem it solves](#the-problem-it-solves)
- [Architecture](#architecture)
- [Worked example](#worked-example)
- [Quickstart](#quickstart)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Testing](#testing)
- [Commercial value proposition](#commercial-value-proposition)
- [Design decisions and limits](#design-decisions-and-limits)

---

## The problem it solves

A firewall change ticket usually reads like this:

> *"CHG-1042: open TCP from the corporate zone to the database server so the new
> reporting integration can connect."*

The rule that gets written is often `-p tcp` with **no port restriction**. It
passes a peer review, because "corp already talks to the database". What nobody
checked is that the database host firewall was relying on the gateway as its only
control — so a service that was scoped to PostgreSQL/5432 becomes reachable on
SSH, SMB and *every other port*, and the blast radius of a single compromised
workstation doubles.

Corporate Twin answers that question with numbers instead of opinions, and it
does so without touching production.

---

## Architecture

```
                     ┌──────────────────────────────────────────────┐
                     │        Streamlit validation dashboard        │
                     │  topology map · validation panel · diff UI   │
                     └───────────────────────┬──────────────────────┘
                                             │ HTTPS / JSON (async httpx)
                     ┌───────────────────────▼──────────────────────┐
                     │            FastAPI backend (/api/v1)         │
                     │  thin controllers → domain exceptions → HTTP │
                     └───────────────────────┬──────────────────────┘
                                             │
        ┌────────────────────────────────────┼────────────────────────────────────┐
        │                                    │                                    │
┌───────▼────────┐              ┌────────────▼────────────┐            ┌──────────▼──────────┐
│ Snapshot engine│              │  Differential engine     │            │ Compliance controls │
│ baseline + live│              │ policy + reachability    │            │ 7 explainable rules │
│ state capture  │              │ + risk deltas            │            │                     │
└───────┬────────┘              └────────────┬────────────┘            └─────────────────────┘
        │                                    │
        │                   ┌────────────────▼─────────────────┐
        │                   │      Solver core (app/core)      │
        │                   │  routing → next hop → netfilter  │
        │                   │  INPUT / FORWARD / OUTPUT hooks  │
        │                   │  port-interval algebra           │
        │                   └────────────────┬─────────────────┘
        │                                    │
┌───────▼────────────────────────────────────▼───────────────────────────────────┐
│      Runtime gateway (Docker + Containerlab CLIs, timeouts, degradation)       │
└───────────────────────────────────┬────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────▼─────────────────────────────┐
        │   corporate-twin.yml — Containerlab lab (arm64, Alpine) │
        │   perimeter-gateway · employee-workstation · database    │
        └──────────────────────────────────────────────────────────┘
```

### API-first design

Every capability is an HTTP endpoint. The dashboard is a *consumer* of the same
contract that CI, a ticketing integration or a change-approval bot would use, so
the UI can never drift from the product's own engine. The OpenAPI document is
generated at `/openapi.json` and browsable at `/docs`.

### Single source of truth

`config/model.yaml` declares the zones, addressing, routing, criticality and
firewall policy. Three consumers read it:

| Consumer | Purpose |
| --- | --- |
| `scripts/render_policies.py` | Generates the per-node bootstrap scripts Containerlab executes |
| `app/core/*` | Drives reachability, risk and compliance analysis |
| `app/services/render.py` | Serves the same rendering over `POST /api/v1/lab/deploy` |

Because the lab and the model come from one file, the rules running inside the
containers are byte-for-byte the rules the solver evaluates. A mismatch between
the twin and reality is the one failure mode that makes a digital twin worthless,
so the loader refuses to start when `corporate-twin.yml` and `config/model.yaml`
disagree about nodes, interfaces, coupling or zones.

### Snapshot & differential engine

1. **Snapshot** — captures the baseline: interfaces and routing tables, the
   compiled firewall policy, and the fully solved reachability matrix for every
   probe flow. Live container state is read via `docker exec` when the lab is
   deployed; otherwise the state is resolved from the model and the snapshot
   says so in `warnings`.
2. **Simulate** — applies the candidate change to a *copy* of the baseline model.
   The baseline is never mutated, which is what makes rollback trivial and
   trustworthy.
3. **Diff** — computes a policy delta (rules added/removed), a reachability delta
   (paths opened/closed/**widened**) and a risk delta (score, blast radius and
   risk-level transition).

### Solver core

The reachability engine reproduces what a real forwarding plane does, rather than
walking an adjacency list:

- longest-prefix-match routing on every node, including synthesised connected
  routes and declared static/default routes;
- next-hop resolution by IP ownership across the topology graph, with link state
  taken into account (a severed link removes the connected route *and* the
  next-hop that depended on it);
- netfilter chains evaluated at the correct hook — `OUTPUT` on the origin,
  `FORWARD` on every transit router with the correct ingress **and** egress
  interface, `INPUT` on the destination;
- conntrack rules that only match `ESTABLISHED,RELATED` are excluded from
  new-flow analysis, because they cannot open a new connection;
- exact **port-interval algebra** for port-agnostic flows, so a permit is only
  reported when every hop agrees on a usable port.

### Risk and blast radius

`blast_radius_pct` is the share of total asset value (criticality-weighted) that
becomes reachable from an assumed compromise origin, where each asset counts only
to the extent of its **most exploitable reachable service**.

`risk_score` (0-100) blends four explainable components:

| Component | Weight | Meaning |
| --- | --- | --- |
| Blast radius | 0.40 | Weighted share of the estate reachable from the origin |
| Zone penetration | 0.25 | Fraction of zones beyond the origin's own zone that were reached |
| Crown-jewel exposure | 0.25 | Exploitability of the most exposed crown-jewel asset |
| Path novelty | 0.10 | Share of previously blocked origin paths this change opens |

Buckets: **HIGH** ≥ 70, **MEDIUM** ≥ 30, **LOW** < 30. Every weight and
threshold is a named constant in `backend/app/core/risk.py`, so an enterprise can
tune them and every score remains explainable to an auditor.

---

## Worked example

The reference topology is a branch office with three zones: `perimeter` (the
gateway), `corp` (the workstation) and `data` (the database).

**Baseline**

| Metric | Value |
| --- | --- |
| Reachability pairs solved | 36 (3 nodes × 2 peers × 6 probe flows) |
| Pairs permitting a new connection | 10 |
| Risk score | **49.17 — MEDIUM** |
| Blast radius from `employee-workstation` | **29.17%** |
| Compliance | **85.71%** (6 of 7 controls pass) |

The one failing control is `CTL-002`: the database host firewall is `default
ACCEPT`. That is a deliberate, extremely common real-world misconfiguration — the
crown-jewel server relies entirely on the gateway for isolation. Corporate Twin
flags it as a latent finding instead of hiding it.

**Candidate change — CHG-1042** (`allow_flow`, unrestricted ports, corp → DB):

```bash
curl -s -X POST http://localhost:8000/api/v1/simulate-change \
  -H 'Content-Type: application/json' \
  -d '{"change_type":"allow_flow","target_node":"perimeter-gateway","chain":"FORWARD",
       "src":"10.10.10.0/24","dst":"10.10.20.50","protocol":"tcp",
       "description":"CHG-1042: reporting integration"}' | jq .
```

| Metric | Baseline | Projected |
| --- | --- | --- |
| Risk score | 49.17 (MEDIUM) | **73.33 (HIGH)** |
| Blast radius | 29.17% | **50.0%** |
| Compliance | 85.71% | **57.14%** |
| Paths opened | — | 3 (SSH/22, SMB/445, HTTP/80) |
| Paths widened | — | 1 (the port-agnostic flow, now *every* port) |
| Controls failing | 1 | 3 (`CTL-002`, `CTL-004`, `CTL-006`) |

Verdict: `REGRESSION — do not deploy`.

**The same change, scoped correctly** — replacing the application permit instead
of widening it is scored as hardening:

| Change | Risk | Blast radius |
| --- | --- | --- |
| Remove the corridor permit entirely | 15.83 (LOW) | 8.33% |
| Add a host-level `DROP` for 5432 on the database | 15.83 (LOW) | 8.33% |

---

## Quickstart

### Prerequisites

- Docker (with a running daemon) — optional, but required for live capture
- [Containerlab](https://containerlab.dev/) — optional, same caveat
- Python 3.11+ (tested on 3.14 / arm64)

The platform is designed to work *without* Docker or Containerlab: it then runs
in **model-only mode**, resolves everything from `config/model.yaml`, and reports
`"status": "degraded"` on `/api/v1/health` along with the reason.

### 1. Set up the environment

```bash
git clone <this-repo> && cd corporate-twin
scripts/setup_env.sh          # creates .venv and installs every dependency
```

### 2. (Optional) Deploy the lab

```bash
scripts/deploy.sh             # validates the model, builds the image, deploys the lab
containerlab inspect -t corporate-twin.yml
```

`scripts/deploy.sh` performs, in order: model validation → bootstrap script
rendering → `twin-host:latest` image build (skipped if present) → `containerlab
deploy` → inspection.

To tear it down:

```bash
scripts/teardown.sh
```

### 3. Run the backend

```bash
scripts/run_backend.sh                # add --reload for development
# -> http://localhost:8000/docs
```

### 4. Run the dashboard

```bash
scripts/run_frontend.sh
# -> http://localhost:8501
```

### 5. Capture a baseline and validate a change

```bash
# Capture the pre-change baseline
curl -s -X POST http://localhost:8000/api/v1/snapshot | jq '.snapshot | {snapshot_id, runtime_mode, reachable_count}'

# Analyse the blast radius of a compromised workstation
curl -s -X POST http://localhost:8000/api/v1/analyze-blast-radius \
  -H 'Content-Type: application/json' -d '{}' | jq '{aggregate_risk_score, blast_radius_pct}'

# Revert everything to the captured baseline
curl -s -X POST http://localhost:8000/api/v1/rollback | jq .
```

### Manual equivalent (without the convenience scripts)

```bash
python3 scripts/render_policies.py                       # render bootstrap scripts
docker build -t twin-host:latest -f docker/twin-host.Dockerfile docker/
containerlab deploy -t corporate-twin.yml

uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000     # terminal 1
streamlit run frontend/app.py --server.port 8501                      # terminal 2
```

---

## API reference

Interactive documentation: **`http://localhost:8000/docs`**.

### Primary endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/snapshot` | Capture the pre-change baseline (routing, reachability, firewall policy) |
| `POST` | `/api/v1/simulate-change` | Apply a candidate change or simulate a compromised node |
| `POST` | `/api/v1/analyze-blast-radius` | Graph-based reachability analysis with a risk score and blast-radius footprint |
| `POST` | `/api/v1/rollback` | Revert the network state to the pre-change baseline |

### Supporting endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Readiness, runtime mode and named checks |
| `GET` | `/api/v1/topology` | Nodes, links and zones for map rendering |
| `GET` | `/api/v1/runtime` | Docker / Containerlab / per-node container state |
| `GET` | `/api/v1/policies` | Compiled chains with defaults and rules in order |
| `GET` | `/api/v1/snapshot` · `/snapshot/nodes` | Baseline summary and per-node state |
| `GET` | `/api/v1/compliance` | Compliance score and per-control findings |
| `GET` | `/api/v1/simulations` | Simulation history |
| `POST` | `/api/v1/lab/deploy` · `/lab/destroy` | Containerlab lifecycle |

### Change types accepted by `simulate-change`

| `change_type` | Required fields | Effect |
| --- | --- | --- |
| `allow_flow` | `src`, `dst` (+ optional `chain`, `protocol`, `dport`) | Inserts an `ACCEPT` at position 1 of the target chain |
| `deny_flow` | as above | Inserts a `DROP` at position 1 |
| `add_policy_rule` | `rule`, `chain` | Inserts a raw iptables rule at position 1 |
| `remove_policy_rule` | `chain`, `rule_index` | Removes the rule at that index |
| `set_link_state` | `neighbour`, `enabled` | Brings a point-to-point link up or down |
| `compromise_node` | `origin_node` (optional) | Assumes a node is attacker-controlled and scores its reach |

### Error contract

Every failure returns the same envelope, so clients branch on `code` rather than
parsing prose:

```json
{
  "code": "runtime_unavailable",
  "detail": "Docker daemon is not reachable; the platform is running in model-only mode.",
  "context": { "command": "docker info", "exit_code": 1 }
}
```

| `code` | HTTP | Meaning |
| --- | --- | --- |
| `validation_error` | 422 | Request payload failed schema validation |
| `change_validation_error` | 422 | The change does not apply to this topology |
| `snapshot_not_found` | 404 | No baseline has been captured |
| `runtime_unavailable` | 503 | Docker or containerlab unavailable (recoverable) |
| `command_execution_failed` | 502 | An external command failed or timed out |
| `topology_model_error` | 500 | The topology or model file is invalid |
| `rollback_failed` | 409 | The baseline could not be restored |

---

## Configuration

All settings come from environment variables with repository-relative defaults.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TWIN_TOPOLOGY_FILE` | `corporate-twin.yml` | Containerlab topology (wiring) |
| `TWIN_MODEL_FILE` | `config/model.yaml` | Declarative model (single source of truth) |
| `TWIN_STATE_DIR` | `.twin-state` | Persisted baseline and simulation history |
| `TWIN_COMMAND_TIMEOUT` | `60` | Timeout for every external command, in seconds |
| `TWIN_DOCKER_BIN` | `docker` | Docker CLI |
| `TWIN_CONTAINERLAB_BIN` | `containerlab` | Containerlab CLI |
| `TWIN_API_HOST` / `TWIN_API_PORT` | `0.0.0.0` / `8000` | Backend bind address |
| `TWIN_CORS_ORIGINS` | `http://localhost:8501,...` | Allowed dashboard origins |
| `TWIN_API_BASE_URL` | `http://localhost:8000` | Dashboard → backend URL |

---

## Testing

```bash
.venv/bin/python -m pytest                          # 101 tests
.venv/bin/ruff check backend frontend scripts       # lint
.venv/bin/mypy                                     # static types (backend)
.venv/bin/python scripts/render_policies.py --check # generated scripts are current
```

The suite runs with **no Docker daemon and no lab deployed**. The runtime is faked
at the *process boundary* (`docker inspect` / `docker exec` output), so the real
node validation, container-state checks, capture logic and command timeouts are
still exercised. Coverage includes:

- iptables parsing, first-match-wins evaluation, port-interval algebra;
- multi-hop routing, link-state changes, port-set intersection;
- risk scoring, blast radius and the differential engine;
- full end-to-end HTTP tests through the ASGI application, including error
  envelopes and baseline persistence across a simulated restart.

### Verifying the delivered system

The checks below were used during development and are the recommended acceptance
criteria for a change to this platform:

```bash
# 1. Static analysis and unit/integration tests
.venv/bin/ruff check backend frontend scripts && .venv/bin/mypy && .venv/bin/python -m pytest

# 2. Exercise the API as a client would (lab not required)
scripts/run_backend.sh &
curl -s -X POST localhost:8000/api/v1/snapshot | jq '.snapshot.snapshot_id'
curl -s -X POST localhost:8000/api/v1/simulate-change -H 'Content-Type: application/json' \
  -d '{"change_type":"allow_flow","target_node":"perimeter-gateway","src":"10.10.10.0/24","dst":"10.10.20.50","protocol":"tcp"}' \
  | jq '.risk.projected | {risk_score, risk_level, blast_radius_pct}'

# 3. Confirm the two analysis endpoints agree on the same change
#    (they answer the same question via different routes, so they must match)
```

---

## Commercial value proposition

### 1. Prevent production outages before they happen

Change-induced outages are among the most expensive incidents an enterprise
faces, and firewall changes are a leading cause. Corporate Twin turns a change
ticket from a two-person guess into a machine-verified statement: *"3 paths open,
1 path widens, risk moves MEDIUM → HIGH, crown jewels newly exposed."* That is a
decision a change board can actually approve or reject.

### 2. Catch the failures binary checks miss

The `exposure_widened` signal is the differentiator. A path can remain reachable
while its permitted port set goes from `{5432}` to `{0-65535}`; a connectivity
check reports "still reachable, no change" and the regression ships. Corporate
Twin reports the widening, and the risk score moves 49.17 → 73.33 accordingly.

### 3. Automated compliance evidence

Seven controls are evaluated on every baseline and every candidate change:
default-deny posture, unrestricted permits, crown-jewel cross-zone exposure,
management-plane reachability from user zones, blanket permits into crown-jewel
zones, and legacy cleartext protocols. Each finding carries severity, observed
evidence and remediation text — ready to attach to an audit or a change record.

### 4. Quantified risk, not a red/green light

Blast radius and risk score answer the question executives actually ask: *"if
this device is popped, how much of the estate goes with it?"* The 49.17 → 73.33
movement is a number that can be used as a gate in a change-management workflow.

### 5. Runs where the work happens

Every node is a lightweight Alpine container (~25 MB), designed for a Raspberry
Pi 5 with 4 GB of RAM. No hypervisors, no VM-backed network OS images, no
GNS3/EVE-NG dependency. The backend keeps working with the lab torn down, so a
laptop with no Docker daemon can still validate changes against the model.

---

## Design decisions and limits

**Deliberate design decisions**

- **The model is the contract.** The loader rejects a topology that disagrees
  with the model, because a twin that silently diverges from reality is worse
  than no twin.
- **The baseline is immutable.** Changes are applied to copies; this makes
  rollback trivial and makes every diff trustworthy.
- **A partial lab is not "live".** If any node container is missing, snapshots
  fall back to model mode and say so, rather than claiming live capture over two
  thirds of the estate.
- **Typed domain errors, never bare exceptions.** Every external command has a
  timeout, and every timeout becomes a `command_execution_failed` envelope.

**Known limits**

- The solver models IPv4 forwarding, netfilter `INPUT`/`FORWARD`/`OUTPUT` and
  static routing. It does not model NAT, dynamic routing protocols, user-defined
  chains, connection tracking of specific flows, VLANs or IPv6.
- Rules are assumed to be applied at deploy time via `iptables`; the platform
  does not currently parse vendor ACL syntaxes such as Cisco IOS or SRX.
- The blast-radius model is a weighted graph heuristic, not an exploit
  emulator. It estimates reachable *exposure*; it does not prove exploitability.
