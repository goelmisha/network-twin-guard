# Handoff — Corporate Network Digital Twin

**What it is:** a Containerlab + FastAPI + Streamlit "virtual branch office" that lets you
pre-validate a firewall rule change (blast radius, risk delta, crown-jewel reachability)
*before* it touches production, then roll back.

---

## Status at handoff

| Check | Result |
|---|---|
| `pytest` | **101 passed, 0 skipped** (re-run at handoff, exit 0) |
| `ruff check .` | **All checks passed** |
| `mypy` | **Success, 35 files** |
| Live HTTP (4 required endpoints + error paths) | 201/200/200/200; 422 / 422 / 503 |
| Dashboard end-to-end (`AppTest`, real backend) | 6 tabs, full validate → diff → rollback flow |
| `render_policies.py --check` | 3 bootstrap scripts current |

Measured demo numbers: baseline **49.17 MEDIUM / 29.17 % blast / 85.71 % compliance**
→ CHG-1042 **73.33 HIGH / 50.0 % blast / 57.14 %** (3 paths opened, 1 widened,
crown jewel = `database-server`). `/simulate-change` and `/analyze-blast-radius` return
**identical** scores for the same change — there is a test pinning that.

---

## THE BLOCKER — read this first

**Docker's daemon is DOWN and `containerlab` is NOT INSTALLED on this machine.**

Consequence: everything **model-driven** works today. Everything that needs **ground truth**
does not.

| Capability | Needs Docker | Needs containerlab |
|---|---|---|
| Solver, risk, diff, compliance (`CTL-001…007`) | — | — |
| `/simulate-change`, `/analyze-blast-radius`, `/compliance`, `/topology`, `/policies` | — | — |
| `render_policies.py` → `config/generated/<node>.sh` | — | — |
| `POST /snapshot` (baseline) | no — degrades to model-only | — |
| `POST /rollback` | no — **logical only**, `runtime_applied=false` | — |
| `POST /lab/deploy` / `/lab/destroy` | yes | **yes** → `503 runtime_unavailable` |
| Live capture (`docker exec`: ifaces, routes, `iptables -S`) | **yes** | — |
| `scripts/build_images.sh` | **yes** | — |

This degradation is **by design** (`backend/app/services/runtime.py`): *"a digital twin must
still be able to answer 'what would happen if' while the lab is torn down."* `status()` returns
`runtime_mode=MODEL` rather than raising.

**Never executed against real containers:** `scripts/deploy.sh`, `scripts/build_images.sh`,
`scripts/teardown.sh`, and the live-capture path. They are covered only by `bash -n`, a
process-boundary stub with real `docker inspect`/`exec` output shapes, and the clean `503`.
Treat the live path as **unverified**.

---

## Layout

```
corporate-twin.yml          Containerlab topology (name: corporate-twin, 3 nodes)
config/model.yaml           SINGLE SOURCE OF TRUTH — zones, nodes, policies, probe_flows
config/generated/*.sh       Rendered bootstrap scripts (do not hand-edit)
docker/twin-host.Dockerfile Alpine + iproute2 + iptables (~25 MB, arm64)
backend/app/
  models/     Pydantic v2 domain models
  core/       policy_engine, reachability, risk, diff, change, compliance, snapshot
  services/   runtime (Docker/clab gateway), twin_service (orchestration)
  api/routes/ system, topology, snapshots, simulation, compliance, lab
frontend/     Streamlit: app.py, api_client.py, components/
scripts/      setup_env, build_images, deploy, teardown, run_backend, run_frontend, render_policies
pyproject.toml  ruff + mypy + pytest config (single source; pytest.ini was removed)
```

Layering is strict: `models → core → services → api`. Keep it that way.

---

## Run it

```bash
scripts/setup_env.sh            # creates .venv, installs deps  (confirmed exit 0)
scripts/run_backend.sh          # → http://127.0.0.1:8000
scripts/run_frontend.sh         # → http://127.0.0.1:8501
python3 scripts/render_policies.py --check   # generated scripts current?
```

The model-only workflow needs **no Docker**. Full lab:

```bash
scripts/build_images.sh && scripts/deploy.sh      # REQUIRES Docker + containerlab
```

API surface (all under `/api/v1`, verified against `backend/app/api/routes/`):

- **POST** `/snapshot`, `/simulate-change`, `/analyze-blast-radius`, `/rollback` — the four core operations
- **POST** `/lab/deploy`, `/lab/destroy` — need containerlab + Docker → `503` otherwise
- **GET** `/health`, `/version`, `/runtime`, `/topology`, `/policies`, `/compliance`, `/simulations`, `/snapshot/nodes`

---

## Gotchas discovered the hard way

- **`model.yaml` ↔ `corporate-twin.yml` must agree** (node names, interface names, IPs). The
  loader **refuses to start** on mismatch — that is intentional, it stops deployed and simulated
  rules drifting. Editing topology means editing both.
- **No importer for real device configs.** Verified: zero code paths for `iptables-save` ingest
  or discovery. Adapting to a real network = hand-transcribing into `model.yaml`. This is the
  main practical friction and the highest-value thing to build next.
- **`render_policies.py` self-bootstraps** into `.venv/bin/python`, because the system `python3`
  has no pydantic.
- **`setup_env.sh` derives the Python version from `python3`** — do not hardcode `--python 3.13`.
  uv rejects a Homebrew interpreter *path* outright.
- **Target is Python 3.11** (Raspberry Pi OS Bookworm). PEP 695 `type` aliases were deliberately
  removed. This dev machine's venv is 3.14, so do not reintroduce 3.12+ syntax.
- **Live capture keys off containerlab's naming**: containers are found via
  `label=containerlab=<lab>` then the `clab-<lab>-` prefix is stripped. A hand-rolled
  `docker run` lab must replicate both or it stays invisible in model-only mode.
- **Rules are first-match-wins**, so the conntrack `ESTABLISHED,RELATED` rule must stay first in
  `FORWARD`.
- Crown jewel `database-server` is **deliberately default-ALLOW on INPUT** — it models the common
  real-world latent risk and trips `CTL-002`. Don't "fix" it; it's the demo.

## Bugs already fixed (don't regress these)

1. Connected-route branch conflated "destination owns the IP" with "current node owns it" → every path read as blocked.
2. A wildcard `ACCEPT` masked an earlier explicit `DROP` → a port-agnostic path falsely reported *every* port open.
3. `/snapshot/nodes` returned domain `Interface` objects (no `subnet`) → baseline tab crashed.
4. Component barrel didn't re-export `render_blast_radius`.
5. `/analyze-blast-radius` omitted the novelty component with a simulated change (70.0 vs 73.33) → endpoints disagreed; now pinned by a test.

---

## Scope limits (documented in README, not bugs)

IPv4 forwarding, static routing, `INPUT`/`FORWARD`/`OUTPUT` only. **No** NAT, dynamic routing
(OSPF/BGP), user-defined chains, VLANs, or IPv6. The twin **estimates reachable exposure**; it
does not prove exploitability. L7 appliances (e.g. the Cloudflare 2019 WAF-regex outage) are out
of scope — the tool models the *class* of unintended-blast-radius change, not L7 failures.

## Suggested next steps

1. **Config importer** (`iptables-save` + static-route ingest → `model.yaml`) — removes the biggest friction.
2. **CI gate**: run `render_policies.py --check` + a baseline `simulate-change` on firewall PRs.
3. **Segmentation-evidence report** for PCI DSS / CIS Control 12 — a diffable per-period artifact.
4. **Install Docker + containerlab** and finally exercise `deploy.sh` + live capture end-to-end.
