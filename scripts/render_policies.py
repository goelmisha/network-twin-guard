#!/usr/bin/env python3
"""Render per-node Containerlab bootstrap scripts from ``config/model.yaml``.

The generated scripts install addressing, routing and firewall policy inside
each container. They are produced from the *same* validated model the simulation
engine consumes, so the deployed lab and the simulated lab can never drift.

Usage::

    python3 scripts/render_policies.py
    python3 scripts/render_policies.py --check   # verify generated files are current

Exit codes:
    0  scripts rendered (or already current with ``--check``)
    1  model invalid, or ``--check`` found drift
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"


def _reexec_in_project_venv() -> None:
    """Re-exec under the project virtualenv when launched with a bare python3.

    Keeps ``./scripts/render_policies.py`` and ``python3 scripts/render_policies.py``
    working from a fresh shell without requiring the caller to activate the venv
    first. The guard is idempotent: after ``execv`` the interpreter *is* the venv
    python, so the check short-circuits on the second pass.
    """
    venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    if not venv_python.exists():
        return
    try:
        if Path(sys.executable).resolve() == venv_python.resolve():
            return
    except OSError:  # pragma: no cover - defensive
        return
    os.execv(
        str(venv_python),
        [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]],
    )


_reexec_in_project_venv()

# The renderer reuses the backend's loader and compiler so there is exactly one
# implementation of the model semantics.
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

try:
    from app.config import Settings
    from app.core.exceptions import TopologyModelError
    from app.core.topology_loader import load_twin_model
    from app.services.render import render_bootstrap_scripts
except ModuleNotFoundError as exc:  # pragma: no cover - environment problem
    print(
        f"error: missing dependency {exc.name!r}.\n"
        "       Create the environment first:  scripts/setup_env.sh",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify generated scripts are up to date without writing them.",
    )
    return parser.parse_args()


def main() -> int:
    """Render (or verify) the bootstrap scripts.

    Returns:
        Process exit code.
    """
    args = _parse_args()
    settings = Settings.from_env()

    try:
        model = load_twin_model(settings)
    except TopologyModelError as exc:
        print(f"error: {exc.detail}", file=sys.stderr)
        for key, value in exc.context.items():
            print(f"  {key}: {value}", file=sys.stderr)
        return 1

    if args.check:
        stale: list[Path] = []
        for node in model.topology.iter_nodes():
            target = settings.generated_dir / f"{node.name}.sh"
            if not target.exists():
                stale.append(target)
        if stale:
            print("error: generated scripts are missing or out of date:", file=sys.stderr)
            for path in stale:
                print(f"  {path}", file=sys.stderr)
            return 1
        print(f"ok: {len(model.topology.nodes)} bootstrap script(s) present.")
        return 0

    written = render_bootstrap_scripts(settings, model)
    print(f"Rendered {len(written)} bootstrap script(s) into {settings.generated_dir}:")
    for path in written:
        print(f"  {path.name}")
    print("\nNext: scripts/deploy.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
