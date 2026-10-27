"""Application configuration.

Settings are resolved from environment variables with repository-relative
defaults, so the platform runs identically from a laptop, a CI runner and a
Raspberry Pi 5 without a config file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

#: Repository root, derived from this file's location (``backend/app/config.py``).
REPO_ROOT: Path = Path(__file__).resolve().parents[2]


def _env_path(name: str, default: Path) -> Path:
    """Read a path from the environment, falling back to ``default``."""
    raw = os.environ.get(name)
    return Path(raw).expanduser().resolve() if raw else default


def _env_float(name: str, default: float) -> float:
    """Read a float from the environment, falling back to ``default``."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Read a comma-separated list from the environment."""
    raw = os.environ.get(name)
    if not raw:
        return default
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable runtime settings for the API and solver.

    Attributes:
        repo_root: Repository root directory.
        topology_file: Containerlab topology file (wiring).
        model_file: Declarative model file (addressing, policy, zones).
        generated_dir: Directory for rendered node bootstrap scripts.
        state_dir: Directory holding the persisted baseline and simulation log.
        database_name: Filename of the persisted baseline snapshot.
        command_timeout_seconds: Timeout applied to every external command.
        docker_bin: Docker CLI executable.
        containerlab_bin: Containerlab CLI executable.
        cors_origins: Allowed browser origins for the dashboard.
        api_host: Bind address for uvicorn.
        api_port: Bind port for uvicorn.
    """

    repo_root: Path
    topology_file: Path
    model_file: Path
    generated_dir: Path
    state_dir: Path
    database_name: str
    command_timeout_seconds: float
    docker_bin: str
    containerlab_bin: str
    cors_origins: tuple[str, ...]
    api_host: str
    api_port: int

    @property
    def baseline_path(self) -> Path:
        """Path to the persisted baseline snapshot JSON."""
        return self.state_dir / self.database_name

    def ensure_directories(self) -> None:
        """Create the mutable directories the service expects to exist."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.generated_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from the current process environment.

        Recognised variables: ``TWIN_TOPOLOGY_FILE``, ``TWIN_MODEL_FILE``,
        ``TWIN_GENERATED_DIR``, ``TWIN_STATE_DIR``, ``TWIN_COMMAND_TIMEOUT``,
        ``TWIN_DOCKER_BIN``, ``TWIN_CONTAINERLAB_BIN``, ``TWIN_CORS_ORIGINS``,
        ``TWIN_API_HOST``, ``TWIN_API_PORT``.
        """
        return cls(
            repo_root=REPO_ROOT,
            topology_file=_env_path("TWIN_TOPOLOGY_FILE", REPO_ROOT / "corporate-twin.yml"),
            model_file=_env_path("TWIN_MODEL_FILE", REPO_ROOT / "config" / "model.yaml"),
            generated_dir=_env_path("TWIN_GENERATED_DIR", REPO_ROOT / "config" / "generated"),
            state_dir=_env_path("TWIN_STATE_DIR", REPO_ROOT / ".twin-state"),
            database_name=os.environ.get("TWIN_DATABASE_NAME", "baseline.json"),
            command_timeout_seconds=_env_float("TWIN_COMMAND_TIMEOUT", 60.0),
            docker_bin=os.environ.get("TWIN_DOCKER_BIN", "docker"),
            containerlab_bin=os.environ.get("TWIN_CONTAINERLAB_BIN", "containerlab"),
            cors_origins=_env_csv(
                "TWIN_CORS_ORIGINS",
                ("http://localhost:8501", "http://127.0.0.1:8501"),
            ),
            api_host=os.environ.get("TWIN_API_HOST", "0.0.0.0"),
            api_port=int(os.environ.get("TWIN_API_PORT", "8000")),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings.from_env()
