"""Runtime configuration and well-known filesystem locations.

`mcp-control-plane` is *local-first*: by default all state lives in a single
SQLite file under a home directory so a solo developer can run the whole control
plane with zero infrastructure. Every path is overridable by environment
variable so the same binary scales to a shared, self-hosted deployment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _home() -> Path:
    """Resolve the control-plane home directory.

    Order of precedence:
        1. ``MCPCP_HOME`` environment variable (explicit override)
        2. ``./.mcpcp`` if it already exists (project-local state)
        3. ``~/.mcpcp`` (per-user default)
    """
    env = os.environ.get("MCPCP_HOME")
    if env:
        return Path(env).expanduser().resolve()
    local = Path.cwd() / ".mcpcp"
    if local.exists():
        return local.resolve()
    return (Path.home() / ".mcpcp").resolve()


@dataclass(frozen=True)
class Settings:
    """Immutable resolved settings for a process."""

    home: Path = field(default_factory=_home)

    @property
    def db_path(self) -> Path:
        return Path(os.environ.get("MCPCP_DB", str(self.home / "mcpcp.db")))

    @property
    def policy_path(self) -> Path:
        """Active policy file. Defaults to ``<home>/policy.yaml``."""
        return Path(os.environ.get("MCPCP_POLICY", str(self.home / "policy.yaml")))

    @property
    def api_host(self) -> str:
        return os.environ.get("MCPCP_HOST", "127.0.0.1")

    @property
    def api_port(self) -> int:
        return int(os.environ.get("MCPCP_PORT", "8765"))

    @property
    def api_token(self) -> str | None:
        """Optional bearer token gating the control-plane API.

        When unset the API binds to localhost only (secure-by-default for the
        single-developer case). Set ``MCPCP_API_TOKEN`` before exposing it.
        """
        return os.environ.get("MCPCP_API_TOKEN")

    def ensure_home(self) -> Path:
        self.home.mkdir(parents=True, exist_ok=True)
        return self.home


def get_settings() -> Settings:
    """Return freshly-resolved settings (cheap; reflects current env/cwd)."""
    return Settings()
