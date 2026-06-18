"""Discover MCP server configurations across known clients.

Most MCP clients persist their servers in a JSON file using the same shape:

    {"mcpServers": {"<name>": {"command": "...", "args": [...], "env": {...}}}}

(VS Code uses the key ``servers`` and supports ``url`` for HTTP transports.)
This module knows the well-known on-disk locations for the popular clients and
can also walk a project directory for committed config files, then normalises
everything into :class:`MCPServer` objects tagged with their source client.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from mcp_control_plane.models import MCPServer, ServerStatus, Transport


@dataclass
class ConfigLocation:
    client: str
    path: Path
    scope: str  # "user" or "project"


def _home() -> Path:
    return Path.home()


def user_config_locations() -> list[ConfigLocation]:
    """Return well-known per-user MCP config paths for this platform."""
    home = _home()
    locs: list[ConfigLocation] = []

    def add(client: str, path: Path):
        locs.append(ConfigLocation(client, path, "user"))

    if sys.platform == "darwin":
        appsup = home / "Library" / "Application Support"
        add("Claude Desktop", appsup / "Claude" / "claude_desktop_config.json")
        add(
            "Cline",
            appsup
            / "Code"
            / "User"
            / "globalStorage"
            / "saoudrizwan.claude-dev"
            / "settings"
            / "cline_mcp_settings.json",
        )
    elif sys.platform.startswith("win"):
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        add("Claude Desktop", appdata / "Claude" / "claude_desktop_config.json")
        add(
            "Cline",
            appdata
            / "Code"
            / "User"
            / "globalStorage"
            / "saoudrizwan.claude-dev"
            / "settings"
            / "cline_mcp_settings.json",
        )
    else:  # linux / other
        cfg = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        add("Claude Desktop", cfg / "Claude" / "claude_desktop_config.json")

    # Cross-platform, home-relative locations.
    add("Cursor", home / ".cursor" / "mcp.json")
    add("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json")
    add("Continue", home / ".continue" / "config.yaml")
    add("Continue", home / ".continue" / "config.json")
    add("Goose", home / ".config" / "goose" / "config.yaml")
    add("Zed", home / ".config" / "zed" / "settings.json")
    add("Claude Code", home / ".claude.json")
    return locs


def project_config_locations(root: Path) -> list[ConfigLocation]:
    """Config files commonly committed into a repository."""
    root = Path(root)
    candidates = [
        ("Claude Code", root / ".mcp.json", "project"),
        ("Cursor", root / ".cursor" / "mcp.json", "project"),
        ("VS Code", root / ".vscode" / "mcp.json", "project"),
        ("Continue", root / ".continue" / "config.json", "project"),
    ]
    return [ConfigLocation(c, p, s) for c, p, s in candidates]


def _parse_env_keys(env: dict | None) -> tuple[list[str], dict[str, str]]:
    """Return (env_key_names, raw_env) — we keep names for policy, raw for checks."""
    if not isinstance(env, dict):
        return [], {}
    return list(env.keys()), {k: str(v) for k, v in env.items()}


def _load_raw(path: Path) -> object | None:
    """Load a config file as JSON or YAML (best-effort)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml

            return yaml.safe_load(text)
        except Exception:
            return None
    return None


def _server_block(raw: object) -> list[tuple[str, dict]]:
    """Normalise the many client shapes into a list of (name, spec) pairs.

    Handles object-maps (``mcpServers``/``servers``/``context_servers``) and the
    YAML-list shape used by Continue/Goose where each entry carries its own name.
    """
    if not isinstance(raw, dict):
        return []
    for key in ("mcpServers", "servers", "context_servers", "extensions"):
        block = raw.get(key)
        if isinstance(block, dict):
            return [(n, s) for n, s in block.items() if isinstance(s, dict)]
        if isinstance(block, list):  # Continue/Goose style list-of-objects
            out = []
            for i, s in enumerate(block):
                if isinstance(s, dict):
                    out.append((s.get("name") or f"server-{i}", s))
            return out
    return []


def parse_config(loc: ConfigLocation) -> list[MCPServer]:
    """Parse a single config file into MCPServer objects (best-effort)."""
    raw = _load_raw(loc.path)
    if raw is None:
        return []

    servers: list[MCPServer] = []
    for name, spec in _server_block(raw):
        env_keys, raw_env = _parse_env_keys(spec.get("env") or spec.get("envs"))
        url = spec.get("url") or spec.get("serverUrl") or spec.get("uri")
        if url:
            transport = (
                Transport.SSE
                if str(spec.get("type", "")).lower() == "sse"
                else Transport.HTTP
            )
        else:
            transport = Transport.STDIO
        server = MCPServer(
            name=name,
            description=spec.get("description", ""),
            transport=transport,
            command=spec.get("command"),
            args=[str(a) for a in spec.get("args", []) or []],
            env_keys=env_keys,
            url=url,
            status=ServerStatus.DISCOVERED,
            source=f"scanner:{loc.client}",
            tags=[loc.client.lower().replace(" ", "-"), loc.scope],
        )
        # Stash raw values transiently for the rule checks (not persisted to the
        # registry — only env_keys/names are kept on the model).
        server.__dict__["_raw_env"] = raw_env
        server.__dict__["_config_path"] = str(loc.path)
        server.__dict__["_headers"] = spec.get("headers") or {}
        server.__dict__["_auto_approve"] = spec.get("autoApprove") or spec.get("alwaysAllow") or []
        servers.append(server)
    return servers


def discover(
    *, include_user: bool = True, project_root: Path | None = None
) -> list[tuple[ConfigLocation, list[MCPServer]]]:
    """Discover all MCP servers from user + project configs that exist on disk."""
    locations: list[ConfigLocation] = []
    if include_user:
        locations += user_config_locations()
    if project_root is not None:
        locations += project_config_locations(project_root)

    results: list[tuple[ConfigLocation, list[MCPServer]]] = []
    for loc in locations:
        if loc.path.exists():
            results.append((loc, parse_config(loc)))
    return results
