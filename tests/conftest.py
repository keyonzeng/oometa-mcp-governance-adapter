"""Shared pytest fixtures: each test gets an isolated control plane."""

from __future__ import annotations

import pytest

from mcp_control_plane.config import Settings
from mcp_control_plane.core import ControlPlane


@pytest.fixture
def plane(tmp_path, monkeypatch) -> ControlPlane:
    home = tmp_path / "mcpcp"
    monkeypatch.setenv("MCPCP_HOME", str(home))
    monkeypatch.delenv("MCPCP_DB", raising=False)
    monkeypatch.delenv("MCPCP_POLICY", raising=False)
    return ControlPlane(settings=Settings(home=home))
