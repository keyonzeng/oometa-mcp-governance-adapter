"""API tests: auth/localhost guard, transport parsing, evaluate, approvals."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mcp_control_plane.api.app import create_app
from mcp_control_plane.models import MCPServer, MCPTool, ServerStatus


@pytest.fixture
def token_client(plane, monkeypatch):
    monkeypatch.setenv("MCPCP_API_TOKEN", "test-token")
    app = create_app(plane)
    c = TestClient(app)
    c.headers.update({"Authorization": "Bearer test-token"})
    return c, plane


def test_health_and_auth(token_client, monkeypatch):
    c, _ = token_client
    assert c.get("/api/health").status_code == 200
    # Wrong token -> 401
    bad = c.get("/api/stats", headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 401


def test_localhost_guard_blocks_non_local_without_token(plane, monkeypatch):
    monkeypatch.delenv("MCPCP_API_TOKEN", raising=False)
    c = TestClient(create_app(plane))
    # TestClient's client host is "testclient" (non-loopback) -> blocked.
    r = c.get("/api/stats")
    assert r.status_code == 403
    assert "MCPCP_API_TOKEN" in r.json()["detail"]


def test_register_server_respects_transport(token_client):
    c, _ = token_client
    r = c.post("/api/servers", json={"name": "remote", "transport": "http", "url": "https://x/mcp"})
    assert r.status_code == 200
    assert r.json()["transport"] == "http"


def test_register_server_rejects_bad_transport(token_client):
    c, _ = token_client
    r = c.post("/api/servers", json={"name": "x", "transport": "carrier-pigeon"})
    assert r.status_code == 400


def test_evaluate_endpoint_returns_trace(token_client):
    c, plane = token_client
    s = MCPServer(name="pay", status=ServerStatus.APPROVED,
                  tools=[MCPTool(name="create_charge", description="Charge a customer's card for an amount")])
    s = plane.registry.register(s)
    plane.registry.approve(s.id, by="t")
    r = c.post("/api/policy/evaluate", json={"server_name": "pay", "tool": "create_charge", "arguments": {"amount": 10}})
    assert r.status_code == 200
    body = r.json()
    assert body["effect"] == "require_approval"
    assert len(body["trace"]) > 0
