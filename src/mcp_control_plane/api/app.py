"""FastAPI control plane + dashboard host.

This is the team-facing surface: a small JSON API over the same ControlPlane the
CLI uses, plus the static dashboard. Secure-by-default: when no ``MCPCP_API_TOKEN``
is set the server is meant to bind to localhost only; once a token is set every
``/api`` route requires ``Authorization: Bearer <token>``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mcp_control_plane.core import ControlPlane, get_control_plane
from mcp_control_plane.models import (
    CallContext,
    MCPServer,
    MCPTool,
    RiskLevel,
    ServerStatus,
)
from mcp_control_plane.policy.builtin import enrich_tool
from mcp_control_plane.scanner import scan
from mcp_control_plane.version import __version__

STATIC_DIR = Path(__file__).parent.parent / "dashboard" / "static"


def require_auth(authorization: str | None = Header(default=None)) -> None:
    plane = get_control_plane()
    token = plane.settings.api_token
    if not token:
        return  # localhost-only mode
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")


# ----- request bodies ----------------------------------------------------- #
class ToolIn(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = {}


class ServerIn(BaseModel):
    name: str
    description: str = ""
    transport: str = "stdio"
    command: str | None = None
    args: list[str] = []
    env_keys: list[str] = []
    url: str | None = None
    tags: list[str] = []
    tools: list[ToolIn] = []


class ReviewIn(BaseModel):
    by: str = "dashboard"
    note: str | None = None


class DecideIn(BaseModel):
    approve: bool
    by: str = "dashboard"
    note: str | None = None


class EvaluateIn(BaseModel):
    server_id: str | None = None
    server_name: str | None = None
    tool: str
    arguments: dict[str, Any] = {}
    agent: str = "explorer"


class ScanIn(BaseModel):
    include_user: bool = True
    project_root: str | None = None
    fail_on: str = "high"


def create_app(plane: ControlPlane | None = None) -> FastAPI:
    plane = plane or get_control_plane()
    app = FastAPI(
        title="mcp-control-plane",
        version=__version__,
        description="Governance & security control plane for MCP.",
    )

    auth = [Depends(require_auth)]

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/api/stats", dependencies=auth)
    def stats() -> dict:
        return plane.stats()

    # ----- servers -------------------------------------------------------- #
    @app.get("/api/servers", dependencies=auth)
    def list_servers(status: str | None = None) -> list[dict]:
        st = ServerStatus(status) if status else None
        return [s.model_dump(mode="json") for s in plane.registry.list(st)]

    @app.get("/api/servers/{server_id}", dependencies=auth)
    def get_server(server_id: str) -> dict:
        s = plane.registry.get(server_id)
        if not s:
            raise HTTPException(404, "server not found")
        return s.model_dump(mode="json")

    @app.post("/api/servers", dependencies=auth)
    def register_server(body: ServerIn) -> dict:
        server = MCPServer(
            name=body.name,
            description=body.description,
            command=body.command,
            args=body.args,
            env_keys=body.env_keys,
            url=body.url,
            tags=body.tags,
            tools=[
                MCPTool(name=t.name, description=t.description, input_schema=t.input_schema)
                for t in body.tools
            ],
        )
        return plane.registry.register(server).model_dump(mode="json")

    @app.post("/api/servers/{server_id}/approve", dependencies=auth)
    def approve_server(server_id: str, body: ReviewIn) -> dict:
        return _review(plane, server_id, ServerStatus.APPROVED, body)

    @app.post("/api/servers/{server_id}/reject", dependencies=auth)
    def reject_server(server_id: str, body: ReviewIn) -> dict:
        return _review(plane, server_id, ServerStatus.REJECTED, body)

    @app.post("/api/servers/{server_id}/disable", dependencies=auth)
    def disable_server(server_id: str, body: ReviewIn) -> dict:
        return _review(plane, server_id, ServerStatus.DISABLED, body)

    @app.delete("/api/servers/{server_id}", dependencies=auth)
    def delete_server(server_id: str) -> dict:
        ok = plane.db.delete_server(server_id)
        if not ok:
            raise HTTPException(404, "server not found")
        return {"deleted": server_id}

    # ----- policy --------------------------------------------------------- #
    @app.get("/api/policy", dependencies=auth)
    def get_policy() -> dict:
        return plane.policy.model_dump(mode="json")

    @app.post("/api/policy/evaluate", dependencies=auth)
    def evaluate_call(body: EvaluateIn) -> dict:
        server = None
        if body.server_id:
            server = plane.registry.get(body.server_id)
        elif body.server_name:
            server = plane.registry.get_by_name(body.server_name)
        if server is None:
            raise HTTPException(404, "server not found; register it first")
        tool = next((t for t in server.tools if t.name == body.tool), None)
        if tool is None:
            tool = enrich_tool(MCPTool(name=body.tool))
        ctx = CallContext(
            server=server, tool=tool, arguments=body.arguments, agent=body.agent
        )
        decision = plane.decide(ctx)
        return decision.model_dump(mode="json")

    # ----- approvals ------------------------------------------------------ #
    @app.get("/api/approvals", dependencies=auth)
    def list_approvals(status: str | None = None) -> list[dict]:
        return [a.model_dump(mode="json") for a in plane.approvals.list(status)]

    @app.post("/api/approvals/{approval_id}/decide", dependencies=auth)
    def decide_approval(approval_id: str, body: DecideIn) -> dict:
        try:
            a = plane.approvals.decide(approval_id, body.approve, by=body.by, note=body.note)
        except KeyError:
            raise HTTPException(404, "approval not found") from None
        return a.model_dump(mode="json")

    # ----- audit ---------------------------------------------------------- #
    @app.get("/api/audit", dependencies=auth)
    def list_audit(limit: int = 100, kind: str | None = None) -> list[dict]:
        return [e.model_dump(mode="json") for e in plane.audit.recent(limit=limit, kind=kind)]

    @app.get("/api/audit/verify", dependencies=auth)
    def verify_audit() -> dict:
        ok, broken = plane.audit.verify()
        return {"ok": ok, "broken_at": broken}

    # ----- scan ----------------------------------------------------------- #
    @app.post("/api/scan", dependencies=auth)
    def run_scan(body: ScanIn) -> dict:
        report = scan(
            include_user=body.include_user,
            project_root=Path(body.project_root) if body.project_root else None,
            fail_on=RiskLevel(body.fail_on),
        )
        return report.to_dict()

    # ----- dashboard ------------------------------------------------------ #
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/")
        def index() -> Any:
            idx = STATIC_DIR / "index.html"
            if idx.exists():
                return FileResponse(str(idx))
            return JSONResponse({"detail": "dashboard not built"}, status_code=404)

    return app


def _review(plane: ControlPlane, server_id: str, status: ServerStatus, body: ReviewIn) -> dict:
    try:
        s = plane.registry.set_status(server_id, status, by=body.by, note=body.note)
    except KeyError:
        raise HTTPException(404, "server not found") from None
    return s.model_dump(mode="json")


app = create_app
