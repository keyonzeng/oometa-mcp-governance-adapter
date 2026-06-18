"""Registry service: the inventory and review workflow for MCP servers.

The registry is the source of truth for *which servers exist* and *whether they
are allowed*. Registering a server enriches each advertised tool with inferred
capabilities, poisoning findings and a risk level, then rolls those up into a
server-level risk score. Re-registering an existing server compares fingerprints
to detect a 'rug pull' (a server silently changing what it runs or exposes).
"""

from __future__ import annotations

from mcp_control_plane.audit.service import AuditService
from mcp_control_plane.models import (
    Capability,
    MCPServer,
    RiskLevel,
    ServerStatus,
    utcnow,
)
from mcp_control_plane.policy.builtin import enrich_tool
from mcp_control_plane.storage.db import Database


class RugPullError(Exception):
    """Raised when a server's fingerprint changes unexpectedly on re-register."""


class RegistryService:
    def __init__(self, db: Database, audit: AuditService | None = None):
        self.db = db
        self.audit = audit or AuditService(db)

    # ----- enrichment / scoring ------------------------------------------ #
    def enrich(self, server: MCPServer) -> MCPServer:
        for tool in server.tools:
            enrich_tool(tool)
        server.risk, server.risk_score, server.risk_factors = self._score_server(server)
        server.updated_at = utcnow()
        return server

    def _score_server(self, server: MCPServer) -> tuple[RiskLevel, int, list[str]]:
        factors: list[str] = []
        score = 0
        caps: set[Capability] = set()
        for tool in server.tools:
            caps.update(tool.capabilities)
            if tool.findings:
                score += 40
                factors.append(f"tool '{tool.name}': {tool.findings[0]}")
            score += {"info": 0, "low": 2, "medium": 8, "high": 18, "critical": 30}[
                tool.risk.value
            ]

        cap_weight = {
            Capability.PROCESS_EXEC: 25,
            Capability.CODE_EXECUTION: 22,
            Capability.PAYMENT: 20,
            Capability.SECRETS: 18,
            Capability.FILESYSTEM_WRITE: 14,
            Capability.DATABASE_WRITE: 14,
            Capability.DESTRUCTIVE: 16,
            Capability.EMAIL_SEND: 10,
            Capability.NETWORK: 8,
        }
        for cap, w in cap_weight.items():
            if cap in caps:
                score += w
                factors.append(f"exposes capability '{cap.value}'")

        # Transport / config hygiene signals.
        if server.transport.value == "sse":
            factors.append("uses deprecated SSE transport")
            score += 5
        if server.url and server.url.startswith("http://"):
            factors.append("connects over plaintext http://")
            score += 10
        if server.command in ("npx", "uvx", "uv", "bunx"):
            factors.append(f"runs remote code on each launch via '{server.command}'")
            score += 8
        if not server.tools:
            factors.append("no tools enumerated yet (unknown surface)")
            score += 5

        # Static configuration findings from the scanner (kept distinct from
        # runtime tool risk) raise the score and impose a floor on the level, so
        # a critical config issue can never read as a low-risk registry entry.
        finding_weight = {"info": 0, "low": 4, "medium": 10, "high": 22, "critical": 40}
        worst_finding = RiskLevel.INFO
        for f in server.config_findings:
            sev = str(f.get("severity", "info"))
            score += finding_weight.get(sev, 0)
            if sev not in ("info",):
                factors.append(f"config: {f.get('code', '?')} {f.get('title', '')}".strip())
            try:
                lvl = RiskLevel(sev)
                if lvl.score > worst_finding.score:
                    worst_finding = lvl
            except ValueError:
                pass

        score = min(score, 100)
        level = (
            RiskLevel.CRITICAL
            if score >= 75
            else RiskLevel.HIGH
            if score >= 50
            else RiskLevel.MEDIUM
            if score >= 25
            else RiskLevel.LOW
        )
        # Never let a registry entry read safer than its worst static finding.
        if worst_finding.score > level.score:
            level = worst_finding
        return level, score, factors

    # ----- register / review --------------------------------------------- #
    def register(
        self,
        server: MCPServer,
        *,
        on_fingerprint_change: str = "flag",
        config_findings: list | None = None,
    ) -> MCPServer:
        """Register or update a server.

        ``on_fingerprint_change`` controls rug-pull handling when a server with
        the same name already exists: ``flag`` (default, reset to pending +
        record), ``error`` (raise), or ``ignore``.

        ``config_findings`` are static scanner findings (``ConfigFinding`` or
        dicts) to fold into the server's risk so a dangerous config cannot be
        registered as low-risk.
        """
        if config_findings:
            server.config_findings = [_finding_to_dict(f) for f in config_findings]
        existing = self.db.find_server_by_name(server.name)
        server = self.enrich(server)

        if existing is not None:
            server.id = existing.id
            server.created_at = existing.created_at
            if existing.fingerprint() != server.fingerprint():
                if on_fingerprint_change == "error":
                    raise RugPullError(
                        f"server '{server.name}' fingerprint changed since last review"
                    )
                if on_fingerprint_change == "flag":
                    server.status = ServerStatus.PENDING
                    server.risk_factors.insert(
                        0, "FINGERPRINT CHANGED since last review (possible rug pull)"
                    )
                    self.audit.record_event(
                        "registry",
                        server_id=server.id,
                        server_name=server.name,
                        reason="fingerprint changed; reset to pending",
                        outcome="flagged",
                    )
            else:
                # Preserve prior review status if nothing material changed.
                server.status = existing.status
                server.reviewed_at = existing.reviewed_at
                server.reviewed_by = existing.reviewed_by

        self.db.upsert_server(server)
        self.audit.record_event(
            "registry",
            server_id=server.id,
            server_name=server.name,
            risk=server.risk,
            reason=f"registered ({server.status.value})",
            outcome="ok",
        )
        return server

    def set_status(
        self, server_id: str, status: ServerStatus, by: str = "cli", note: str | None = None
    ) -> MCPServer:
        server = self.db.get_server(server_id)
        if server is None:
            raise KeyError(server_id)
        server.status = status
        server.reviewed_at = utcnow()
        server.reviewed_by = by
        server.review_note = note
        server.updated_at = utcnow()
        self.db.upsert_server(server)
        self.audit.record_event(
            "registry",
            server_id=server.id,
            server_name=server.name,
            reason=f"status -> {status.value} by {by}" + (f": {note}" if note else ""),
            outcome="ok",
        )
        return server

    def approve(self, server_id: str, by: str = "cli", note: str | None = None) -> MCPServer:
        return self.set_status(server_id, ServerStatus.APPROVED, by, note)

    def reject(self, server_id: str, by: str = "cli", note: str | None = None) -> MCPServer:
        return self.set_status(server_id, ServerStatus.REJECTED, by, note)

    def get(self, server_id: str) -> MCPServer | None:
        return self.db.get_server(server_id)

    def get_by_name(self, name: str) -> MCPServer | None:
        return self.db.find_server_by_name(name)

    def list(self, status: ServerStatus | None = None) -> list[MCPServer]:
        return self.db.list_servers(status)


def _finding_to_dict(f) -> dict:
    """Normalise a ConfigFinding (dataclass) or dict to a stored finding dict."""
    if isinstance(f, dict):
        sev = f.get("severity")
        sev = sev.value if hasattr(sev, "value") else (sev or "info")
        return {
            "code": f.get("code", "?"),
            "title": f.get("title", ""),
            "severity": sev,
            "detail": f.get("detail", ""),
            "remediation": f.get("remediation", ""),
        }
    sev = getattr(f, "severity", None)
    return {
        "code": getattr(f, "code", "?"),
        "title": getattr(f, "title", ""),
        "severity": sev.value if hasattr(sev, "value") else (sev or "info"),
        "detail": getattr(f, "detail", ""),
        "remediation": getattr(f, "remediation", ""),
    }
