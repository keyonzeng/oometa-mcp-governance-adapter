"""Audit service: the tamper-evident activity trail.

Every meaningful action in the control plane (a tool call decision, an approval,
a config scan, a registry change) becomes an :class:`AuditEvent` appended to a
hash chain. Because each event hashes the previous one, any silent edit or
deletion of history is detectable via ``Database.verify_audit_chain``.
"""

from __future__ import annotations

from mcp_control_plane.models import (
    AuditEvent,
    CallContext,
    Decision,
    redact_arguments,
)
from mcp_control_plane.storage.db import Database


class AuditService:
    def __init__(self, db: Database):
        self.db = db

    def record(self, event: AuditEvent) -> AuditEvent:
        return self.db.append_audit(event)

    def record_decision(
        self,
        ctx: CallContext,
        decision: Decision,
        outcome: str = "ok",
        latency_ms: float | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            kind="tool_call",
            agent=ctx.agent,
            principal=ctx.principal,
            server_id=ctx.server.id,
            server_name=ctx.server.name,
            tool=ctx.tool.name,
            effect=decision.effect,
            reason=decision.reason,
            risk=decision.risk,
            arguments_digest=ctx.arguments_digest(),
            matched_rule=decision.matched_rule,
            latency_ms=latency_ms,
            outcome=outcome,
            detail={
                "arguments_preview": redact_arguments(ctx.arguments),
                "obligations": decision.obligations,
                "capabilities": [c.value for c in ctx.capabilities],
            },
        )
        return self.db.append_audit(event)

    def record_event(self, kind: str, **fields) -> AuditEvent:
        return self.db.append_audit(AuditEvent(kind=kind, **fields))

    def recent(self, limit: int = 100, kind: str | None = None) -> list[AuditEvent]:
        return self.db.list_audit(limit=limit, kind=kind)

    def verify(self) -> tuple[bool, str | None]:
        return self.db.verify_audit_chain()
