"""Approval service: human-in-the-loop gate for risky tool calls.

When the policy engine returns ``require_approval``, the gateway parks the call
and creates an :class:`Approval`. A human (via CLI or dashboard) approves or
denies it. This implements 'prefer explicit approval over hidden automation'.
"""

from __future__ import annotations

from datetime import timedelta

from mcp_control_plane.audit.service import AuditService
from mcp_control_plane.models import (
    Approval,
    ApprovalStatus,
    CallContext,
    Decision,
    redact_arguments,
    utcnow,
)
from mcp_control_plane.storage.db import Database

DEFAULT_GRANT_TTL_SECONDS = 600


class ApprovalService:
    def __init__(self, db: Database, audit: AuditService | None = None):
        self.db = db
        self.audit = audit or AuditService(db)

    def find_active_grant(self, ctx: CallContext) -> Approval | None:
        """Return an approved, unexpired grant matching this *exact* call.

        A grant is bound to (server, tool, exact arguments, agent, principal) so
        that approving a call lets an identical retry proceed — but a *different*
        call (other args/tool/agent) still requires its own approval.
        """
        digest = ctx.arguments_digest()
        now = utcnow()
        for a in self.db.list_approvals(status="approved", limit=200):
            if (
                a.is_active_grant(now)
                and a.server_id == ctx.server.id
                and a.tool == ctx.tool.name
                and a.arguments_digest == digest
                and a.agent == ctx.agent
                and a.principal == ctx.principal
            ):
                return a
        return None

    def request(self, ctx: CallContext, decision: Decision) -> Approval:
        approval = Approval(
            agent=ctx.agent,
            principal=ctx.principal,
            server_id=ctx.server.id,
            server_name=ctx.server.name,
            tool=ctx.tool.name,
            arguments_preview=redact_arguments(ctx.arguments),
            arguments_digest=ctx.arguments_digest(),
            reason=decision.reason,
            risk=decision.risk,
        )
        self.db.upsert_approval(approval)
        self.audit.record_event(
            "approval",
            agent=ctx.agent,
            principal=ctx.principal,
            server_id=ctx.server.id,
            server_name=ctx.server.name,
            tool=ctx.tool.name,
            reason=f"approval requested: {decision.reason}",
            risk=decision.risk,
            outcome="pending",
            detail={"approval_id": approval.id},
        )
        return approval

    def decide(
        self,
        approval_id: str,
        approve: bool,
        by: str = "cli",
        note: str | None = None,
        grant_ttl_seconds: int = DEFAULT_GRANT_TTL_SECONDS,
    ) -> Approval:
        approval = self.db.get_approval(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        approval.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
        approval.decided_at = utcnow()
        approval.decided_by = by
        approval.decision_note = note
        if approve:
            approval.expires_at = approval.decided_at + timedelta(seconds=grant_ttl_seconds)
        self.db.upsert_approval(approval)
        self.audit.record_event(
            "approval",
            agent=approval.agent,
            principal=approval.principal,
            server_id=approval.server_id,
            server_name=approval.server_name,
            tool=approval.tool,
            reason=f"approval {approval.status.value} by {by}"
            + (f": {note}" if note else ""),
            risk=approval.risk,
            outcome=approval.status.value,
            detail={"approval_id": approval.id},
        )
        return approval

    def get(self, approval_id: str) -> Approval | None:
        return self.db.get_approval(approval_id)

    def pending(self, limit: int = 100) -> list[Approval]:
        return self.db.list_approvals(status="pending", limit=limit)

    def list(self, status: str | None = None, limit: int = 100) -> list[Approval]:
        return self.db.list_approvals(status=status, limit=limit)
