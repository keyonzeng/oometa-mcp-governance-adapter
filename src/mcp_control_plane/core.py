"""ControlPlane: the facade that wires storage + services + policy together.

The CLI, HTTP API and gateway all construct one ``ControlPlane`` so they share a
single database, a single audit chain and the same active policy. Keeping the
assembly in one place means there is exactly one definition of 'the control
plane' and no subsystem can accidentally diverge.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from mcp_control_plane.approvals.service import ApprovalService
from mcp_control_plane.audit.service import AuditService
from mcp_control_plane.config import Settings, get_settings
from mcp_control_plane.models import CallContext, Decision
from mcp_control_plane.policy import Policy, evaluate
from mcp_control_plane.policy.default_policies import baseline_policy
from mcp_control_plane.registry.service import RegistryService
from mcp_control_plane.storage.db import Database, get_db


class ControlPlane:
    def __init__(self, settings: Settings | None = None, policy: Policy | None = None):
        self.settings = settings or get_settings()
        self.settings.ensure_home()
        self.db: Database = get_db(self.settings.db_path)
        self.audit = AuditService(self.db)
        self.registry = RegistryService(self.db, self.audit)
        self.approvals = ApprovalService(self.db, self.audit)
        self._policy = policy

    # ----- policy --------------------------------------------------------- #
    @property
    def policy(self) -> Policy:
        if self._policy is not None:
            return self._policy
        path = self.settings.policy_path
        if Path(path).exists():
            return Policy.from_file(str(path))
        # Secure, sensible default when no policy file is present yet.
        return baseline_policy()

    def set_policy(self, policy: Policy) -> None:
        self._policy = policy

    def decide(self, ctx: CallContext) -> Decision:
        """Pure policy decision for a call context (no side effects)."""
        return evaluate(self.policy, ctx)

    # ----- stats ---------------------------------------------------------- #
    def stats(self) -> dict:
        counts = self.db.counts()
        ok, broken = self.audit.verify()
        counts["audit_chain_ok"] = ok
        counts["audit_chain_broken_at"] = broken
        return counts


@lru_cache(maxsize=8)
def get_control_plane() -> ControlPlane:
    """Process-wide default control plane (keyed by resolved db path)."""
    return ControlPlane()
