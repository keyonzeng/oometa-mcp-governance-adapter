"""Transport-agnostic gateway core.

The mediator is the single place where MCP traffic meets policy. A transport
adapter (stdio today; HTTP later) is responsible only for moving bytes; it hands
parsed JSON-RPC messages to the mediator and acts on the verdict. This keeps the
security-critical logic in one tested unit, independent of how the agent and the
upstream server are connected.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import Enum

from mcp_control_plane.core import ControlPlane
from mcp_control_plane.models import (
    ApprovalStatus,
    CallContext,
    Decision,
    Effect,
    MCPServer,
    MCPTool,
    ServerStatus,
    Transport,
)
from mcp_control_plane.policy.builtin import enrich_tool


class Verdict(str, Enum):
    FORWARD = "forward"  # send the request upstream unchanged
    BLOCK = "block"  # synthesize an error back to the client
    APPROVED = "approved"  # was held, approval granted -> forward


@dataclass
class CallOutcome:
    verdict: Verdict
    decision: Decision
    approval_id: str | None = None
    message: str = ""


# JSON-RPC error code we return for a policy denial. -32001 is in the
# implementation-defined server-error range reserved by the spec.
POLICY_DENIED = -32001
APPROVAL_REQUIRED = -32002


class GatewayMediator:
    def __init__(
        self,
        plane: ControlPlane,
        server_name: str,
        *,
        agent: str = "unknown",
        principal: str = "anonymous",
        transport: Transport = Transport.STDIO,
        approval_mode: str = "deny",  # "deny" | "wait"
        approval_timeout: float = 120.0,
        poll_interval: float = 1.0,
    ):
        self.plane = plane
        self.agent = agent
        self.principal = principal
        self.transport = transport
        self.approval_mode = approval_mode
        self.approval_timeout = approval_timeout
        self.poll_interval = poll_interval
        self.server: MCPServer = plane.registry.get_by_name(server_name) or MCPServer(
            name=server_name, source="gateway", status=ServerStatus.DISCOVERED
        )

    # ----- tools/list interception ---------------------------------------- #
    def on_tools_list(self, tools: list[dict]) -> list[dict]:
        """Learn & enrich the upstream tool surface; register the server.

        Returns the (possibly annotated) tool list to relay back to the client.
        Tools flagged as poisoned are kept but marked, and will be caught by the
        policy engine at call time — we record the finding immediately so the
        line-jumping window is itself audited.
        """
        enriched: list[MCPTool] = []
        for t in tools:
            tool = MCPTool(
                name=t.get("name", "unknown"),
                description=t.get("description", "") or "",
                input_schema=t.get("inputSchema") or t.get("input_schema") or {},
            )
            enrich_tool(tool)
            enriched.append(tool)

        self.server.tools = enriched
        self.server.transport = self.transport
        # Re-register (preserves approval status unless the fingerprint changed,
        # in which case the registry flags a possible rug pull and resets it).
        self.server = self.plane.registry.register(self.server)

        flagged = [t for t in enriched if t.findings]
        if flagged:
            self.plane.audit.record_event(
                "scan",
                server_id=self.server.id,
                server_name=self.server.name,
                reason=f"{len(flagged)} tool(s) flagged on tools/list (possible poisoning/line-jumping)",
                risk=self.server.risk,
                outcome="flagged",
                detail={"tools": [t.name for t in flagged]},
            )
        return tools  # relay original payload unchanged (we govern at call time)

    def _resolve_tool(self, tool_name: str) -> MCPTool:
        for t in self.server.tools:
            if t.name == tool_name:
                return t
        # Unknown tool (call before list, or hidden tool): synthesize & enrich.
        tool = MCPTool(name=tool_name, description="")
        enrich_tool(tool)
        return tool

    # ----- tools/call interception ---------------------------------------- #
    def authorize_call(self, tool_name: str, arguments: dict) -> CallOutcome:
        started = time.monotonic()
        tool = self._resolve_tool(tool_name)
        ctx = CallContext(
            server=self.server,
            tool=tool,
            arguments=arguments or {},
            agent=self.agent,
            principal=self.principal,
            transport=self.transport,
        )
        decision = self.plane.decide(ctx)
        latency = (time.monotonic() - started) * 1000

        if decision.effect == Effect.ALLOW:
            self.plane.audit.record_decision(ctx, decision, outcome="ok", latency_ms=latency)
            return CallOutcome(Verdict.FORWARD, decision)

        if decision.effect == Effect.DENY:
            self.plane.audit.record_decision(ctx, decision, outcome="blocked", latency_ms=latency)
            return CallOutcome(Verdict.BLOCK, decision, message=decision.reason)

        # REQUIRE_APPROVAL
        approval = self.plane.approvals.request(ctx, decision)
        self.plane.audit.record_decision(ctx, decision, outcome="pending", latency_ms=latency)

        if self.approval_mode == "wait":
            granted = self._wait_for_approval(approval.id)
            if granted is True:
                return CallOutcome(Verdict.APPROVED, decision, approval_id=approval.id)
            return CallOutcome(
                Verdict.BLOCK,
                decision,
                approval_id=approval.id,
                message=(
                    f"approval {approval.id} was denied or timed out"
                    if granted is False
                    else f"approval {approval.id} timed out"
                ),
            )

        # deny-with-instructions mode (default): do not hang the agent.
        return CallOutcome(
            Verdict.BLOCK,
            decision,
            approval_id=approval.id,
            message=(
                f"This call requires approval. Request '{approval.id}' is pending — "
                f"approve it with `mcpcp approvals approve {approval.id}` or in the "
                f"dashboard, then retry. Reason: {decision.reason}"
            ),
        )

    def _wait_for_approval(self, approval_id: str) -> bool | None:
        """Block until an approval is decided. True=approved, False=denied, None=timeout."""
        deadline = time.monotonic() + self.approval_timeout
        while time.monotonic() < deadline:
            approval = self.plane.approvals.get(approval_id)
            if approval and approval.status == ApprovalStatus.APPROVED:
                return True
            if approval and approval.status == ApprovalStatus.DENIED:
                return False
            time.sleep(self.poll_interval)
        return None

    # ----- response obligations ------------------------------------------- #
    def apply_obligations(self, decision: Decision, result_text: str) -> str:
        """Enforce response-side obligations such as secret redaction."""
        if "redact:secrets" in decision.obligations:
            return _redact_secrets(result_text)
        return result_text


_SECRET_RES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-(ant-)?[A-Za-z0-9_\-]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END [^-]*-----"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"),
]


def _redact_secrets(text: str) -> str:
    for rx in _SECRET_RES:
        text = rx.sub("***redacted-by-mcp-control-plane***", text)
    return text
