"""Domain model for mcp-control-plane.

These Pydantic models are the contract shared by every subsystem (registry,
policy, gateway, audit, approvals, API, CLI). Keep them transport-agnostic and
free of storage concerns.
"""

from __future__ import annotations

import enum
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    """Time-sortable-ish opaque id without external deps."""
    import secrets

    return f"{prefix}_{secrets.token_hex(8)}"


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Transport(str, enum.Enum):
    STDIO = "stdio"
    HTTP = "http"  # Streamable HTTP (the current MCP HTTP transport)
    SSE = "sse"  # legacy / deprecated, recognised for discovery only
    UNKNOWN = "unknown"


class ServerStatus(str, enum.Enum):
    DISCOVERED = "discovered"  # found by the scanner, not yet reviewed
    PENDING = "pending"  # submitted for review
    APPROVED = "approved"  # allowed to be proxied
    REJECTED = "rejected"  # explicitly disallowed
    DISABLED = "disabled"  # previously approved, now turned off


class RiskLevel(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {"info": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}[self.value]


class Effect(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


# Capability tags describe *what a tool can do* in security terms. They are the
# vocabulary policies match on, so they are intentionally coarse and stable.
class Capability(str, enum.Enum):
    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_WRITE = "filesystem.write"
    PROCESS_EXEC = "process.exec"
    NETWORK = "network"
    SECRETS = "secrets"
    DATABASE_READ = "database.read"
    DATABASE_WRITE = "database.write"
    CODE_EXECUTION = "code.execution"
    EMAIL_SEND = "messaging.send"
    PAYMENT = "payment"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------- #
# Core entities
# --------------------------------------------------------------------------- #
class MCPTool(BaseModel):
    """A single tool advertised by an MCP server (from ``tools/list``)."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[Capability] = Field(default_factory=list)
    risk: RiskLevel = RiskLevel.LOW
    # Free-form notes from heuristics (e.g. "tool description contains hidden
    # instructions" -> possible tool-poisoning).
    findings: list[str] = Field(default_factory=list)


class MCPServer(BaseModel):
    """A registered (or merely discovered) MCP server."""

    id: str = Field(default_factory=lambda: new_id("srv"))
    name: str
    description: str = ""
    transport: Transport = Transport.STDIO

    # stdio transport
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list)  # names only, never values

    # http/sse transport
    url: str | None = None

    status: ServerStatus = ServerStatus.DISCOVERED
    source: str = "manual"  # e.g. "scanner:claude-desktop", "manual", "import"
    owner: str | None = None
    tags: list[str] = Field(default_factory=list)

    risk: RiskLevel = RiskLevel.LOW
    risk_score: int = 0
    risk_factors: list[str] = Field(default_factory=list)
    # Static configuration findings carried over from the scanner (kept separate
    # from runtime tool risk). Each item: {code,title,severity,detail,remediation}.
    config_findings: list[dict[str, Any]] = Field(default_factory=list)

    tools: list[MCPTool] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    reviewed_at: datetime | None = None
    reviewed_by: str | None = None
    review_note: str | None = None

    def fingerprint(self) -> str:
        """Stable identity used to detect 'rug pulls' (a server silently changing
        what it runs or which tools it exposes)."""
        material = {
            "command": self.command,
            "args": self.args,
            "url": self.url,
            "tools": sorted(
                (t.name, _sha(t.description), _sha(json.dumps(t.input_schema, sort_keys=True)))
                for t in self.tools
            ),
        }
        return _sha(json.dumps(material, sort_keys=True, default=str))


class CallContext(BaseModel):
    """Everything the policy engine needs to judge one tool call."""

    server: MCPServer
    tool: MCPTool
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent: str = "unknown"  # the MCP client / agent making the call
    principal: str = "anonymous"  # human/service identity, if known
    transport: Transport = Transport.STDIO
    timestamp: datetime = Field(default_factory=utcnow)

    @property
    def capabilities(self) -> list[Capability]:
        return self.tool.capabilities

    def arguments_digest(self) -> str:
        return _sha(json.dumps(self.arguments, sort_keys=True, default=str))


class Decision(BaseModel):
    """The explainable result of evaluating a CallContext against a Policy."""

    effect: Effect
    reason: str
    matched_rule: str | None = None
    risk: RiskLevel = RiskLevel.LOW
    obligations: list[str] = Field(default_factory=list)  # e.g. "redact:secrets"
    # Ordered trace of every rule considered -> full explainability.
    trace: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.effect == Effect.ALLOW


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evt"))
    timestamp: datetime = Field(default_factory=utcnow)
    kind: str  # "tool_call", "decision", "approval", "scan", "registry"
    agent: str = "unknown"
    principal: str = "anonymous"
    server_id: str | None = None
    server_name: str | None = None
    tool: str | None = None
    effect: Effect | None = None
    reason: str | None = None
    risk: RiskLevel | None = None
    arguments_digest: str | None = None
    matched_rule: str | None = None
    latency_ms: float | None = None
    outcome: str | None = None  # "ok", "error", "blocked", "pending"
    detail: dict[str, Any] = Field(default_factory=dict)
    # Hash chain (prev_hash -> this) makes the audit log tamper-evident.
    prev_hash: str | None = None
    hash: str | None = None

    def compute_hash(self, prev_hash: str | None) -> str:
        payload = self.model_dump(
            mode="json", exclude={"hash", "prev_hash"}, exclude_none=False
        )
        return _sha(json.dumps(payload, sort_keys=True, default=str) + (prev_hash or ""))


class Approval(BaseModel):
    id: str = Field(default_factory=lambda: new_id("apr"))
    status: ApprovalStatus = ApprovalStatus.PENDING
    agent: str = "unknown"
    principal: str = "anonymous"
    server_id: str | None = None
    server_name: str | None = None
    tool: str | None = None
    arguments_preview: dict[str, Any] = Field(default_factory=dict)
    # Exact-argument digest so an approval can be matched on retry (a *grant*),
    # rather than re-prompting for an identical call.
    arguments_digest: str | None = None
    reason: str = ""
    risk: RiskLevel = RiskLevel.MEDIUM
    requested_at: datetime = Field(default_factory=utcnow)
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_note: str | None = None
    # When approved, the grant is valid (re-usable for the identical call) until
    # this time. None means not yet granted.
    expires_at: datetime | None = None

    def is_active_grant(self, now: datetime | None = None) -> bool:
        now = now or utcnow()
        return (
            self.status == ApprovalStatus.APPROVED
            and self.expires_at is not None
            and self.expires_at > now
        )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def redact_arguments(arguments: dict[str, Any], max_len: int = 120) -> dict[str, Any]:
    """Produce a safe-to-store preview of arguments.

    Never persist raw secret-looking values: long opaque strings and keys that
    look sensitive are masked. This enforces the 'never silently expose secrets'
    principle even inside our own audit store.
    """
    sensitive = ("token", "secret", "password", "passwd", "apikey", "api_key", "key", "auth")
    out: dict[str, Any] = {}
    for k, v in arguments.items():
        kl = k.lower()
        if any(s in kl for s in sensitive):
            out[k] = "***redacted***"
        elif isinstance(v, str) and len(v) > max_len:
            out[k] = v[:max_len] + f"… (+{len(v) - max_len} chars)"
        elif isinstance(v, (dict, list)):
            out[k] = f"<{type(v).__name__} len={len(v)}>"
        else:
            out[k] = v
    return out
