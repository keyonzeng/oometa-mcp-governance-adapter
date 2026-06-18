"""Policy-as-code: the rule model and matcher.

A *policy* is a small, reviewable YAML document. It is a list of ordered rules
plus a secure default. Each rule has a ``when`` block (the match conditions) and
an ``effect`` (allow / deny / require_approval). This module knows how to load
policies and decide whether a single rule matches a :class:`CallContext`; the
overall evaluation lives in :mod:`mcp_control_plane.policy.engine`.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

import yaml
from pydantic import BaseModel, Field

from mcp_control_plane.models import (
    CallContext,
    Capability,
    Effect,
    RiskLevel,
)

_RISK_ORDER = {r: i for i, r in enumerate([RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL])}


class ArgMatch(BaseModel):
    field: str = "*"  # arg name, or "*" for any value (recursively)
    regex: str
    description: str | None = None


class Match(BaseModel):
    """Conditions for a rule. All present conditions must hold (logical AND)."""

    server_status: list[str] | None = None
    server_name: list[str] | None = None  # glob patterns
    server_tags_any: list[str] | None = None
    tool_name: list[str] | None = None  # glob patterns
    agent: list[str] | None = None  # glob patterns
    capabilities_any: list[Capability] | None = None
    capabilities_all: list[Capability] | None = None
    capabilities_none: list[Capability] | None = None
    risk_at_least: RiskLevel | None = None
    arg_matches: list[ArgMatch] | None = None

    def evaluate(self, ctx: CallContext) -> tuple[bool, list[str]]:
        """Return (matched, reasons-it-matched)."""
        reasons: list[str] = []
        caps = set(ctx.capabilities)

        if self.server_status is not None:
            if ctx.server.status.value not in self.server_status:
                return False, []
            reasons.append(f"server status is {ctx.server.status.value}")

        if self.server_name is not None:
            if not any(fnmatch.fnmatch(ctx.server.name, p) for p in self.server_name):
                return False, []
            reasons.append(f"server name matches {self.server_name}")

        if self.server_tags_any is not None:
            if not (set(self.server_tags_any) & set(ctx.server.tags)):
                return False, []
            reasons.append("server has a matching tag")

        if self.tool_name is not None:
            if not any(fnmatch.fnmatch(ctx.tool.name, p) for p in self.tool_name):
                return False, []
            reasons.append(f"tool name matches {self.tool_name}")

        if self.agent is not None:
            if not any(fnmatch.fnmatch(ctx.agent, p) for p in self.agent):
                return False, []
            reasons.append(f"agent matches {self.agent}")

        if self.capabilities_any is not None:
            hit = caps & set(self.capabilities_any)
            if not hit:
                return False, []
            reasons.append(f"tool has capability {sorted(c.value for c in hit)}")

        if self.capabilities_all is not None:
            if not set(self.capabilities_all) <= caps:
                return False, []
            reasons.append(f"tool has all of {[c.value for c in self.capabilities_all]}")

        if self.capabilities_none is not None:
            bad = caps & set(self.capabilities_none)
            if bad:
                return False, []
            reasons.append(f"tool lacks {[c.value for c in self.capabilities_none]}")

        if self.risk_at_least is not None:
            if _RISK_ORDER[ctx.tool.risk] < _RISK_ORDER[self.risk_at_least]:
                return False, []
            reasons.append(f"tool risk >= {self.risk_at_least.value}")

        if self.arg_matches is not None:
            hit_any = False
            for am in self.arg_matches:
                if _arg_matches(ctx.arguments, am):
                    hit_any = True
                    reasons.append(am.description or f"argument matched /{am.regex}/")
            if not hit_any:
                return False, []

        return True, reasons


class Rule(BaseModel):
    id: str
    description: str = ""
    effect: Effect
    when: Match = Field(default_factory=Match)
    reason: str | None = None
    priority: int = 0
    risk: RiskLevel | None = None
    obligations: list[str] = Field(default_factory=list)


class PolicySettings(BaseModel):
    # What to do with calls to servers that are not 'approved' in the registry.
    unapproved_server_effect: Effect = Effect.REQUIRE_APPROVAL
    # If a winning ALLOW touches secrets, attach a redaction obligation.
    redact_secrets: bool = True


class Policy(BaseModel):
    version: int = 1
    name: str = "unnamed"
    description: str = ""
    default_effect: Effect = Effect.REQUIRE_APPROVAL  # secure-by-default
    settings: PolicySettings = Field(default_factory=PolicySettings)
    rules: list[Rule] = Field(default_factory=list)

    def sorted_rules(self) -> list[Rule]:
        # Highest priority first; stable for equal priorities (file order).
        return sorted(self.rules, key=lambda r: -r.priority)

    @classmethod
    def from_yaml(cls, text: str) -> Policy:
        data = yaml.safe_load(text) or {}
        return cls.model_validate(data)

    @classmethod
    def from_file(cls, path: str) -> Policy:
        with open(path, encoding="utf-8") as fh:
            return cls.from_yaml(fh.read())


def _arg_matches(arguments: dict[str, Any], am: ArgMatch) -> bool:
    pattern = re.compile(am.regex)

    def walk(value: Any) -> bool:
        if isinstance(value, str):
            return bool(pattern.search(value))
        if isinstance(value, dict):
            return any(walk(v) for v in value.values())
        if isinstance(value, list):
            return any(walk(v) for v in value)
        return False

    if am.field == "*":
        return walk(arguments)
    if am.field in arguments:
        return walk(arguments[am.field])
    return False
