"""Built-in policies shipped with the control plane.

``baseline_policy`` is the secure-by-default policy used when no ``policy.yaml``
exists yet: read-only tools on approved servers flow freely, everything that can
write / execute / spend / exfiltrate requires explicit approval, and outright
command execution is denied. These are expressed in the same rule model users
author by hand, so the defaults are themselves a worked example.
"""

from __future__ import annotations

from mcp_control_plane.models import Capability, Effect, RiskLevel
from mcp_control_plane.policy.rules import (
    ArgMatch,
    Match,
    Policy,
    PolicySettings,
    Rule,
)


def baseline_policy() -> Policy:
    return Policy(
        name="baseline",
        description=(
            "Secure-by-default baseline: allow read-only tools on approved servers, "
            "require approval for state-changing tools, deny raw command execution "
            "and obvious secret exfiltration."
        ),
        default_effect=Effect.REQUIRE_APPROVAL,
        settings=PolicySettings(
            unapproved_server_effect=Effect.REQUIRE_APPROVAL,
            redact_secrets=True,
        ),
        rules=[
            Rule(
                id="deny-command-execution",
                description="Block arbitrary command/code execution over MCP",
                effect=Effect.DENY,
                priority=100,
                reason="Raw command or code execution via MCP is not permitted",
                when=Match(capabilities_any=[Capability.PROCESS_EXEC, Capability.CODE_EXECUTION]),
            ),
            Rule(
                id="deny-secret-exfiltration",
                description="Block tool calls whose arguments reference sensitive paths/material",
                effect=Effect.DENY,
                priority=95,
                reason="Argument references a sensitive path or credential material",
                when=Match(
                    arg_matches=[
                        ArgMatch(
                            field="*",
                            regex=r"(?i)(/\.ssh/|id_rsa|\.env\b|/\.aws/|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)",
                            description="argument references secret files / private keys",
                        )
                    ]
                ),
            ),
            Rule(
                id="approve-poisoned-tools",
                description="Quarantine tools flagged with prompt-injection findings",
                effect=Effect.REQUIRE_APPROVAL,
                priority=90,
                risk=RiskLevel.CRITICAL,
                reason="Tool was flagged for possible poisoning; needs human review",
                when=Match(risk_at_least=RiskLevel.CRITICAL),
            ),
            Rule(
                id="approve-destructive-and-spend",
                description="Require approval for destructive, financial or outbound-messaging tools",
                effect=Effect.REQUIRE_APPROVAL,
                priority=70,
                reason="High-impact action (write/destroy/pay/send) requires approval",
                when=Match(
                    capabilities_any=[
                        Capability.DESTRUCTIVE,
                        Capability.PAYMENT,
                        Capability.EMAIL_SEND,
                        Capability.DATABASE_WRITE,
                        Capability.FILESYSTEM_WRITE,
                    ]
                ),
            ),
            Rule(
                id="approve-unknown-capability",
                description="Quarantine tools whose capability we cannot determine",
                effect=Effect.REQUIRE_APPROVAL,
                priority=60,
                reason="Tool capability is unknown (not-yet-trusted); needs human review",
                when=Match(capabilities_any=[Capability.UNKNOWN]),
            ),
            Rule(
                id="allow-readonly-on-approved",
                description="Allow read-only tools on approved servers",
                effect=Effect.ALLOW,
                priority=40,
                reason="Read-only tool on an approved server",
                when=Match(
                    server_status=["approved"],
                    capabilities_none=[
                        Capability.FILESYSTEM_WRITE,
                        Capability.DATABASE_WRITE,
                        Capability.PROCESS_EXEC,
                        Capability.CODE_EXECUTION,
                        Capability.PAYMENT,
                        Capability.DESTRUCTIVE,
                        Capability.EMAIL_SEND,
                        Capability.SECRETS,
                        Capability.UNKNOWN,
                    ],
                ),
            ),
        ],
    )


def strict_policy() -> Policy:
    """Deny-by-default: nothing runs without an explicit allow rule or approval."""
    p = baseline_policy()
    p.name = "strict"
    p.description = "Deny-by-default; only explicitly approved, read-only tools pass."
    p.default_effect = Effect.DENY
    p.settings.unapproved_server_effect = Effect.DENY
    return p


def permissive_demo_policy() -> Policy:
    """Looser policy for local experimentation (NOT for shared/team use)."""
    p = baseline_policy()
    p.name = "permissive-demo"
    p.description = "Looser policy for local demos; do not use for team deployments."
    p.default_effect = Effect.ALLOW
    p.settings.unapproved_server_effect = Effect.REQUIRE_APPROVAL
    return p


BUILTIN_POLICIES = {
    "baseline": baseline_policy,
    "strict": strict_policy,
    "permissive-demo": permissive_demo_policy,
}
