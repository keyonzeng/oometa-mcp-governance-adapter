"""The policy decision point (PDP).

``evaluate(policy, ctx)`` turns a :class:`CallContext` into an explainable
:class:`Decision`. The algorithm is intentionally simple and auditable:

    1. Walk rules in priority order. The first matching rule wins.
    2. If no rule matches, fall back to ``policy.default_effect``.
    3. Apply secure-by-default *post-conditions*: an ALLOW that targets a server
       which is not ``approved`` is downgraded to the policy's configured
       ``unapproved_server_effect`` (default: require approval).
    4. Attach obligations (e.g. secret redaction) and a full decision trace.

Every step is recorded in ``Decision.trace`` so any allow/deny can be explained
after the fact — the basis of 'explainable security decisions'.
"""

from __future__ import annotations

from mcp_control_plane.models import (
    CallContext,
    Capability,
    Decision,
    Effect,
    ServerStatus,
)
from mcp_control_plane.policy.rules import Policy


def evaluate(policy: Policy, ctx: CallContext) -> Decision:
    trace: list[dict] = []
    winner = None
    matched_reasons: list[str] = []

    for rule in policy.sorted_rules():
        matched, reasons = rule.when.evaluate(ctx)
        trace.append(
            {
                "rule": rule.id,
                "priority": rule.priority,
                "effect": rule.effect.value,
                "matched": matched,
                "why": reasons,
            }
        )
        if matched and winner is None:
            winner = rule
            matched_reasons = reasons
            # Do not break: we keep evaluating so the trace shows everything,
            # but the first (highest-priority) match is the decision.

    if winner is not None:
        effect = winner.effect
        reason = winner.reason or winner.description or f"matched rule '{winner.id}'"
        matched_rule = winner.id
        risk = winner.risk or ctx.tool.risk
        obligations = list(winner.obligations)
    else:
        effect = policy.default_effect
        reason = f"no rule matched; policy default is '{policy.default_effect.value}'"
        matched_rule = None
        risk = ctx.tool.risk
        obligations = []
        trace.append(
            {"rule": "<default>", "effect": effect.value, "matched": True, "why": [reason]}
        )

    # ---- secure-by-default post-conditions -------------------------------- #
    if effect == Effect.ALLOW and ctx.server.status != ServerStatus.APPROVED:
        downgraded = policy.settings.unapproved_server_effect
        trace.append(
            {
                "rule": "<post:unapproved-server>",
                "effect": downgraded.value,
                "matched": True,
                "why": [
                    f"target server '{ctx.server.name}' status is "
                    f"'{ctx.server.status.value}', not 'approved'"
                ],
            }
        )
        reason = (
            f"{reason}; but server '{ctx.server.name}' is not approved, so the "
            f"allow was downgraded to '{downgraded.value}'"
        )
        effect = downgraded

    # Secret redaction obligation on any surviving allow.
    if (
        effect == Effect.ALLOW
        and policy.settings.redact_secrets
        and Capability.SECRETS in set(ctx.capabilities)
        and "redact:secrets" not in obligations
    ):
        obligations.append("redact:secrets")
        trace.append(
            {
                "rule": "<post:redact-secrets>",
                "effect": "allow",
                "matched": True,
                "why": ["tool touches secrets; attaching redact:secrets obligation"],
            }
        )

    if matched_reasons:
        reason = f"{reason} ({'; '.join(matched_reasons)})"

    return Decision(
        effect=effect,
        reason=reason,
        matched_rule=matched_rule,
        risk=risk,
        obligations=obligations,
        trace=trace,
    )
