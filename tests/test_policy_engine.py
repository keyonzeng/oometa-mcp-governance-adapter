from mcp_control_plane.models import (
    CallContext,
    Capability,
    Effect,
    MCPServer,
    MCPTool,
    RiskLevel,
    ServerStatus,
)
from mcp_control_plane.policy import evaluate
from mcp_control_plane.policy.default_policies import baseline_policy, strict_policy
from mcp_control_plane.policy.rules import ArgMatch, Match, Policy, Rule


def _ctx(tool, status=ServerStatus.APPROVED, args=None, **tkw):
    server = MCPServer(name="s", status=status, tools=[tool])
    return CallContext(server=server, tool=tool, arguments=args or {})


def test_exec_is_denied():
    t = MCPTool(name="run", capabilities=[Capability.PROCESS_EXEC], risk=RiskLevel.CRITICAL)
    d = evaluate(baseline_policy(), _ctx(t))
    assert d.effect == Effect.DENY


def test_readonly_on_approved_allowed():
    t = MCPTool(name="read", capabilities=[Capability.FILESYSTEM_READ], risk=RiskLevel.MEDIUM)
    d = evaluate(baseline_policy(), _ctx(t))
    assert d.effect == Effect.ALLOW


def test_write_requires_approval():
    t = MCPTool(name="write", capabilities=[Capability.FILESYSTEM_WRITE], risk=RiskLevel.HIGH)
    d = evaluate(baseline_policy(), _ctx(t))
    assert d.effect == Effect.REQUIRE_APPROVAL


def test_unapproved_server_downgrades_allow():
    # A rule explicitly allows, but the server is not approved -> secure-by-default
    # downgrade kicks in and is recorded in the trace.
    pol = Policy(
        name="t", default_effect=Effect.DENY,
        rules=[Rule(id="allow-read", effect=Effect.ALLOW, priority=10,
                    when=Match(capabilities_any=[Capability.FILESYSTEM_READ]))],
    )
    t = MCPTool(name="read", capabilities=[Capability.FILESYSTEM_READ], risk=RiskLevel.LOW)
    d = evaluate(pol, _ctx(t, status=ServerStatus.DISCOVERED))
    assert d.effect == Effect.REQUIRE_APPROVAL
    assert any("post:unapproved-server" in step["rule"] for step in d.trace)


def test_secret_path_argument_denied():
    t = MCPTool(name="read", capabilities=[Capability.FILESYSTEM_READ], risk=RiskLevel.LOW)
    d = evaluate(baseline_policy(), _ctx(t, args={"path": "/home/u/.ssh/id_rsa"}))
    assert d.effect == Effect.DENY


def test_strict_policy_denies_by_default():
    # Strict keeps the inherited 'allow readonly on approved' rule, so deny-by-default
    # is observed on a server that is NOT approved (and an unmatched capability).
    t = MCPTool(name="mystery", capabilities=[Capability.UNKNOWN], risk=RiskLevel.MEDIUM)
    d = evaluate(strict_policy(), _ctx(t, status=ServerStatus.DISCOVERED))
    assert d.effect == Effect.DENY


def test_secrets_capability_attaches_redaction_obligation():
    pol = Policy(
        name="t", default_effect=Effect.DENY,
        rules=[Rule(id="allow-secrets", effect=Effect.ALLOW, priority=10,
                    when=Match(capabilities_any=[Capability.SECRETS]))],
    )
    t = MCPTool(name="vault", capabilities=[Capability.SECRETS], risk=RiskLevel.HIGH)
    d = evaluate(pol, _ctx(t))
    assert d.effect == Effect.ALLOW
    assert "redact:secrets" in d.obligations


def test_priority_first_match_wins():
    t = MCPTool(name="x", capabilities=[Capability.NETWORK], risk=RiskLevel.MEDIUM)
    pol = Policy(
        name="t", default_effect=Effect.DENY,
        rules=[
            Rule(id="low-allow", effect=Effect.ALLOW, priority=1, when=Match(capabilities_any=[Capability.NETWORK])),
            Rule(id="high-deny", effect=Effect.DENY, priority=100, when=Match(capabilities_any=[Capability.NETWORK])),
        ],
    )
    d = evaluate(pol, _ctx(t))
    assert d.effect == Effect.DENY
    assert d.matched_rule == "high-deny"


def test_arg_match_field_specific():
    m = Match(arg_matches=[ArgMatch(field="url", regex=r"ngrok")])
    t = MCPTool(name="x")
    ok, _ = m.evaluate(_ctx(t, args={"url": "http://x.ngrok.io"}))
    assert ok
    bad, _ = m.evaluate(_ctx(t, args={"other": "http://x.ngrok.io"}))
    assert not bad
