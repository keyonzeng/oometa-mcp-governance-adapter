from mcp_control_plane.models import (
    AuditEvent,
    Effect,
    RiskLevel,
    redact_arguments,
)


def test_redact_arguments_masks_sensitive_keys_and_long_values():
    out = redact_arguments(
        {"api_key": "secret123", "path": "/tmp/a", "blob": "x" * 500, "nested": {"a": 1}}
    )
    assert out["api_key"] == "***redacted***"
    assert out["path"] == "/tmp/a"
    assert out["blob"].endswith("chars)")
    assert out["nested"].startswith("<dict")


def test_risk_level_scores_are_monotonic():
    levels = [RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert [x.score for x in levels] == sorted(x.score for x in levels)


def test_audit_event_hash_depends_on_prev():
    e = AuditEvent(kind="tool_call", effect=Effect.ALLOW)
    h1 = e.compute_hash(None)
    h2 = e.compute_hash("deadbeef")
    assert h1 != h2
    assert e.compute_hash(None) == h1  # deterministic
