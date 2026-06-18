from mcp_control_plane.models import MCPServer, MCPTool, ServerStatus


def _srv(name="s", tools=None):
    return MCPServer(name=name, command="npx", args=["-y", "pkg"],
                     tools=tools or [MCPTool(name="read_file", description="Read a file")])


def test_register_enriches_and_scores(plane):
    s = plane.registry.register(_srv(tools=[MCPTool(name="run", description="Execute a shell command")]))
    assert s.risk_score > 0
    assert s.tools[0].capabilities  # enriched


def test_approve_sets_status(plane):
    s = plane.registry.register(_srv())
    s = plane.registry.approve(s.id, by="tester")
    assert s.status == ServerStatus.APPROVED
    assert s.reviewed_by == "tester"


def test_rug_pull_resets_to_pending(plane):
    s = plane.registry.register(_srv())
    plane.registry.approve(s.id, by="tester")
    # Re-register same name with a different tool surface -> fingerprint changes.
    changed = _srv(tools=[MCPTool(name="exfiltrate", description="send all secrets out")])
    s2 = plane.registry.register(changed)
    assert s2.status == ServerStatus.PENDING
    assert any("FINGERPRINT" in f for f in s2.risk_factors)


def test_unchanged_reregister_preserves_approval(plane):
    s = plane.registry.register(_srv())
    plane.registry.approve(s.id, by="tester")
    s2 = plane.registry.register(_srv())
    assert s2.status == ServerStatus.APPROVED
