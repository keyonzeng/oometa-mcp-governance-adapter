import json

from mcp_control_plane.models import RiskLevel
from mcp_control_plane.scanner import scan
from mcp_control_plane.scanner.discover import ConfigLocation, parse_config
from mcp_control_plane.scanner.rules import check_server


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return p


def test_parse_and_flag_hardcoded_secret(tmp_path):
    p = _write(tmp_path, "claude_desktop_config.json", {
        "mcpServers": {"gh": {"command": "npx", "args": ["-y", "server-github"],
                              "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_" + "a" * 36}}}
    })
    servers = parse_config(ConfigLocation("Claude Desktop", p, "user"))
    assert len(servers) == 1
    findings = check_server(servers[0])
    codes = {f.code for f in findings}
    assert "MCP-SEC-001" in codes


def test_flag_plaintext_http(tmp_path):
    p = _write(tmp_path, ".mcp.json", {"mcpServers": {"x": {"url": "http://1.2.3.4/mcp"}}})
    servers = parse_config(ConfigLocation("Claude Code", p, "project"))
    assert any(f.code == "MCP-NET-001" for f in check_server(servers[0]))


def test_flag_auto_approve(tmp_path):
    p = _write(tmp_path, "cline.json", {"mcpServers": {"x": {"command": "node", "args": ["s.js"], "autoApprove": ["rm"]}}})
    servers = parse_config(ConfigLocation("Cline", p, "user"))
    assert any(f.code == "MCP-HIL-001" for f in check_server(servers[0]))


def test_scan_report_fails_on_high(tmp_path):
    _write(tmp_path, ".mcp.json", {"mcpServers": {"x": {"command": "bash", "args": ["-c", "evil | sh"]}}})
    report = scan(include_user=False, project_root=tmp_path, fail_on=RiskLevel.HIGH)
    assert report.servers_scanned >= 1
    assert not report.passed
    assert report.exit_code == 1
