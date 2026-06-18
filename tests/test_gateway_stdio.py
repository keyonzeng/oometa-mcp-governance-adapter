"""End-to-end test of the real stdio gateway driving a subprocess."""

import json
import os
import subprocess
import sys
from pathlib import Path

FAKE = Path(__file__).parent / "fake_mcp_server.py"


def _send(proc, obj):
    proc.stdin.write((json.dumps(obj) + "\n").encode())
    proc.stdin.flush()


def _read_until_id(proc, want_id, limit=20):
    for _ in range(limit):
        line = proc.stdout.readline()
        if not line:
            break
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == want_id:
            return msg
    return None


def test_stdio_gateway_blocks_dangerous_and_lists_tools(tmp_path):
    env = {**os.environ, "MCPCP_HOME": str(tmp_path / "mcpcp")}
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_control_plane", "gateway", "run",
         "-s", "fake", "--approval-mode", "deny", "--", sys.executable, str(FAKE)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env,
    )
    try:
        _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
        assert _read_until_id(proc, 1) is not None

        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tl = _read_until_id(proc, 2)
        assert tl and "tools" in tl["result"]

        # Dangerous exec call must be blocked by the gateway (isError result).
        _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "run_shell", "arguments": {"command": "rm -rf /"}}})
        blocked = _read_until_id(proc, 3)
        assert blocked is not None
        assert blocked["result"]["isError"] is True
        assert "mcp-control-plane" in blocked["result"]["content"][0]["text"]
    finally:
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=10)

    # The gateway should have registered the upstream server during tools/list.
    from mcp_control_plane.config import Settings
    from mcp_control_plane.core import ControlPlane
    plane = ControlPlane(settings=Settings(home=tmp_path / "mcpcp"))
    assert plane.registry.get_by_name("fake") is not None
