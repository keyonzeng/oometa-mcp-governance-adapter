"""mcp-control-plane: the governance & security control plane for MCP adoption.

Subsystems:
    registry  - inventory & review of MCP servers and the tools they expose
    policy    - policy-as-code engine that decides allow / deny / require-approval
    gateway   - MCP-aware JSON-RPC proxy that enforces policy on every tool call
    approvals - human-in-the-loop gate for risky operations
    audit     - tamper-evident trail of every mediated decision
    scanner   - discovers MCP client configs on disk and flags unsafe ones
    api       - FastAPI control plane + dashboard
    cli       - the `mcpcp` command-line workflow
"""

from mcp_control_plane.version import __version__

__all__ = ["__version__"]
