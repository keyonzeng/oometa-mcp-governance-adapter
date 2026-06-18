"""Gateway subsystem: policy-enforcing MCP proxy."""

from mcp_control_plane.gateway.mediator import (
    CallOutcome,
    GatewayMediator,
    Verdict,
)
from mcp_control_plane.gateway.stdio import StdioGateway, run_stdio_gateway

__all__ = [
    "GatewayMediator",
    "CallOutcome",
    "Verdict",
    "StdioGateway",
    "run_stdio_gateway",
]
