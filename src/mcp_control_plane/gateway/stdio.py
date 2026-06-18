"""stdio transport adapter for the gateway.

The MCP client launches *the gateway* as if it were the server. The gateway in
turn spawns the real upstream server as a subprocess and relays newline-delimited
JSON-RPC between the two, consulting the :class:`GatewayMediator` on every
``tools/call`` (enforcement) and ``tools/list`` (discovery). Everything else is
passed through untouched, so the gateway is transparent to both sides.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from mcp_control_plane.core import ControlPlane
from mcp_control_plane.gateway.mediator import GatewayMediator, Verdict
from mcp_control_plane.models import Transport


def _dump(obj: Any) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def _error_response(req_id: Any, code: int, message: str, data: dict | None = None) -> dict:
    err: dict = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _tool_error_result(req_id: Any, message: str) -> dict:
    """A successful-shaped tools/call result that carries an error flag.

    MCP tool execution errors are reported as a normal result with
    ``isError: true`` so the model sees them, rather than a protocol error.
    """
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        },
    }


class StdioGateway:
    def __init__(self, plane: ControlPlane, mediator: GatewayMediator):
        self.plane = plane
        self.mediator = mediator
        # id -> ("tools/list", None) | ("tools/call", decision)
        self._pending: dict[Any, tuple[str, Any]] = {}

    async def run(self, command: str, args: list[str], env: dict | None = None) -> int:
        full_env = {**os.environ, **(env or {})}
        proc = await asyncio.create_subprocess_exec(
            command,
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # let the upstream log straight to our stderr
            env=full_env,
        )

        client_reader = await _stdin_reader()
        client_writer = sys.stdout.buffer

        await asyncio.gather(
            self._pump_client_to_server(client_reader, proc, client_writer),
            self._pump_server_to_client(proc, client_writer),
        )
        return await proc.wait()

    # ----- client -> server ---------------------------------------------- #
    async def _pump_client_to_server(self, reader, proc, client_writer) -> None:
        while True:
            line = await reader.readline()
            if not line:
                break
            msg = _parse(line)
            if msg is None:
                proc.stdin.write(line)
                await proc.stdin.drain()
                continue

            method = msg.get("method")
            req_id = msg.get("id")

            if method == "tools/call":
                handled = await self._handle_tool_call(msg, proc, client_writer)
                if handled:
                    continue  # blocked: response already sent to client
            elif method == "tools/list" and req_id is not None:
                self._pending[req_id] = ("tools/list", None)

            proc.stdin.write(_dump(msg))
            await proc.stdin.drain()

        try:
            proc.stdin.close()
        except Exception:
            pass

    async def _handle_tool_call(self, msg: dict, proc, client_writer) -> bool:
        """Return True if the call was blocked (client already answered)."""
        req_id = msg.get("id")
        params = msg.get("params") or {}
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments") or {}

        outcome = await asyncio.to_thread(
            self.mediator.authorize_call, tool_name, arguments
        )

        if outcome.verdict in (Verdict.FORWARD, Verdict.APPROVED):
            # Track so we can apply response obligations (e.g. redaction).
            self._pending[req_id] = ("tools/call", outcome.decision)
            return False

        # BLOCK -> answer the client ourselves with an explainable error result.
        client_writer.write(
            _dump(
                _tool_error_result(
                    req_id,
                    f"[mcp-control-plane] blocked: {outcome.message}",
                )
            )
        )
        client_writer.flush()
        return True

    # ----- server -> client ---------------------------------------------- #
    async def _pump_server_to_client(self, proc, client_writer) -> None:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            msg = _parse(line)
            if msg is None:
                client_writer.write(line)
                client_writer.flush()
                continue

            req_id = msg.get("id")
            method = msg.get("method")

            # Rug-pull signal: upstream announces its tool list changed.
            if method == "notifications/tools/list_changed":
                self.plane.audit.record_event(
                    "scan",
                    server_id=self.mediator.server.id,
                    server_name=self.mediator.server.name,
                    reason="upstream sent tools/list_changed (re-review recommended)",
                    outcome="flagged",
                )

            if req_id in self._pending:
                kind, decision = self._pending.pop(req_id)
                if kind == "tools/list":
                    msg = self._intercept_tools_list(msg)
                elif kind == "tools/call" and decision is not None:
                    msg = self._apply_call_obligations(msg, decision)

            client_writer.write(_dump(msg))
            client_writer.flush()

    def _intercept_tools_list(self, msg: dict) -> dict:
        result = msg.get("result") or {}
        tools = result.get("tools")
        if isinstance(tools, list):
            self.mediator.on_tools_list(tools)
        return msg

    def _apply_call_obligations(self, msg: dict, decision) -> dict:
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        content = result.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    block["text"] = self.mediator.apply_obligations(
                        decision, block.get("text", "")
                    )
        return msg


def _parse(line: bytes) -> dict | None:
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


async def _stdin_reader() -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


def run_stdio_gateway(
    plane: ControlPlane,
    server_name: str,
    command: str,
    args: list[str],
    *,
    env: dict | None = None,
    agent: str = "unknown",
    principal: str = "anonymous",
    approval_mode: str = "deny",
    approval_timeout: float = 120.0,
) -> int:
    mediator = GatewayMediator(
        plane,
        server_name,
        agent=agent,
        principal=principal,
        transport=Transport.STDIO,
        approval_mode=approval_mode,
        approval_timeout=approval_timeout,
    )
    gateway = StdioGateway(plane, mediator)
    return asyncio.run(gateway.run(command, args, env=env))
