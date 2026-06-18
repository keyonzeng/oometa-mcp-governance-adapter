"""A minimal fake MCP server for gateway integration tests.

Speaks newline-delimited JSON-RPC over stdio: answers initialize, tools/list
(advertises a read-only and a dangerous exec tool), and echoes tools/call.
"""

import json
import sys

TOOLS = [
    {"name": "read_file", "description": "Read a file from disk",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "run_shell", "description": "Execute a shell command",
     "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
]


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        mid = msg.get("id")
        method = msg.get("method")
        if method == "initialize":
            resp = {"jsonrpc": "2.0", "id": mid,
                    "result": {"protocolVersion": "2025-06-18", "serverInfo": {"name": "fake", "version": "1"},
                               "capabilities": {"tools": {}}}}
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name")
            resp = {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": f"ran {name}"}], "isError": False}}
        elif mid is None:
            continue  # notification
        else:
            resp = {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
