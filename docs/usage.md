# Usage

A practical guide to installing `mcp-control-plane`, scanning your machine for MCP servers, reviewing and approving them, putting the gateway in front of a real server, running the API and dashboard, and wiring it into CI. For the concepts behind these commands see the [architecture](architecture.md), [policy model](policy-model.md), and [security model](security-model.md) docs. For the project overview see the [README](../README.md).

---

## Installation

Requires **Python 3.11+**. Install the CLI with `pipx` (recommended — isolated, on your PATH) or `pip`:

```bash
pipx install mcp-control-plane
# or
pip install mcp-control-plane
```

This provides the `mcpcp` command. Verify:

```bash
mcpcp --help
```

State lives under `~/.mcpcp/` by default (a single SQLite file plus your policy). Nothing is created until you run a command that needs it.

---

## Where state lives & environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `MCPCP_HOME` | `~/.mcpcp` (or `./.mcpcp` if it exists) | Root directory for all state. |
| `MCPCP_DB` | `<home>/mcpcp.db` | SQLite database (servers, audit chain, approvals). |
| `MCPCP_POLICY` | `<home>/policy.yaml` | Active policy file. If absent, the secure `baseline` policy is used. |
| `MCPCP_HOST` | `127.0.0.1` | API bind host. |
| `MCPCP_PORT` | `8765` | API port. |
| `MCPCP_API_TOKEN` | _(unset)_ | Bearer token gating the API. **Unset = localhost-only.** Set this before exposing the API to a team. |

```
~/.mcpcp/
├── mcpcp.db        # servers, audit hash chain, approvals (single file)
└── policy.yaml     # your policy-as-code (optional; baseline used if missing)
```

---

## CLI workflows

### 1. Discover what's already installed

The scanner reads MCP configs across your installed clients (Claude Desktop, Cursor, Cline, Windsurf, Continue, Goose, Zed, Claude Code, VS Code project configs) and flags risky config hygiene — no server is launched.

```bash
mcpcp scan                       # scan user-level client configs
mcpcp scan --project .           # also scan committed configs in this repo
```

Findings carry codes (`MCP-SEC-*` secrets, `MCP-NET-*` transport, `MCP-SUP-*` supply chain, `MCP-CMD-*` command injection, `MCP-HIL-*` human-in-the-loop bypass), a severity, and a concrete remediation. See the [threat model](threat-model.md) for what each maps to.

### 2. Review and approve servers in the registry

```bash
mcpcp servers list                       # inventory, sorted by risk
mcpcp servers list --status pending      # only those awaiting review
mcpcp servers show <server_id>           # tools, capabilities, risk factors, fingerprint
mcpcp servers approve <server_id> --by you --note "reviewed, read-only fs"
mcpcp servers reject  <server_id> --by you --note "ships a shell tool"
```

Approval is a hard gate: under the default policy, even an allow rule is downgraded to require-approval for a server that is not `approved` (see [security model](security-model.md#secure-by-default)).

### 3. Inspect and explain policy

```bash
mcpcp policy show                        # render the active policy
mcpcp policy explain \
  --server filesystem --tool write_file \
  --arg path=/etc/hosts                  # full decision + rule-by-rule trace
```

`policy explain` is the offline way to answer "what would happen if the agent called this?" — it prints the effect, reason, obligations, and the ordered trace (see [policy model](policy-model.md#a-sample-decision-trace)).

### 4. Work the approval queue

When a call is parked for approval (by policy), it shows up here:

```bash
mcpcp approvals list                     # pending requests with reason + risk
mcpcp approvals approve <approval_id> --by you --note "ok for this run"
mcpcp approvals deny    <approval_id> --by you --note "wrong path"
```

In the gateway's default `deny` mode the agent is told an approval is pending and to retry; in `wait` mode the call blocks until you decide here or in the dashboard.

### 5. Audit the trail

```bash
mcpcp audit tail                         # recent decisions, approvals, scans, registry changes
mcpcp audit tail --kind tool_call        # filter by event kind
mcpcp audit verify                       # recompute the hash chain
```

`audit verify` returns OK or the id of the first event that fails the integrity check — the way silent edits are detected (see [security model](security-model.md#tamper-evident-audit-chain)).

### 6. Run the API + dashboard

```bash
mcpcp serve                              # start FastAPI + dashboard on 127.0.0.1:8765
# team deployment:
MCPCP_API_TOKEN=$(openssl rand -hex 24) MCPCP_HOST=0.0.0.0 mcpcp serve
```

The dashboard spans servers, policy, approvals, and audit. With no token the API binds to localhost only; with a token every `/api` route requires `Authorization: Bearer <token>`.

### 7. Try it without real servers

```bash
mcpcp demo seed                          # load demo servers, tools, and events
```

`demo seed` populates the registry and audit trail with representative data (including a deliberately poisoned tool and a risky config) so you can explore the dashboard, policy explain, and approvals immediately.

---

## Putting the gateway in front of a real MCP server

The gateway wraps an upstream MCP server: your client launches `mcpcp gateway run` *as if it were the server*, and the gateway spawns the real server as a subprocess, relaying JSON-RPC and enforcing policy on every `tools/call`.

Run it standalone to see the shape:

```bash
mcpcp gateway run --server filesystem -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

Everything after `--` is the real server command. `--server` names the registry entry the traffic is attributed to (its approval status and policy apply).

### Claude Desktop / Cursor `mcp.json`

Replace the server's `command`/`args` with the gateway, and move the real command after `--`. Before:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

After (governed by the control plane):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpcp",
      "args": [
        "gateway", "run", "--server", "filesystem",
        "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

The same pattern works for Cursor (`~/.cursor/mcp.json`) and any client using the `mcpServers` shape. From the client's perspective nothing changed; from yours, every tool call is now evaluated, audited, and (where risky) gated on approval, and secret-bearing responses are redacted.

To make the gateway block-and-wait for approval instead of returning a retry instruction, add `--approval-mode wait` (optionally `--approval-timeout <seconds>`) to the gateway args.

---

## CI usage

Fail a pipeline when a checked-in MCP config introduces a high-or-worse risk (hardcoded secret, plaintext transport, unpinned remote code, auto-approve bypass, …):

```bash
mcpcp scan --ci --fail-on high --project .
```

- `--ci` emits machine-readable output suitable for a pipeline.
- `--fail-on high` sets the threshold; the process exits non-zero when the worst finding is at or above it (`--fail-on critical` to gate only on the most severe).
- `--project .` includes repo-committed configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.continue/config.json`) alongside (or instead of) user-level ones.

Example GitHub Actions step:

```yaml
- name: MCP config scan
  run: |
    pipx install mcp-control-plane
    mcpcp scan --ci --fail-on high --project .
```

This catches the most common "secret committed in an MCP config" and "shadow server added without review" classes before they merge.
