# Architecture

`mcp-control-plane` is a self-hostable governance and security control plane for the Model Context Protocol (MCP). It puts a policy-enforcing gateway between an MCP client (agent) and the MCP servers it talks to, backs that with a server registry, an approval workflow, a tamper-evident audit trail, and a config scanner, and exposes the whole thing through a CLI, an HTTP API, and a dashboard. This document is the mental model: the seven subsystems, how a request flows through them, and where you extend it. For the project overview see the [README](../README.md).

---

## The seven subsystems

| Subsystem | Module | Responsibility |
|-----------|--------|----------------|
| **Registry** | `registry/service.py` | Inventory of every MCP server and its review status. Enriches tools, scores risk, detects rug pulls. The source of truth for *what exists* and *whether it is approved*. |
| **Policy** | `policy/` | Policy-as-code. The decision point (PDP): given one call context, returns an explainable allow / deny / require-approval `Decision`. |
| **Gateway** | `gateway/` | The enforcement point (PEP). A transparent proxy that sits in front of an upstream MCP server and consults the policy engine on every `tools/call`. |
| **Approvals** | `approvals/service.py` | Human-in-the-loop gate. Parks calls the policy flagged `require_approval` until a human approves or denies. |
| **Audit** | `audit/service.py` | Append-only, hash-chained activity trail. Records every decision, approval, scan, and registry change so history is tamper-evident. |
| **Scanner** | `scanner/` | Static analysis of MCP *configurations* on disk — discovers installed/shadow servers across clients and flags risky config hygiene without a live connection. |
| **API / CLI** | `api/app.py`, `cli/` | The human and machine surfaces. The CLI and the FastAPI app construct the same `ControlPlane` and share its database, audit chain, and policy. |

All seven are wired together by a single facade, `ControlPlane` (`core.py`). The CLI, the HTTP API, and the gateway each construct one `ControlPlane`, so there is exactly one definition of "the control plane" and no subsystem can diverge on which database, audit chain, or active policy it uses.

The shared contract between subsystems is the domain model in `models.py` (`MCPServer`, `MCPTool`, `Capability`, `Effect`, `Decision`, `AuditEvent`, `Approval`, `CallContext`). These Pydantic models are transport-agnostic and free of storage concerns, so every subsystem speaks the same vocabulary.

---

## Architecture diagram

```
                          ┌──────────────────────────────────────────────┐
                          │              CONTROL PLANE (core.py)           │
                          │                                                │
   MCP client / agent     │   ┌──────────┐   ┌──────────┐   ┌──────────┐  │
   (Claude Desktop,       │   │ Registry │   │  Policy  │   │ Approvals│  │
    Cursor, Cline, ...)   │   │ service  │   │  engine  │   │ service  │  │
        │                 │   └────┬─────┘   └────┬─────┘   └────┬─────┘  │
        │ JSON-RPC        │        │              │              │        │
        │ over stdio      │        └──────┬───────┴──────┬───────┘        │
        ▼                 │               │              │                │
  ┌───────────┐  parsed   │        ┌──────▼──────┐       │                │
  │  GATEWAY  │  messages  │        │   MEDIATOR   │◄─────┘                │
  │  (stdio   │──────────► │        │  (PEP core)  │                       │
  │  adapter) │            │        └──────┬──────┘                       │
  └─────┬─────┘            │               │ records                      │
        │ forward /        │        ┌──────▼──────┐                        │
        │ block            │        │    AUDIT    │ (append-only           │
        ▼                  │        │   service   │  hash chain)           │
  ┌───────────┐            │        └──────┬──────┘                        │
  │  Upstream │            │               │                               │
  │ MCP server│            │        ┌──────▼──────┐    ┌──────────┐        │
  │ (npx / uv │            │        │   SQLite     │◄───│ Scanner  │        │
  │  subproc) │            │        │ (~/.mcpcp/   │    │ (config  │        │
  └───────────┘            │        │   mcpcp.db)  │    │  discovery)       │
                           │        └──────┬──────┘    └──────────┘        │
                           └───────────────┼────────────────────────────────┘
                                           │
                            ┌──────────────┴──────────────┐
                            │   CLI  ·  HTTP API  ·  Dashboard
                            └─────────────────────────────┘
```

The gateway is the only component on the hot path between the agent and the upstream server. Everything else (registry, approvals, scanner, dashboard) operates on the same SQLite store out of band.

---

## Data flow: a `tools/call`

This is the enforcement path — the security-critical one.

```
agent ──tools/call──► gateway(stdio) ──► mediator.authorize_call()
                                              │
                                              │ build CallContext(server, tool, arguments, agent)
                                              ▼
                                        policy.evaluate()  ◄── the PDP
                                              │
                              ┌───────────────┼───────────────┐
                              ▼               ▼               ▼
                           ALLOW           DENY        REQUIRE_APPROVAL
                              │               │               │
                    record decision     record decision   request approval
                    (audit: ok)         (audit: blocked)  (audit: pending)
                              │               │               │
                     forward upstream   synth error      mode=deny: error w/ instructions
                              │          back to agent    mode=wait: block until decided
                              ▼                                  │
                     upstream result                      approved ──► forward upstream
                              │                            denied/timeout ──► error
                     apply obligations
                     (e.g. redact:secrets)
                              ▼
                        relay to agent
```

Step by step (`gateway/mediator.py::authorize_call`):

1. The stdio adapter (`gateway/stdio.py`) parses a JSON-RPC `tools/call` from the client and hands the tool name and arguments to the mediator.
2. The mediator resolves the tool (from the server's enriched tool list, or synthesizes and enriches it if unseen) and builds a `CallContext`.
3. `ControlPlane.decide()` runs `policy.evaluate()` — a pure function, no side effects — producing a `Decision` with an effect, a human reason, the matched rule, obligations, and a full trace.
4. The mediator acts on the effect:
   - **ALLOW** → audit `ok`, return `Verdict.FORWARD`. The adapter sends the request upstream and, on the way back, applies any response obligations (such as `redact:secrets`).
   - **DENY** → audit `blocked`, return `Verdict.BLOCK`. The adapter answers the client itself with an MCP tool-error result (`isError: true`) carrying the reason — the agent sees an explainable refusal, the upstream server is never contacted.
   - **REQUIRE_APPROVAL** → create an `Approval`, audit `pending`. In `deny` mode (default) the call is blocked immediately with instructions to approve and retry; in `wait` mode the mediator blocks, polling until the approval is decided or times out.

Every branch writes to the audit chain, so the trail is complete whether a call was allowed, refused, or held.

## Data flow: a `tools/list`

This is the discovery + enrichment path. It is where the control plane *learns* the upstream surface and where line-jumping / poisoning is first caught.

1. The client sends `tools/list`; the adapter records the request id as pending and forwards it upstream untouched.
2. The upstream server replies with its tools. The adapter intercepts the response and calls `mediator.on_tools_list()`.
3. For each advertised tool the mediator builds an `MCPTool` and runs `enrich_tool()` (`policy/builtin.py`): it infers `Capability` tags from the name, description, and schema; runs `detect_poisoning()` over the description; and assigns a `RiskLevel`.
4. The enriched tool list becomes the server's surface, and `registry.register()` is called. Re-registration compares fingerprints: an unchanged fingerprint preserves the prior approval status; a changed one flags a possible **rug pull**, resets the server to `pending`, and records it.
5. Any tool with poisoning findings triggers an immediate `scan` audit event, so the line-jumping window — the moment a tool description is delivered to the model — is itself audited.
6. The original payload is relayed to the client unchanged. The control plane governs at *call* time, not by rewriting the list, so the agent sees what the server actually advertises.

A separate signal, `notifications/tools/list_changed` from the upstream, is also audited (`gateway/stdio.py`) as a re-review prompt — the protocol-level rug-pull tell.

---

## Local-first, single-SQLite-file design

By default the entire control plane is one SQLite file under a per-user home directory (`config.py`):

- `MCPCP_HOME` resolves to `~/.mcpcp` (per-user), or `./.mcpcp` if it already exists (project-local), or an explicit override.
- All state — servers, audit chain, approvals, meta — lives in `mcpcp.db` (`storage/db.py`). Standard-library `sqlite3` only; no ORM, no migration framework. Entities are stored as JSON blobs in a thin relational envelope, with indexes on the columns actually queried (status, timestamp, server_id). WAL journaling is enabled so readers don't block the writer.
- A solo developer runs the whole thing — gateway, registry, policy, audit — with zero infrastructure.

The same binary scales to a shared, self-hosted team deployment by changing environment, not code:

- Point `MCPCP_DB` at a shared volume (or a path on a single host that runs the API), and `MCPCP_HOST` / `MCPCP_PORT` to expose the API.
- Set `MCPCP_API_TOKEN`. Until it is set the API is meant to bind to localhost only (secure-by-default for the single-developer case); once set, every `/api` route requires `Authorization: Bearer <token>`.
- The dashboard and API are stateless over the database, so the scaling story is "where does the SQLite file live and who can reach the API," not a rearchitecture.

The `Database` is a process-wide singleton per path and thread-safe (an `RLock` guards writes), and `get_control_plane()` is `lru_cache`d per resolved db path, so CLI invocations, API workers, and gateway processes that share a db path share one consistent view.

---

## Extensibility points

The architecture is designed so the security-critical logic lives in one tested unit and the variable parts plug into it.

### New transports

The mediator (`gateway/mediator.py`) is transport-agnostic: it takes parsed JSON-RPC and returns a `Verdict`. A transport adapter is responsible only for moving bytes. `stdio.py` is the reference adapter; it launches the upstream server as a subprocess and relays newline-delimited JSON-RPC, calling `mediator.authorize_call()` on `tools/call` and `mediator.on_tools_list()` on `tools/list`. A new transport (Streamable HTTP, for example) implements the same byte-moving contract and calls the *same* mediator — so policy, audit, approvals, and obligations come for free and the security logic is never reimplemented per transport.

### New capability heuristics

Tool understanding lives in `policy/builtin.py`. To teach the system about a new class of tool you extend `_CAPABILITY_KEYWORDS` (keyword → `Capability`), the schema field-name heuristics, or `_POISON_PATTERNS` (regex → finding label). Because policies match on the stable `Capability` vocabulary (`models.py`), improving inference improves every policy at once without touching any policy file.

### Pluggable policy engines

The PDP is `evaluate(policy, ctx) -> Decision` in `policy/engine.py`. The built-in engine is an **embedded YAML rule engine**: an ordered list of rules with `when` match conditions, priority-ordered first-match-wins evaluation, plus secure-by-default post-conditions and obligations. Its conceptual lineage is authorization engines like **Cedar** (whose Principal/Action/Resource/Context maps cleanly onto agent/tool-call/server/arguments) and **OPA/Rego**. The engine is deliberately small and auditable so the policy is itself a reviewable artifact; the boundary is the `evaluate` signature, so a deployment that wants Cedar or OPA semantics can substitute an engine that consumes the same `CallContext` and returns the same `Decision`, and the gateway, audit, and approval flow are unchanged.

### Scanner clients and rules

`scanner/discover.py` knows the on-disk config locations for popular clients; adding a client is adding a location and, if its config shape differs, a normalizer in `_server_block`. `scanner/rules.py` holds the static checks (`MCP-SEC-*`, `MCP-NET-*`, `MCP-SUP-*`, `MCP-CMD-*`, `MCP-HIL-*`); each is an independent function returning `ConfigFinding`s with a severity and remediation.
