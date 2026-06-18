# Security Model

This document states the security principles `mcp-control-plane` is built on, explains the mechanisms that enforce them — secure-by-default policy evaluation, secret handling, and the tamper-evident audit chain — and is honest about the trust boundaries and what is *not* protected. It is the "why it's safe, and where it isn't" companion to the [architecture](architecture.md) doc. For the project overview see the [README](../README.md).

---

## Five design principles

1. **Never silently trust an MCP server.** A server found by the scanner or seen by the gateway starts as `discovered`/`pending`, not `approved`. Tools are translated into a security vocabulary and scored before any policy reasons about them; unknown means not-yet-trusted, not safe.
2. **Never silently expose secrets.** Arguments are redacted before they enter the audit store; responses from allowed calls that touch secrets carry a `redact:secrets` obligation; the registry stores environment-variable *names*, never values.
3. **Make risky tool calls visible and explainable.** Every decision carries a human-readable reason and a full rule-by-rule trace. Every decision, approval, scan, and registry change is audited.
4. **Prefer explicit approval over hidden automation.** When a call is risky the default is to require a human approval rather than guess. Auto-approve / always-allow config is itself flagged as a finding.
5. **Local-first but team-ready.** The whole control plane runs on one developer's machine with zero infrastructure and no exposed network surface, and the same code scales to a shared, token-gated deployment without changing the trust model.

---

## Secure-by-default

The policy model defaults to the safe answer at every layer, so a gap in the rules fails closed rather than open.

**Default effect.** `Policy.default_effect` is `require_approval` (`policy/rules.py`). If no rule matches a call, the call is parked for a human, not allowed. The shipped `strict` policy goes further and defaults to `deny`.

**Unapproved-server downgrade.** Even when a rule says ALLOW, the engine applies a post-condition (`policy/engine.py`): if the target server's status is not `approved`, the allow is downgraded to the policy's `unapproved_server_effect` (default `require_approval`; `deny` under the strict policy). Concretely:

```
ALLOW rule matched
  └─ but server status == "pending"
        └─ <post:unapproved-server> downgrade → require_approval
```

This means a permissive rule cannot accidentally grant access to a server nobody has reviewed. Approval in the registry is a hard gate that sits *after* the rule logic.

**Conservative enrichment.** When capability inference is unsure it tags `UNKNOWN` and raises risk to `MEDIUM` rather than assuming `LOW` (`policy/builtin.py::score_tool`). A tool flagged with any poisoning finding is scored `CRITICAL`, and the baseline policy quarantines anything `CRITICAL` for approval.

**Default-deny on raw execution.** The baseline policy denies `process.exec` and `code.execution` outright (priority 100) and denies arguments referencing secret paths (priority 95) — these are decisions, not heuristics, and apply before any allow rule can be considered.

---

## Secret handling

Secrets are handled defensively at three distinct points so a leak requires more than one failure.

**Arguments redacted before storage (`models.py::redact_arguments`).** Before a call's arguments are written to the audit store or an approval preview, keys that look sensitive (`token`, `secret`, `password`, `apikey`, `api_key`, `key`, `auth`, …) are masked to `***redacted***`, long opaque strings are truncated, and nested structures are summarized. The audit store records an `arguments_digest` (a SHA-256 of the full arguments) for correlation, but never the raw values. This enforces "never silently expose secrets" even inside the tool's own trust boundary.

**Response redaction obligation (`policy/engine.py` + `gateway/mediator.py`).** When an ALLOW survives and the tool has the `SECRETS` capability (and `settings.redact_secrets` is on), the engine attaches a `redact:secrets` obligation to the decision. The gateway enforces it on the way back: `apply_obligations()` runs the response text through a set of high-confidence secret regexes (AWS keys, OpenAI/Anthropic keys, GitHub/Slack/GitLab tokens, PEM private keys, JWTs) and replaces matches with `***redacted-by-mcp-control-plane***` before the agent ever sees them. Obligations are the bridge between a *decision* (PDP) and an *enforcement action* (PEP).

**Names, not values, in the registry (`models.py::MCPServer.env_keys`).** A server records only the *names* of the environment variables it is configured with (`env_keys`), never their values. The scanner separately reads raw env values transiently, in memory, only to check for hardcoded secrets — those values are never persisted to the registry.

---

## Tamper-evident audit chain

Every meaningful action becomes an `AuditEvent` appended to a hash chain. The chain makes silent edits or deletions of history detectable.

**How it works (`models.py`, `storage/db.py::append_audit`).** Each event's `hash` is `SHA-256( canonical_json(event without hash/prev_hash) + prev_hash )`, where `prev_hash` is the hash of the immediately preceding event. Appending is serialized under a lock: read the last hash, set it as this event's `prev_hash`, compute this event's `hash`, insert. The result is a linked chain where each link commits to everything before it.

```
evt₀  hash₀ = H(payload₀ + "")
evt₁  prev=hash₀  hash₁ = H(payload₁ + hash₀)
evt₂  prev=hash₁  hash₂ = H(payload₂ + hash₁)
 ...
```

**How verification detects edits (`storage/db.py::verify_audit_chain`).** Verification walks the chain from the beginning, recomputing each event's hash from its payload and the running previous hash, and checks both that the stored `hash` matches and that the stored `prev_hash` equals the actual previous hash. If any event was altered, deleted, or reordered, the recomputed hash diverges and verification returns `(False, first_broken_event_id)`. `mcpcp audit verify` (and `GET /api/audit/verify`) surface exactly this: the boolean and the id of the first event that fails. Because `compute_hash` includes the event payload, even a single changed field anywhere in history breaks the chain from that point forward.

**What this gives you, and what it doesn't.** The chain is *tamper-evident*, not *tamper-proof*: an attacker with write access to the SQLite file and the code could in principle recompute the entire chain forward from the point of edit. It defends against silent, partial, or after-the-fact edits and accidental corruption, and gives you a verifiable integrity signal. For stronger guarantees, export and externally anchor the chain (e.g. periodic off-host snapshots) — the per-event hashes make any such anchoring straightforward.

---

## Trust boundaries

```
   ┌── TRUSTED ──────────────────────────────────────────────┐
   │  Control plane process(es): mediator, policy engine,      │
   │  registry, approvals, audit, SQLite db, API+dashboard     │
   └──────────────────────────────────────────────────────────┘
          ▲ stdio (JSON-RPC)                ▲ subprocess stdio
   ┌──────┴───────┐                  ┌───────┴──────────────────┐
   │  MCP client  │  SEMI-TRUSTED    │  Upstream MCP server      │  UNTRUSTED
   │  / agent     │  (may be tricked │  (third-party code; may   │  within an
   │              │   by a poisoned  │   misbehave inside an      │  allowed call
   │              │   tool)          │   allowed call)            │
   └──────────────┘                  └───────────────────────────┘
```

- The **control plane** is the trust anchor. Compromise of the host running it is out of scope for these mechanisms.
- The **agent / MCP client** is semi-trusted: it is the thing being protected, but it can be manipulated by a poisoned tool description. The control plane's job is to keep the agent's *actions* governable even when its judgment is compromised.
- The **upstream MCP server** is untrusted third-party code. The gateway governs *which calls reach it* and *redacts what comes back*, but does not sandbox what it does with an allowed call.
- The **API surface** is a trust boundary controlled by `MCPCP_API_TOKEN`: localhost-only until a token is set, bearer-gated after.

---

## Honest limits — what is and isn't protected

This is defense in depth, not a silver bullet. Be calibrated about the boundary:

- **The gateway governs `tools/call`, not what an allowed call does.** If policy allows a call, a malicious or buggy upstream server can still misbehave *within* that allowed call (read more than it should, make side network requests, return tainted content). The gateway is an authorization and redaction layer, not a sandbox. Pair it with OS/container isolation for the upstream process (e.g. Docker MCP Gateway-style containment) where the threat warrants it.
- **Capability inference and poisoning detection are heuristics.** They are deliberately conservative (fail toward higher risk), but a sufficiently novel description can evade keyword and regex matching. They reduce, not eliminate, the chance that a dangerous tool is mis-scored. Approval gates and default-deny on raw execution are the backstop.
- **Response redaction is best-effort pattern matching.** It catches well-known secret shapes; it will not catch every encoding or a secret an upstream actively tries to smuggle past it. It lowers casual exposure, not a determined exfiltration.
- **The audit chain is tamper-evident, not append-only at the OS level.** See above — it detects edits, it does not prevent an attacker with full host access from rewriting history.
- **Confused-deputy / token-passthrough is only partially addressed.** The control plane decides authorization and can redact, but it does not yet mint or scope downstream credentials. Treat upstream auth as the server's responsibility for now.

The value is layered: discover and review servers before use, deny the clearly-dangerous, require humans for the risky, redact secrets in both directions, and keep a verifiable record of all of it — so that no single failure silently becomes a breach.
