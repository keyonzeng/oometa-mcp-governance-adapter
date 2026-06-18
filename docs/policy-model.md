# Policy Model

Policy in `mcp-control-plane` is code: a small, reviewable YAML document of ordered rules plus a secure default. The policy decision point (PDP) turns one tool call into an explainable `Decision` — an effect (allow / deny / require-approval), a human reason, attached obligations, and a full rule-by-rule trace. This document is the complete schema reference, the evaluation algorithm, the capability vocabulary, and worked examples. For where the PDP sits in the system see the [architecture](architecture.md) doc; for the principles behind the defaults see the [security model](security-model.md). For the project overview see the [README](../README.md).

---

## The YAML schema

```yaml
version: 1                       # schema version (int)
name: my-policy                  # identifier shown in traces/audit
description: "..."               # free text
default_effect: require_approval # allow | deny | require_approval — applies when no rule matches

settings:
  unapproved_server_effect: require_approval  # allow | deny | require_approval
  redact_secrets: true                        # attach redact:secrets to allows touching secrets

rules:
  - id: a-stable-id              # required, unique; appears in trace + audit
    description: "..."           # free text; used as the reason if `reason` is unset
    effect: deny                 # allow | deny | require_approval — required
    priority: 100                # int; higher wins; default 0
    reason: "..."                # the human explanation surfaced to the agent
    risk: critical               # optional override of the decision's risk level
    obligations: [redact:secrets]# optional list attached to the decision
    when:                        # match conditions — all present conditions must hold (AND)
      server_status: [approved]
      server_name: ["github*"]
      server_tags_any: [production]
      tool_name: ["read_*", "list_*"]
      agent: ["claude-desktop"]
      capabilities_any: [filesystem.read]
      capabilities_all: [network, secrets]
      capabilities_none: [process.exec]
      risk_at_least: high
      arg_matches:
        - field: path            # arg name, or "*" for any value (recursive)
          regex: '(?i)/\.ssh/'
          description: "references an SSH directory"
```

### Top-level fields

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `version` | int | `1` | Schema version. |
| `name` | str | `"unnamed"` | Policy identifier. |
| `description` | str | `""` | Free text. |
| `default_effect` | `allow` \| `deny` \| `require_approval` | `require_approval` | Effect when no rule matches (secure-by-default). |
| `settings` | object | see below | Engine-wide post-conditions. |
| `rules` | list | `[]` | Ordered rules (sorted by priority at evaluation). |

### `settings`

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `unapproved_server_effect` | `allow` \| `deny` \| `require_approval` | `require_approval` | What an ALLOW is downgraded to when the target server's status is not `approved`. |
| `redact_secrets` | bool | `true` | When a surviving ALLOW targets a tool with the `secrets` capability, attach a `redact:secrets` obligation. |

### `rules[]`

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `id` | str | — (required) | Stable, unique id. Surfaced in the trace and audit. |
| `description` | str | `""` | Free text; becomes the reason if `reason` is unset. |
| `effect` | `allow` \| `deny` \| `require_approval` | — (required) | The rule's verdict if it matches. |
| `priority` | int | `0` | Higher wins. Ties break on file order. |
| `reason` | str \| null | `null` | The explanation surfaced to the agent and audit. |
| `risk` | RiskLevel \| null | `null` | Optional override of the decision's risk (else the tool's risk). |
| `obligations` | list[str] | `[]` | Attached to the decision (e.g. `redact:secrets`). |
| `when` | `Match` | empty (matches everything) | Conditions; see below. |

### `when` — match conditions

All present conditions must hold (logical AND). An empty `when` matches every call. Each condition (`policy/rules.py::Match`):

| Condition | Type | Matches when |
|-----------|------|--------------|
| `server_status` | list[str] | The server's status is one of these (`discovered`/`pending`/`approved`/`rejected`/`disabled`). |
| `server_name` | list[glob] | The server name matches any glob (`fnmatch`). |
| `server_tags_any` | list[str] | The server has at least one of these tags. |
| `tool_name` | list[glob] | The tool name matches any glob. |
| `agent` | list[glob] | The calling agent matches any glob. |
| `capabilities_any` | list[Capability] | The tool has at least one of these capabilities. |
| `capabilities_all` | list[Capability] | The tool has all of these capabilities. |
| `capabilities_none` | list[Capability] | The tool has none of these capabilities. |
| `risk_at_least` | RiskLevel | The tool's risk is at least this level. |
| `arg_matches` | list[`ArgMatch`] | At least one `ArgMatch` matches the call's arguments. |

`ArgMatch` fields: `field` (arg name, or `"*"` to search all values recursively), `regex` (Python `re`, applied with `search` over string values, walking nested dicts/lists), and optional `description` (used as the match reason in the trace).

---

## Evaluation algorithm

The PDP (`policy/engine.py::evaluate`) is intentionally simple so any verdict can be explained after the fact.

1. **Sort rules by priority descending** (ties keep file order). Walk them in that order.
2. **First match wins.** The first rule whose `when` holds is the winner and its effect, reason, risk, and obligations are taken. Evaluation continues — *not* breaking — purely so the trace records every rule considered; only the first match decides.
3. **No match → `default_effect`.** A `<default>` entry is added to the trace.
4. **Secure-by-default post-conditions** (applied after the winner is chosen):
   - **Unapproved-server downgrade.** If the effect is now ALLOW but the target server's status is not `approved`, the allow is downgraded to `settings.unapproved_server_effect`. A `<post:unapproved-server>` trace entry and an explanation are added.
   - **Secret-redaction obligation.** If the effect is still ALLOW, `settings.redact_secrets` is on, and the tool has the `secrets` capability, a `redact:secrets` obligation is attached (unless already present) with a `<post:redact-secrets>` trace entry.
5. **Compose the reason** from the rule reason plus the human-readable list of why the winning `when` matched, and return a `Decision`.

The full ordered trace — every rule with its priority, effect, whether it matched, and why — is on `Decision.trace`. This is the basis of explainable security: a deny is never a black box.

```
priority desc ─► [rule, rule, rule, …] ─► first match ─► post-conditions ─► Decision(effect, reason, obligations, trace)
                                              │
                                  no match ─► default_effect
```

---

## Capability vocabulary

Capabilities (`models.py::Capability`) describe *what a tool can do* in security terms. They are coarse and stable so policies match on them rather than on brittle tool names. Inference happens in `policy/builtin.py`.

| Capability | Value | Inferred from (examples) |
|------------|-------|--------------------------|
| Filesystem read | `filesystem.read` | "read file", "list directory", a `path`/`filename` arg |
| Filesystem write | `filesystem.write` | "write file", "delete file", "mkdir", "rename" |
| Process execution | `process.exec` | "run command", "shell", "exec", a `command`/`cmd`/`script` arg |
| Code execution | `code.execution` | "eval", "run python", "interpreter", "code_interpreter" |
| Network | `network` | "http", "fetch url", "download", a `url`/`uri`/`endpoint` arg |
| Secrets | `secrets` | "credential", "api key", "vault", ".env", "ssh key" |
| Database read | `database.read` | "select", "query database", a `query`/`sql` arg |
| Database write | `database.write` | "insert into", "drop table", "execute sql" |
| Email / messaging send | `messaging.send` | "send email", "send slack", "post message" |
| Payment | `payment` | "charge", "transfer funds", "refund", "checkout" |
| Destructive | `destructive` | "delete", "destroy", "force push", "reset --hard", "wipe" |
| Unknown | `unknown` | nothing matched → treated as not-yet-trusted (risk ≥ medium) |

Risk scoring (`score_tool`): any poisoning finding → `critical`; `process.exec` → `critical`; `code.execution`/`payment` → `high`; write/secrets/destructive/messaging → `high`; network/read → `medium`; `unknown` → `medium`; else `low`.

---

## Worked examples

### 1. Read-only baseline (the shipped default)

Allow read-only tools on approved servers; require approval for state-changing tools; deny raw execution and obvious secret-path arguments. This is `baseline_policy()` (`policy/default_policies.py`) expressed as YAML.

```yaml
version: 1
name: baseline
description: Secure-by-default baseline.
default_effect: require_approval
settings:
  unapproved_server_effect: require_approval
  redact_secrets: true
rules:
  - id: deny-command-execution
    effect: deny
    priority: 100
    reason: Raw command or code execution via MCP is not permitted
    when:
      capabilities_any: [process.exec, code.execution]

  - id: deny-secret-exfiltration
    effect: deny
    priority: 95
    reason: Argument references a sensitive path or credential material
    when:
      arg_matches:
        - field: "*"
          regex: '(?i)(/\.ssh/|id_rsa|\.env\b|/\.aws/|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)'
          description: argument references secret files / private keys

  - id: approve-poisoned-tools
    effect: require_approval
    priority: 90
    risk: critical
    reason: Tool was flagged for possible poisoning; needs human review
    when:
      risk_at_least: critical

  - id: approve-destructive-and-spend
    effect: require_approval
    priority: 70
    reason: High-impact action (write/destroy/pay/send) requires approval
    when:
      capabilities_any: [destructive, payment, messaging.send, database.write, filesystem.write]

  - id: allow-readonly-on-approved
    effect: allow
    priority: 40
    reason: Read-only tool on an approved server
    when:
      server_status: [approved]
      capabilities_none:
        [filesystem.write, database.write, process.exec, code.execution,
         payment, destructive, messaging.send, secrets]
```

### 2. Strict deny-by-default

Nothing runs without an explicit allow rule or an approval. This is `strict_policy()`: the baseline with `default_effect: deny` and `unapproved_server_effect: deny`.

```yaml
version: 1
name: strict
description: Deny-by-default; only explicitly approved, read-only tools pass.
default_effect: deny
settings:
  unapproved_server_effect: deny
  redact_secrets: true
rules:
  # ... same rule bodies as the baseline above ...
```

### 3. Deny secret-path arguments

A standalone rule (drop into any policy) that denies any call whose arguments reference common credential locations, regardless of which tool it is.

```yaml
- id: deny-credential-paths
  effect: deny
  priority: 95
  reason: Call arguments reference a credential file or cloud-credentials directory
  when:
    arg_matches:
      - field: "*"
        regex: '(?i)(/\.ssh/|id_rsa|\.env\b|/\.aws/|/\.kube/config|\.npmrc)'
        description: argument references secret files
```

### 4. Require approval for a server tag

Require a human for every call to any server tagged `production`, even reads.

```yaml
- id: approve-production-servers
  effect: require_approval
  priority: 80
  reason: All calls to production-tagged servers require approval
  when:
    server_tags_any: [production]
```

---

## A sample decision trace

A call to a `write_file` tool (capability `filesystem.write`) on a server that is `pending`, under the baseline policy. The destructive/write rule matches first:

```json
{
  "effect": "require_approval",
  "matched_rule": "approve-destructive-and-spend",
  "risk": "high",
  "obligations": [],
  "reason": "High-impact action (write/destroy/pay/send) requires approval (tool has capability ['filesystem.write'])",
  "trace": [
    {"rule": "deny-command-execution",        "priority": 100, "effect": "deny",             "matched": false, "why": []},
    {"rule": "deny-secret-exfiltration",      "priority": 95,  "effect": "deny",             "matched": false, "why": []},
    {"rule": "approve-poisoned-tools",        "priority": 90,  "effect": "require_approval", "matched": false, "why": []},
    {"rule": "approve-destructive-and-spend", "priority": 70,  "effect": "require_approval", "matched": true,
       "why": ["tool has capability ['filesystem.write']"]},
    {"rule": "allow-readonly-on-approved",    "priority": 40,  "effect": "allow",            "matched": false, "why": []}
  ]
}
```

If instead a read-only tool on an *approved* server were called, `allow-readonly-on-approved` would win with `effect: allow`. Had that same read-only tool been on a `pending` server, the ALLOW would have survived rule evaluation and then been downgraded by the `<post:unapproved-server>` post-condition to `require_approval`, with both the winning rule and the downgrade visible in the trace.

You can produce these traces interactively with `mcpcp policy explain` or `POST /api/policy/evaluate`.
