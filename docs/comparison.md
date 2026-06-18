# Comparison & Positioning

An honest look at where `mcp-control-plane` sits in the MCP security landscape as of mid-2026: the closest open-source analogs, the dedicated scanners, the official registry, the commercial gateways, and the policy engines — and the specific white space this project fills. The short version: no single open-source project unifies registry + gateway + policy-as-code + approval workflow + audit trail + config scanner + dashboard as one coherent, self-hostable *team* governance control plane. For what this project actually does, see the [architecture](architecture.md) and [threat model](threat-model.md) docs. For the project overview see the [README](../README.md).

> **The space moves fast.** The projects below ship frequently and reposition often. Treat every cell in the table as a point-in-time snapshot and re-verify against upstream before relying on it.

---

## The landscape

### Closest open-source analogs (registry + gateway + policy)

- **IBM ContextForge** (`github.com/IBM/mcp-context-forge`, Apache-2.0) — the closest single-project analog: a registry plus gateway with policy enforcement (Cedar + OPA). Strong on federation and protocol bridging. Differs in emphasis: less focused on a config *scanner* that discovers shadow servers across developer machines, and on a first-class human-approval workflow.
- **Docker MCP Gateway** (MIT) — container isolation + allowlisting. Its great strength is *runtime sandboxing* of the upstream server (the thing this project explicitly does **not** do), making it a natural complement rather than a competitor.
- **Solo.io agentgateway** (Apache-2.0) — a Rust proxy with CEL-based policy; infrastructure-grade data plane, lighter on the review/approval/registry workflow.
- **Obot** (MIT), **MetaMCP** (MIT) — MCP aggregation / proxy layers with management UIs.
- **Stacklok ToolHive** (uses Cedar for tool-call authorization) — closest in *policy philosophy* (Cedar over tool calls), with container-based running.

### Dedicated scanners

- **Invariant `mcp-scan`** (Apache-2.0, acquired by Snyk) — coined "tool poisoning"; the reference scanner for malicious tool descriptions.
- **`mcp-shield`** (MIT) — tool-description and config scanning.
- **Trail of Bits `mcp-context-protector`** (Apache-2.0) — TOFU (trust-on-first-use) pinning of tool definitions, directly targeting line jumping and rug pulls.
- **Cisco `mcp-scanner`** (Apache-2.0), **Lasso `mcp-gateway`** (MIT) — scanning and gateway-side guardrails.

These are excellent at detection. They are not registries, do not run an approval workflow, and do not maintain a team-wide governed inventory — they are upstream of, and complementary to, a control plane.

### Official registry

- **`github.com/modelcontextprotocol/registry`** (preview) — a *metaregistry* of published MCP servers. This project **consumes** it (as a source of server identity/metadata), it does not rebuild it.

### Commercial / managed

- **MintMCP**, **TrueFoundry MCP Gateway**, **Microsoft Azure API Center / APIM**, **Cloudflare** — managed MCP gateways and governance, typically SaaS or cloud-platform-bound. This project's niche is the *self-hostable, open-source, team* control plane for organizations that want to run it themselves.

### Policy engines (conceptual lineage)

- **Cedar** — the best conceptual fit: its Principal / Action / Resource / Context maps cleanly onto agent / tool-call / server / arguments. Used by ToolHive. This project's embedded YAML rule engine is Cedar-shaped in spirit (see [policy model](policy-model.md)) and the `evaluate()` boundary is designed so a Cedar/OPA engine could be substituted.
- **OPA / Rego** — the most flexible and widely deployed general policy engine.
- **CEL** — a lightweight predicate layer (used by agentgateway).

---

## Capability comparison

Capabilities × selected projects. ✅ = first-class, ➖ = partial / adjacent / via another tool, ❌ = not a goal of that project.

| Capability | mcp-control-plane | IBM ContextForge | Docker MCP Gateway | Invariant/Snyk mcp-scan | Official Registry | MintMCP / TrueFoundry |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Server registry | ✅ | ✅ | ➖ | ❌ | ✅ | ✅ |
| Enforcing gateway | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Policy-as-code | ✅ | ✅ (Cedar/OPA) | ➖ (allowlist) | ❌ | ❌ | ➖ |
| Approval workflow | ✅ | ➖ | ❌ | ❌ | ❌ | ➖ |
| Audit trail | ✅ (hash-chained) | ✅ | ➖ | ➖ | ❌ | ✅ |
| Config scanner (shadow-server discovery) | ✅ | ❌ | ❌ | ➖ (scans, not discover-across-machines) | ❌ | ❌ |
| Threat detection (poisoning/rug-pull) | ✅ | ➖ | ➖ | ✅ | ❌ | ➖ |
| Dashboard | ✅ | ✅ | ➖ | ➖ | ➖ | ✅ |
| Open source | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Self-hostable / team | ✅ | ✅ | ✅ | ✅ (CLI) | ✅ | ➖ (managed) |

*Cells are a mid-2026 snapshot and should be re-verified — see the caveat above.*

---

## The white space, and our positioning

Each piece of the above exists somewhere in open source. What is missing is a *single coherent project* that a team can self-host to govern MCP end to end. That is the gap `mcp-control-plane` fills. Four things differentiate it:

1. **Approval workflow for risky operations.** Gateways generally allow or deny; they lack a human-in-the-loop *park-and-decide* path. Here, a `require_approval` decision creates an `Approval` that a person resolves via CLI or dashboard, with the gateway either returning a retry instruction or blocking until decided. (See [usage](usage.md#4-work-the-approval-queue).)

2. **A config scanner that *discovers* installed and shadow servers across developer machines.** Most scanners analyze a config you hand them; this one knows the on-disk locations of the popular clients and turns "what MCP servers are actually installed across the team" into a reviewable inventory — the shadow-IT problem specialized to MCP. (See [threat model](threat-model.md#shadow--unapproved-servers).)

3. **Policy-as-code as a first-class, auditable artifact.** The policy is a small reviewable YAML file with priority-ordered rules, a capability vocabulary, obligations, and a full decision trace on every verdict — so security decisions are explainable and the policy itself is diffable and reviewable. (See [policy model](policy-model.md).)

4. **A cohesive dashboard spanning all of it.** One UI over the registry, policy, approvals, and audit — not four disconnected tools.

### Complement, don't compete

This project is deliberately scoped to *not* re-do what the ecosystem already does well, and to compose with it:

- **Consume the official registry** for server identity/metadata rather than rebuilding a metaregistry.
- **Pair with runtime sandboxing** (Docker MCP Gateway-style container isolation) for exec-capable servers — this project is an authorization/audit layer, not a sandbox (see [security model](security-model.md#honest-limits--what-is-and-isnt-protected)).
- **Layer the dedicated scanners** (Invariant/Snyk, Trail of Bits TOFU pinning) where deeper detection is needed; their findings and this project's gating are additive.
- **Can embed transport bridging** so a stdio-only server is reachable over HTTP, the way ContextForge and others do — the mediator is transport-agnostic by design (see [architecture](architecture.md#extensibility-points)).

The honest summary: pick a specialized tool when you need one thing done deeply; pick `mcp-control-plane` when a team needs *all* of registry, gateway, policy, approvals, audit, scanning, and a dashboard as one self-hosted whole — and compose it with the specialists above.
