<div align="center">

# 🛡️ OOMeta MCP Governance Adapter

### Enterprise MCP governance — policy enforcement, compliance templates, cross-vendor audit

*Fork of [mcp-control-plane](https://github.com/TWe1v3/mcp-control-plane) with OOMeta branding, compliance policy templates (SOC 2/HIPAA/GDPR/ISO 42001), and multi-vendor governance extensions.*

[![CI](https://github.com/keyonzeng/oometa-mcp-governance-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/keyonzeng/oometa-mcp-governance-adapter/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![OOMeta v0.1](https://img.shields.io/badge/oometa-v0.1-purple.svg)](https://github.com/keyonzeng/oometa-mcp-governance-adapter)

[Quickstart](#-quickstart) · [Why](#-why) · [OOMeta Extensions](#-oometa-extensions) · [Policy Templates](#-compliance-policy-templates) · [Docs](docs/) · [Upstream](https://github.com/TWe1v3/mcp-control-plane)

</div>

---

> **MCP is becoming the plugin layer for AI agents.** OOMeta MCP Governance Adapter turns chaotic MCP adoption into governed, compliant, auditable adoption — with pre-built templates for SOC 2, HIPAA, GDPR, and ISO 42001 environments.

## ✨ What it gives you

| | Subsystem | What it does |
|---|---|---|
| 📇 | **Registry** | An inventory of every MCP server, reviewed and risk-scored. Approve, reject, or quarantine. |
| 🚦 | **Gateway** | A transparent MCP proxy that enforces policy on every `tools/call`. **stdio transport today** (HTTP planned); the decision core is transport-agnostic. |
| 📜 | **Policy engine** | Policy-as-code (reviewable YAML) deciding **allow / deny / require-approval**, with a full explainable trace. |
| ✋ | **Approvals** | Human-in-the-loop gate for risky operations — explicit approval over hidden automation. |
| 🧾 | **Audit** | A tamper-evident, hash-chained log of every decision. `mcpcp audit verify` detects edits. |
| 🔍 | **Scanner** | Discovers MCP servers across Claude Desktop, Cursor, VS Code, Cline, Windsurf, Continue, … and flags unsafe configs. |
| 📊 | **Dashboard** | A polished, zero-build web UI spanning all of the above. |

## 🧠 Why

Six weeks of organic MCP adoption leads to:
- 🤷 Unknown servers on unknown machines
- 🔑 Plaintext `GITHUB_PERSONAL_ACCESS_TOKEN` in config files
- 🪤 Tool poisoning (hidden instructions in descriptions)
- 🌐 Unreviewed ngrok URLs
- 💥 Approved server silently changed (rug pull)

## 🏗 How It Works

```
Agent (Cursor/Cline/Claude/…) → Gateway (PDP) → Upstream MCP server
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
               Registry        Policy         Approvals
               Inventory       as code        queue
                    └───────────┬───────────────┘
                          Audit (hash-chain)
                          SQLite (one file)
```

## 🔌 OOMeta Extensions

### Compliance Policy Templates

Pre-built, reviewable YAML policies for regulated environments:

| Template | Framework | Default Effect | Key Controls |
|----------|-----------|---------------|--------------|
| `oometa-soc2.yaml` | SOC 2 CC6/CC7 | deny | Access logging, change mgmt approval, secret exfil blocking |
| `oometa-hipaa.yaml` | HIPAA §164.312 | deny | ePHI access control, integrity controls, audit trail |
| `oometa-gdpr.yaml` | GDPR Art. 5/25/32 | deny | Data minimisation, PII blocking, DPO notification |
| `oometa-iso-42001.yaml` | ISO 42001 A.7/A.8 | deny | AI system change control, continuous monitoring |
| `oometa-baseline.yaml` | NIST AI RMF | require_approval | Secure-by-default enterprise baseline |

Usage:
```bash
mcpcp policy init --template oometa/oometa-soc2.yaml
```

### Slack MCP Registration

The adapter can be registered as a Slack MCP server for enterprise governance:

```json
{
  "mcpServers": {
    "oometa-governance": {
      "command": "mcpcp",
      "args": ["gateway", "run", "--server", "oometa-governance", "--policy", "oometa-baseline"]
    }
  }
}
```

## 📜 Policy-as-Code (Upstream)

Policies are small, reviewable YAML you can commit and diff. The first matching rule (by priority) wins; an `allow` that targets an unapproved server is automatically downgraded to require-approval.

```yaml
version: 1
name: baseline
default_effect: require_approval
settings:
  unapproved_server_effect: deny
rules:
  - id: deny-command-execution
    effect: deny
    priority: 100
    when:
      capabilities_any: [process.exec, code.execution]
```

## 🚀 Quickstart

```bash
pip install oometa-mcp-governance-adapter  # or pipx

# 1. See what's already on this machine
mcpcp scan

# 2. Load demo scenario
mcpcp demo seed

# 3. Use OOMeta compliance template
mcpcp policy init --template oometa/oometa-soc2.yaml

# 4. Open dashboard
mcpcp serve            # → http://127.0.0.1:8765
```

## 📚 Docs

| Doc | Contents |
|---|---|
| [architecture.md](docs/architecture.md) | Component map, request lifecycle, extensibility |
| [security-model.md](docs/security-model.md) | Principles, trust boundaries, secret handling, audit integrity |
| [policy-model.md](docs/policy-model.md) | Full YAML schema, evaluation order, worked examples |
| [threat-model.md](docs/threat-model.md) | MCP attack classes mapped to mitigations |
| [usage.md](docs/usage.md) | Install, CLI workflows, CI setup |
| [comparison.md](docs/comparison.md) | Honest landscape positioning |

## License

Apache 2.0 — see [LICENSE](LICENSE). Upstream: [TWe1v3/mcp-control-plane](https://github.com/TWe1v3/mcp-control-plane).
