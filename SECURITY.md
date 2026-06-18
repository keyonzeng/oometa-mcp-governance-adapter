# Security Policy

`mcp-control-plane` is a security tool, so we take its own security seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Instead, use
GitHub's private vulnerability reporting ("Report a vulnerability" under the
Security tab) or contact the maintainers privately. We aim to acknowledge reports
within a few days.

## Scope & honest limitations

This project mediates and governs MCP traffic, but it is defense-in-depth, not a
silver bullet. In particular (see [docs/security-model.md](docs/security-model.md)
and [docs/threat-model.md](docs/threat-model.md)):

- The gateway governs `tools/call` decisions; a malicious server can still
  misbehave *within* an allowed call. Scope and review what you approve.
- Capability inference and poisoning detection are heuristic and conservative;
  they reduce risk but do not guarantee detection.
- The audit chain is tamper-*evident* (detects edits), not tamper-*proof*.

## Secure defaults

- No policy file → secure `baseline` (deny exec, require approval for writes/spend).
- API binds to localhost until `MCPCP_API_TOKEN` is set.
- Arguments are redacted in the audit store; `env` values are never persisted
  (only key names are kept).
