"""Built-in heuristics: capability inference, risk scoring, and threat detection.

MCP servers describe their tools in free text and JSON Schema. Before any policy
can reason about a tool we must translate that description into the stable
security vocabulary of :class:`Capability`. We also scan tool/argument text for
known MCP attack patterns (tool poisoning, line jumping, exfiltration hints).

These heuristics are deliberately conservative: when unsure we tag UNKNOWN and
raise risk rather than assume a tool is safe ('never silently trust').
"""

from __future__ import annotations

import re

from mcp_control_plane.models import Capability, MCPTool, RiskLevel

# Keyword -> capability map. Matched against tool name + description + schema.
_CAPABILITY_KEYWORDS: dict[Capability, tuple[str, ...]] = {
    Capability.FILESYSTEM_WRITE: (
        "write file", "write_file", "writefile", "delete file", "delete_file",
        "remove file", "unlink", "create file", "edit file", "edit_file",
        "move file", "rename", "mkdir", "rmdir", "chmod", "truncate", "save to",
    ),
    Capability.FILESYSTEM_READ: (
        "read file", "read_file", "readfile", "list directory", "list_dir",
        "list files", "glob", "cat ", "open file", "get file", "load file",
    ),
    Capability.PROCESS_EXEC: (
        "execute command", "run command", "shell", "exec", "spawn", "subprocess",
        "bash", "/bin/sh", "powershell", "cmd.exe", "run_shell", "terminal",
    ),
    Capability.CODE_EXECUTION: (
        "eval", "run code", "execute code", "run python", "run javascript",
        "interpreter", "sandbox run", "code_interpreter",
    ),
    Capability.NETWORK: (
        "http", "fetch url", "fetch_url", "request", "download", "curl", "webhook",
        "api call", "get url", "post to", "scrape", "crawl",
    ),
    Capability.SECRETS: (
        "secret", "credential", "api key", "api_key", "token", "password",
        "private key", "vault", "keychain", ".env", "ssh key",
    ),
    Capability.DATABASE_WRITE: (
        "insert into", "update set", "delete from", "drop table", "drop database",
        "alter table", "truncate table", "create table", "write query", "execute sql",
    ),
    Capability.DATABASE_READ: (
        "select ", "query database", "read query", "find documents", "db query",
        "run sql", "fetch rows",
    ),
    Capability.EMAIL_SEND: (
        "send email", "send_email", "send message", "send_message", "post message",
        "send sms", "send slack", "send to channel", "publish message",
    ),
    Capability.PAYMENT: (
        "charge", "payment", "transfer funds", "create invoice", "refund",
        "checkout", "wire transfer", "send money",
    ),
    Capability.DESTRUCTIVE: (
        "delete", "destroy", "drop ", "terminate", "force push", "reset --hard",
        "wipe", "purge", "revoke",
    ),
}

# Patterns that suggest a *poisoned* tool description — text aimed at the model,
# not the human reader. This is the core 'tool poisoning' / 'line jumping' class.
_POISON_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?i)ignore (all|any|previous|prior) (instructions|context)", "instruction-override text in description"),
    (r"(?i)<\s*important\s*>", "hidden <IMPORTANT> block in description"),
    (r"(?i)do not (tell|inform|mention to) (the )?(user|human)", "asks model to hide actions from the user"),
    (r"(?i)before (using|calling) (this|any) (other )?tool", "front-runs other tools (line jumping)"),
    (r"(?i)(read|exfiltrate|send|upload).{0,30}(\.env|id_rsa|ssh key|password|secret)", "instructs reading/exfiltrating secrets"),
    (r"(?i)system prompt", "references the system prompt"),
    (r"(?i)\bcurl\b.{0,40}(http|\$\()", "embeds a curl/exfil command"),
)


def infer_capabilities(tool: MCPTool) -> list[Capability]:
    """Infer capabilities from a tool's name, description and input schema."""
    haystack = " ".join(
        [
            tool.name.replace("_", " "),
            tool.description or "",
            " ".join(_iter_schema_text(tool.input_schema)),
        ]
    ).lower()

    found: set[Capability] = set()
    for cap, keywords in _CAPABILITY_KEYWORDS.items():
        if any(kw in haystack for kw in keywords):
            found.add(cap)

    # Schema field-name heuristics (e.g. an arg literally named "command").
    field_names = {f.lower() for f in _iter_schema_field_names(tool.input_schema)}
    if {"command", "cmd", "script"} & field_names:
        found.add(Capability.PROCESS_EXEC)
    if {"path", "filepath", "file_path", "filename"} & field_names:
        found.add(Capability.FILESYSTEM_READ)
    if {"url", "uri", "endpoint"} & field_names:
        found.add(Capability.NETWORK)
    if {"query", "sql"} & field_names:
        found.add(Capability.DATABASE_READ)

    if not found:
        found.add(Capability.UNKNOWN)
    return sorted(found, key=lambda c: c.value)


def detect_poisoning(tool: MCPTool) -> list[str]:
    """Return findings if a tool's description looks like a prompt-injection."""
    text = f"{tool.name}\n{tool.description}"
    findings = []
    for pattern, label in _POISON_PATTERNS:
        if re.search(pattern, text):
            findings.append(label)
    # Suspiciously long descriptions are a classic hiding place.
    if len(tool.description or "") > 1500:
        findings.append("unusually long tool description (possible hidden payload)")
    return findings


def score_tool(tool: MCPTool) -> RiskLevel:
    """Assign a risk level to a tool from its capabilities and findings."""
    caps = set(tool.capabilities or infer_capabilities(tool))
    if tool.findings:
        return RiskLevel.CRITICAL
    critical = {Capability.PROCESS_EXEC, Capability.CODE_EXECUTION, Capability.PAYMENT}
    high = {
        Capability.FILESYSTEM_WRITE,
        Capability.DATABASE_WRITE,
        Capability.SECRETS,
        Capability.DESTRUCTIVE,
        Capability.EMAIL_SEND,
    }
    if caps & critical:
        return RiskLevel.HIGH if not (caps & {Capability.PROCESS_EXEC}) else RiskLevel.CRITICAL
    if caps & high:
        return RiskLevel.HIGH
    if caps & {Capability.NETWORK, Capability.FILESYSTEM_READ, Capability.DATABASE_READ}:
        return RiskLevel.MEDIUM
    if Capability.UNKNOWN in caps:
        return RiskLevel.MEDIUM  # unknown == not-yet-trusted
    return RiskLevel.LOW


def enrich_tool(tool: MCPTool) -> MCPTool:
    """Populate capabilities, findings and risk on a tool in place."""
    tool.capabilities = infer_capabilities(tool)
    tool.findings = detect_poisoning(tool)
    tool.risk = score_tool(tool)
    return tool


def _iter_schema_text(schema: dict) -> list[str]:
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("description", "title") and isinstance(v, str):
                    out.append(v)
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    return out


def _iter_schema_field_names(schema: dict) -> list[str]:
    names: list[str] = []
    props = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(props, dict):
        names.extend(props.keys())
    return names
