"""Static risk checks for MCP server *configurations* (no live connection).

These complement the runtime policy engine: before a server is ever launched we
can already flag dangerous config hygiene — hardcoded secrets, plaintext
transports, remote code pulled on every launch, shell-injection-prone commands.
Each check returns zero or more :class:`ConfigFinding` with a severity and a
concrete remediation hint, so findings are explainable and actionable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mcp_control_plane.models import MCPServer, RiskLevel

# Patterns that look like real, inlined credentials.
_SECRET_VALUE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style secret key"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"ghp_[A-Za-z0-9]{30,}", "GitHub personal access token"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"glpat-[A-Za-z0-9_\-]{20,}", "GitLab token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "private key"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.", "JWT"),
)

_SECRET_KEY_HINTS = ("token", "secret", "password", "passwd", "apikey", "api_key", "key", "auth")
_SHELL_METACHARS = re.compile(r"[;&|`$><]|\$\(|\&\&|\|\|")
_REMOTE_RUNNERS = {"npx", "uvx", "bunx", "pipx"}


@dataclass
class ConfigFinding:
    code: str
    title: str
    severity: RiskLevel
    detail: str
    remediation: str
    server: str
    config_path: str | None = None


@dataclass
class ServerScanResult:
    server: MCPServer
    findings: list[ConfigFinding] = field(default_factory=list)

    @property
    def risk(self) -> RiskLevel:
        order = [RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        worst = RiskLevel.INFO
        for f in self.findings:
            if order.index(f.severity) > order.index(worst):
                worst = f.severity
        return worst


def check_server(server: MCPServer) -> list[ConfigFinding]:
    findings: list[ConfigFinding] = []
    path = server.__dict__.get("_config_path")
    raw_env: dict = server.__dict__.get("_raw_env", {})

    def add(code, title, sev, detail, remediation):
        findings.append(
            ConfigFinding(code, title, sev, detail, remediation, server.name, path)
        )

    # 1. Hardcoded secrets in env values.
    for key, value in raw_env.items():
        for pat, label in _SECRET_VALUE_PATTERNS:
            if re.search(pat, value):
                add(
                    "MCP-SEC-001",
                    "Hardcoded credential in config",
                    RiskLevel.CRITICAL,
                    f"env var '{key}' contains what looks like a {label}.",
                    "Move the secret to a secret manager or shell env; reference it "
                    "indirectly instead of committing the literal value.",
                )
                break
        # Long opaque value under a secret-ish key, even without a known prefix.
        if (
            any(h in key.lower() for h in _SECRET_KEY_HINTS)
            and isinstance(value, str)
            and len(value) >= 20
            and not value.startswith("${")
            and not value.startswith("$")
        ):
            add(
                "MCP-SEC-002",
                "Possible inlined secret",
                RiskLevel.HIGH,
                f"env var '{key}' holds a long literal value under a secret-like name.",
                "Reference an environment variable (e.g. \"${MY_TOKEN}\") instead of "
                "embedding the literal secret.",
            )

    # 2. Plaintext transport.
    if server.url and server.url.startswith("http://"):
        add(
            "MCP-NET-001",
            "Plaintext HTTP transport",
            RiskLevel.HIGH,
            f"server connects to {server.url} over unencrypted http://.",
            "Use https:// so tool traffic and any tokens are encrypted in transit.",
        )

    # 3. Deprecated SSE transport.
    if server.transport.value == "sse":
        add(
            "MCP-NET-002",
            "Deprecated SSE transport",
            RiskLevel.LOW,
            "server uses the deprecated SSE transport.",
            "Migrate to the Streamable HTTP transport when the server supports it.",
        )

    # 4. Remote code executed on every launch.
    if server.command in _REMOTE_RUNNERS:
        pinned = any(re.search(r"@\d+\.\d+", a) or "@sha256" in a for a in server.args)
        add(
            "MCP-SUP-001",
            "Remote code fetched at launch",
            RiskLevel.MEDIUM if pinned else RiskLevel.HIGH,
            f"'{server.command}' downloads and runs a package on each start"
            + (" (version-pinned)." if pinned else " with no version pin."),
            "Pin an exact version/digest and review the package, or vendor it "
            "locally, to avoid silent 'rug pull' updates.",
        )

    # 5. Auto-confirm flags suppress install prompts.
    if any(a in ("-y", "--yes") for a in server.args) and server.command in _REMOTE_RUNNERS:
        add(
            "MCP-SUP-002",
            "Auto-approves package install",
            RiskLevel.MEDIUM,
            "args include -y/--yes, suppressing the install confirmation.",
            "Drop auto-yes so new/changed packages require a human decision.",
        )

    # 6. Shell metacharacters (command injection surface).
    joined = " ".join([server.command or ""] + server.args)
    if _SHELL_METACHARS.search(joined):
        add(
            "MCP-CMD-001",
            "Shell metacharacters in command",
            RiskLevel.HIGH,
            "the command/args contain shell metacharacters (; & | ` $ > <).",
            "Avoid shell-string composition; pass discrete argv entries so input "
            "cannot be interpreted by a shell.",
        )

    # 7. Auto-approve / always-allow lists bypass human-in-the-loop.
    auto_approve = server.__dict__.get("_auto_approve") or []
    if auto_approve:
        add(
            "MCP-HIL-001",
            "Human-in-the-loop bypass (auto-approve)",
            RiskLevel.HIGH,
            f"config auto-approves {len(auto_approve)} tool(s) "
            f"({', '.join(map(str, auto_approve[:5]))}): the agent runs them with "
            "no per-call confirmation.",
            "Remove auto-approve for any tool with write/exec/network capability; "
            "route risky tools through the gateway's approval workflow instead.",
        )

    # 8. Authorization headers carrying inlined bearer tokens.
    headers = server.__dict__.get("_headers") or {}
    for hk, hv in headers.items():
        if hk.lower() == "authorization" and isinstance(hv, str) and "bearer " in hv.lower():
            tok = hv.split(None, 1)[-1]
            if len(tok) >= 16 and not tok.startswith("${") and not tok.startswith("$"):
                add(
                    "MCP-SEC-004",
                    "Bearer token in config header",
                    RiskLevel.CRITICAL,
                    "an Authorization header contains a literal bearer token.",
                    "Inject the token from a secret manager at runtime instead of "
                    "storing the literal value in the config file.",
                )

    # 9. Secret-looking token sitting in plaintext args.
    for arg in server.args:
        for pat, label in _SECRET_VALUE_PATTERNS:
            if re.search(pat, arg):
                add(
                    "MCP-SEC-003",
                    "Credential in command arguments",
                    RiskLevel.CRITICAL,
                    f"an argument contains what looks like a {label}.",
                    "Pass secrets via env or a secret manager, never as argv (argv is "
                    "visible to every process on the host).",
                )
                break

    if not findings:
        add(
            "MCP-OK",
            "No static config issues",
            RiskLevel.INFO,
            "no high-risk config patterns detected (runtime policy still applies).",
            "Register and review this server, then route it through the gateway.",
        )
    return findings
