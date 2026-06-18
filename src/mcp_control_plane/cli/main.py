"""The ``mcpcp`` command-line interface.

A single entrypoint over the same ControlPlane used by the API and gateway. The
command groups mirror the subsystems: scan, servers, policy, approvals, audit,
gateway, demo, plus ``serve`` (API + dashboard).
"""

from __future__ import annotations

import json as jsonlib
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_control_plane.core import ControlPlane
from mcp_control_plane.models import (
    CallContext,
    MCPTool,
    RiskLevel,
    ServerStatus,
)
from mcp_control_plane.policy.builtin import enrich_tool
from mcp_control_plane.version import __version__

console = Console()
err = Console(stderr=True)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="mcp-control-plane — the governance & security control plane for MCP.",
)
servers_app = typer.Typer(no_args_is_help=True, help="Inventory & review MCP servers.")
policy_app = typer.Typer(no_args_is_help=True, help="Inspect, explain and switch policy.")
approvals_app = typer.Typer(no_args_is_help=True, help="Human-in-the-loop approval queue.")
audit_app = typer.Typer(no_args_is_help=True, help="Inspect the tamper-evident audit trail.")
gateway_app = typer.Typer(no_args_is_help=True, help="Run the policy-enforcing MCP gateway.")
demo_app = typer.Typer(no_args_is_help=True, help="Load or reset demo data.")
app.add_typer(servers_app, name="servers")
app.add_typer(policy_app, name="policy")
app.add_typer(approvals_app, name="approvals")
app.add_typer(audit_app, name="audit")
app.add_typer(gateway_app, name="gateway")
app.add_typer(demo_app, name="demo")

_RISK_STYLE = {
    "info": "dim",
    "low": "green",
    "medium": "yellow",
    "high": "dark_orange3",
    "critical": "bold red",
}
_EFFECT_STYLE = {"allow": "green", "deny": "bold red", "require_approval": "yellow"}
_STATUS_STYLE = {
    "approved": "green",
    "discovered": "yellow",
    "pending": "dark_orange3",
    "rejected": "red",
    "disabled": "dim",
}


def _plane() -> ControlPlane:
    return ControlPlane()


def _risk(level: str) -> str:
    return f"[{_RISK_STYLE.get(level, 'white')}]{level}[/]"


# --------------------------------------------------------------------------- #
# top-level
# --------------------------------------------------------------------------- #
@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"mcp-control-plane {__version__}")


@app.command()
def info() -> None:
    """Show where state lives and current counts."""
    plane = _plane()
    s = plane.settings
    t = Table(show_header=False, box=None)
    t.add_row("home", str(s.home))
    t.add_row("database", str(s.db_path))
    t.add_row("policy file", str(s.policy_path) + ("" if s.policy_path.exists() else "  (using built-in baseline)"))
    t.add_row("api", f"http://{s.api_host}:{s.api_port}")
    t.add_row("auth", "token set" if s.api_token else "localhost-only (no token)")
    console.print(Panel(t, title="mcp-control-plane", border_style="cyan"))
    _print_stats(plane)


def _print_stats(plane: ControlPlane) -> None:
    st = plane.stats()
    chain = "[green]OK[/]" if st["audit_chain_ok"] else "[bold red]BROKEN[/]"
    console.print(
        f"servers=[bold]{st['servers']}[/] approved=[green]{st['approved']}[/] "
        f"pending-review=[yellow]{st['pending_servers']}[/] "
        f"pending-approvals=[dark_orange3]{st['pending_approvals']}[/] "
        f"audit-events={st['audit_events']} chain={chain}"
    )


@app.command()
def serve(
    host: str | None = typer.Option(None, help="Bind host (default 127.0.0.1)."),
    port: int | None = typer.Option(None, help="Bind port (default 8765)."),
    reload: bool = typer.Option(False, help="Auto-reload (development)."),
    insecure: bool = typer.Option(
        False, "--insecure", help="Allow a non-local bind without a token (NOT recommended)."
    ),
) -> None:
    """Start the control-plane API + dashboard."""
    import uvicorn

    plane = _plane()
    h = host or plane.settings.api_host
    p = port or plane.settings.api_port
    non_local = h not in ("127.0.0.1", "localhost", "::1", "")
    if non_local and not plane.settings.api_token and not insecure:
        err.print(
            f"[bold red]refusing to bind to non-local host '{h}' without a token.[/]\n"
            "Set MCPCP_API_TOKEN to require authentication, or pass --insecure to "
            "override (the API will still reject non-local clients until a token is set)."
        )
        raise typer.Exit(2)
    console.print(f"[cyan]mcp-control-plane[/] dashboard → http://{h}:{p}")
    uvicorn.run("mcp_control_plane.api.app:create_app", host=h, port=p, factory=True, reload=reload)


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    project: Path | None = typer.Option(None, "--project", "-p", help="Also scan a project dir for committed configs."),
    user: bool = typer.Option(True, help="Scan well-known per-user client configs."),
    fail_on: str = typer.Option("high", help="Min severity that fails CI (info|low|medium|high|critical)."),
    register: bool = typer.Option(False, help="Register discovered servers into the inventory."),
    ci: bool = typer.Option(False, "--ci", help="CI mode: terse output, exit non-zero on findings."),
    as_json: bool = typer.Option(False, "--json", help="Emit the report as JSON."),
) -> None:
    """Discover MCP servers across client configs and flag unsafe ones."""
    from mcp_control_plane.scanner import scan as run_scan

    report = run_scan(
        include_user=user,
        project_root=project,
        fail_on=RiskLevel(fail_on),
    )

    if as_json:
        console.print_json(jsonlib.dumps(report.to_dict()))
        raise typer.Exit(report.exit_code)

    if register:
        plane = _plane()
        for r in report.results:
            findings = [f for f in r.findings if f.code != "MCP-OK"]
            plane.registry.register(r.server, config_findings=findings)

    if not report.results:
        console.print("[dim]No MCP client configs found on this machine.[/]")
        raise typer.Exit(0)

    console.print(
        f"\nScanned [bold]{len(report.locations)}[/] config file(s), "
        f"[bold]{report.servers_scanned}[/] server(s).\n"
    )
    for r in report.results:
        head = (
            f"{_risk(r.risk.value)}  [bold]{r.server.name}[/]  "
            f"[dim]{r.server.source} · {r.server.transport.value}[/]"
        )
        console.print(head)
        for f in r.findings:
            if f.code == "MCP-OK":
                console.print(f"   [green]✓[/] {f.detail}")
                continue
            console.print(
                f"   [{_RISK_STYLE.get(f.severity.value)}]●[/] "
                f"[bold]{f.code}[/] {f.title} — {f.detail}"
            )
            if not ci:
                console.print(f"      [dim]↳ {f.remediation}[/]")
        console.print()

    sc = report.severity_counts
    banner = (
        f"critical={sc['critical']} high={sc['high']} medium={sc['medium']} "
        f"low={sc['low']} info={sc['info']}"
    )
    if report.passed:
        console.print(Panel(f"[green]PASS[/] · worst={_risk(report.worst.value)} · {banner}", border_style="green"))
    else:
        console.print(Panel(f"[bold red]FAIL[/] · worst={_risk(report.worst.value)} · {banner} · fail-on={fail_on}", border_style="red"))
    raise typer.Exit(report.exit_code)


# --------------------------------------------------------------------------- #
# servers
# --------------------------------------------------------------------------- #
@servers_app.command("list")
def servers_list(status: str | None = typer.Option(None, help="Filter by status.")) -> None:
    plane = _plane()
    st = ServerStatus(status) if status else None
    rows = plane.registry.list(st)
    if not rows:
        console.print("[dim]No servers registered. Try `mcpcp scan --register` or `mcpcp demo seed`.[/]")
        return
    t = Table(title="MCP servers")
    t.add_column("risk")
    t.add_column("name", style="bold")
    t.add_column("status")
    t.add_column("transport")
    t.add_column("tools", justify="right")
    t.add_column("source", style="dim")
    t.add_column("id", style="dim")
    for s in rows:
        t.add_row(
            f"{_risk(s.risk.value)} {s.risk_score}",
            s.name,
            f"[{_STATUS_STYLE.get(s.status.value,'white')}]{s.status.value}[/]",
            s.transport.value,
            str(len(s.tools)),
            s.source,
            s.id,
        )
    console.print(t)


def _resolve_server(plane: ControlPlane, ref: str):
    return plane.registry.get(ref) or plane.registry.get_by_name(ref)


@servers_app.command("show")
def servers_show(ref: str = typer.Argument(..., help="Server id or name.")) -> None:
    plane = _plane()
    s = _resolve_server(plane, ref)
    if not s:
        err.print(f"[red]no server matching '{ref}'[/]")
        raise typer.Exit(1)
    console.print(Panel.fit(
        f"[bold]{s.name}[/]  {_risk(s.risk.value)} ({s.risk_score})\n"
        f"[dim]{s.description}[/]\n"
        f"status: [{_STATUS_STYLE.get(s.status.value)}]{s.status.value}[/]   "
        f"transport: {s.transport.value}   source: {s.source}\n"
        f"command: {s.command or s.url}  {' '.join(s.args)}\n"
        f"env keys: {', '.join(s.env_keys) or '—'}   tags: {', '.join(s.tags) or '—'}",
        title=s.id, border_style="cyan",
    ))
    if s.risk_factors:
        console.print("[bold]risk factors[/]")
        for f in s.risk_factors:
            console.print(f"  [yellow]•[/] {f}")
    if s.tools:
        t = Table(title="tools")
        t.add_column("tool", style="bold")
        t.add_column("risk")
        t.add_column("capabilities")
        t.add_column("findings", style="red")
        for tool in s.tools:
            t.add_row(
                tool.name,
                _risk(tool.risk.value),
                ", ".join(c.value for c in tool.capabilities),
                "; ".join(tool.findings) or "",
            )
        console.print(t)
    if s.config_findings:
        ct = Table(title="static config findings (scanner)")
        ct.add_column("code", style="bold")
        ct.add_column("severity")
        ct.add_column("finding")
        ct.add_column("remediation", style="dim")
        for f in s.config_findings:
            ct.add_row(
                f.get("code", "?"),
                _risk(str(f.get("severity", "info"))),
                f.get("title", ""),
                f.get("remediation", ""),
            )
        console.print(ct)


@servers_app.command("approve")
def servers_approve(ref: str, by: str = typer.Option("cli"), note: str | None = typer.Option(None)) -> None:
    _set_status(ref, ServerStatus.APPROVED, by, note)


@servers_app.command("reject")
def servers_reject(ref: str, by: str = typer.Option("cli"), note: str | None = typer.Option(None)) -> None:
    _set_status(ref, ServerStatus.REJECTED, by, note)


@servers_app.command("disable")
def servers_disable(ref: str, by: str = typer.Option("cli"), note: str | None = typer.Option(None)) -> None:
    _set_status(ref, ServerStatus.DISABLED, by, note)


@servers_app.command("rm")
def servers_rm(ref: str) -> None:
    plane = _plane()
    s = _resolve_server(plane, ref)
    if not s or not plane.db.delete_server(s.id):
        err.print(f"[red]no server matching '{ref}'[/]")
        raise typer.Exit(1)
    console.print(f"[green]deleted[/] {s.name} ({s.id})")


def _set_status(ref: str, status: ServerStatus, by: str, note: str | None) -> None:
    plane = _plane()
    s = _resolve_server(plane, ref)
    if not s:
        err.print(f"[red]no server matching '{ref}'[/]")
        raise typer.Exit(1)
    s = plane.registry.set_status(s.id, status, by=by, note=note)
    console.print(f"[green]{s.name}[/] → [{_STATUS_STYLE.get(status.value)}]{status.value}[/]")


# --------------------------------------------------------------------------- #
# policy
# --------------------------------------------------------------------------- #
@policy_app.command("show")
def policy_show() -> None:
    plane = _plane()
    p = plane.policy
    console.print(Panel.fit(
        f"[bold]{p.name}[/]  [dim]{p.description}[/]\n"
        f"default: [{_EFFECT_STYLE.get(p.default_effect.value)}]{p.default_effect.value}[/]   "
        f"unapproved→[{_EFFECT_STYLE.get(p.settings.unapproved_server_effect.value)}]"
        f"{p.settings.unapproved_server_effect.value}[/]",
        title="active policy", border_style="cyan",
    ))
    t = Table(title="rules (priority desc)")
    t.add_column("prio", justify="right")
    t.add_column("id", style="bold")
    t.add_column("effect")
    t.add_column("description")
    for r in p.sorted_rules():
        t.add_row(str(r.priority), r.id, f"[{_EFFECT_STYLE.get(r.effect.value)}]{r.effect.value}[/]", r.description)
    console.print(t)


@policy_app.command("init")
def policy_init(
    template: str = typer.Option("baseline", help="baseline|strict|permissive-demo"),
    force: bool = typer.Option(False, help="Overwrite an existing policy file."),
) -> None:
    """Write a starter policy.yaml you can edit and commit."""
    import yaml

    from mcp_control_plane.policy.default_policies import BUILTIN_POLICIES

    if template not in BUILTIN_POLICIES:
        err.print(f"[red]unknown template '{template}'. Choose from {list(BUILTIN_POLICIES)}[/]")
        raise typer.Exit(1)
    plane = _plane()
    path = plane.settings.policy_path
    if path.exists() and not force:
        err.print(f"[red]{path} exists; use --force to overwrite[/]")
        raise typer.Exit(1)
    policy = BUILTIN_POLICIES[template]()
    path.write_text(yaml.safe_dump(policy.model_dump(mode="json"), sort_keys=False))
    console.print(f"[green]wrote[/] {path}  (template: {template})")


@policy_app.command("explain")
def policy_explain(
    server: str = typer.Argument(..., help="Server id or name."),
    tool: str = typer.Argument(..., help="Tool name."),
    args: str = typer.Option("{}", "--args", help="Arguments as JSON."),
    agent: str = typer.Option("explorer", help="Calling agent identity."),
) -> None:
    """Dry-run a tool call through the policy and print the full decision trace."""
    plane = _plane()
    s = _resolve_server(plane, server)
    if not s:
        err.print(f"[red]no server matching '{server}'[/]")
        raise typer.Exit(1)
    try:
        arguments = jsonlib.loads(args)
    except jsonlib.JSONDecodeError as e:
        err.print(f"[red]--args is not valid JSON: {e}[/]")
        raise typer.Exit(1) from None
    tool_obj = next((t for t in s.tools if t.name == tool), None) or enrich_tool(MCPTool(name=tool))
    ctx = CallContext(server=s, tool=tool_obj, arguments=arguments, agent=agent)
    d = plane.decide(ctx)
    color = _EFFECT_STYLE.get(d.effect.value, "white")
    console.print(Panel.fit(
        f"[{color}]{d.effect.value.upper()}[/]  {_risk(d.risk.value)}\n{d.reason}",
        title=f"{s.name} · {tool}", border_style=color,
    ))
    if d.obligations:
        console.print(f"obligations: [magenta]{', '.join(d.obligations)}[/]")
    t = Table(title="decision trace")
    t.add_column("rule", style="bold")
    t.add_column("effect")
    t.add_column("matched")
    t.add_column("why", style="dim")
    for step in d.trace:
        t.add_row(
            str(step.get("rule")),
            f"[{_EFFECT_STYLE.get(step.get('effect'),'white')}]{step.get('effect')}[/]",
            "[green]✓[/]" if step.get("matched") else "[dim]·[/]",
            "; ".join(step.get("why", [])),
        )
    console.print(t)


# --------------------------------------------------------------------------- #
# approvals
# --------------------------------------------------------------------------- #
@approvals_app.command("list")
def approvals_list(status: str = typer.Option("pending", help="pending|approved|denied|all")) -> None:
    plane = _plane()
    items = plane.approvals.list(None if status == "all" else status)
    if not items:
        console.print(f"[dim]No {status} approvals.[/]")
        return
    t = Table(title=f"approvals ({status})")
    t.add_column("id", style="bold")
    t.add_column("risk")
    t.add_column("server.tool")
    t.add_column("agent")
    t.add_column("reason", style="dim")
    t.add_column("state")
    for a in items:
        t.add_row(a.id, _risk(a.risk.value), f"{a.server_name}.{a.tool}", a.agent, a.reason[:50], a.status.value)
    console.print(t)


@approvals_app.command("approve")
def approvals_approve(approval_id: str, by: str = typer.Option("cli"), note: str | None = typer.Option(None)) -> None:
    _decide(approval_id, True, by, note)


@approvals_app.command("deny")
def approvals_deny(approval_id: str, by: str = typer.Option("cli"), note: str | None = typer.Option(None)) -> None:
    _decide(approval_id, False, by, note)


def _decide(approval_id: str, approve: bool, by: str, note: str | None) -> None:
    plane = _plane()
    try:
        a = plane.approvals.decide(
            approval_id, approve, by=by, note=note,
            grant_ttl_seconds=plane.policy.settings.approval_grant_ttl_seconds,
        )
    except KeyError:
        err.print(f"[red]no approval '{approval_id}'[/]")
        raise typer.Exit(1) from None
    word = "approved" if approve else "denied"
    extra = ""
    if approve and a.expires_at:
        extra = f" — grant valid until {a.expires_at.strftime('%H:%M:%S')} for the identical call"
    console.print(f"[{'green' if approve else 'red'}]{word}[/] {a.id} ({a.server_name}.{a.tool}){extra}")


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #
@audit_app.command("tail")
def audit_tail(limit: int = typer.Option(20), kind: str | None = typer.Option(None)) -> None:
    plane = _plane()
    events = plane.audit.recent(limit=limit, kind=kind)
    if not events:
        console.print("[dim]No audit events yet.[/]")
        return
    t = Table(title="audit trail (newest first)")
    t.add_column("time", style="dim")
    t.add_column("kind")
    t.add_column("effect/outcome")
    t.add_column("target")
    t.add_column("reason", style="dim")
    for e in events:
        eff = e.effect.value if e.effect else (e.outcome or "")
        style = _EFFECT_STYLE.get(eff, "white")
        target = f"{e.server_name}.{e.tool}" if e.tool else (e.server_name or "")
        t.add_row(
            e.timestamp.strftime("%H:%M:%S"),
            e.kind,
            f"[{style}]{eff}[/]",
            target,
            (e.reason or "")[:60],
        )
    console.print(t)


@audit_app.command("verify")
def audit_verify() -> None:
    """Recompute the audit hash chain and report tampering."""
    plane = _plane()
    ok, broken = plane.audit.verify()
    if ok:
        console.print("[green]✓ audit chain intact[/] — no tampering detected")
    else:
        err.print(f"[bold red]✗ audit chain BROKEN[/] at event {broken}")
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# gateway
# --------------------------------------------------------------------------- #
@gateway_app.command("run", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def gateway_run(
    ctx: typer.Context,
    server: str = typer.Option(..., "--server", "-s", help="Registry name for the upstream server."),
    agent: str = typer.Option("unknown", help="Identity of the calling agent."),
    approval_mode: str = typer.Option("deny", help="deny | wait — how to handle require_approval."),
    approval_timeout: float = typer.Option(120.0, help="Seconds to wait in --approval-mode wait."),
) -> None:
    """Wrap an upstream MCP server: `mcpcp gateway run -s NAME -- <command...>`.

    The agent launches THIS as the server; we spawn the real command and enforce
    policy on every tool call in between.
    """
    from mcp_control_plane.gateway.stdio import run_stdio_gateway

    upstream = list(ctx.args)
    if not upstream:
        err.print("[red]provide the upstream command after `--`, e.g. "
                  "`mcpcp gateway run -s fs -- npx -y @modelcontextprotocol/server-filesystem /tmp`[/]")
        raise typer.Exit(2)
    command, *args = upstream
    plane = _plane()
    code = run_stdio_gateway(
        plane, server, command, args,
        agent=agent, approval_mode=approval_mode, approval_timeout=approval_timeout,
    )
    raise typer.Exit(code)


# --------------------------------------------------------------------------- #
# demo
# --------------------------------------------------------------------------- #
@demo_app.command("seed")
def demo_seed() -> None:
    """Load the demo scenario (servers, audit trail, pending approvals)."""
    from mcp_control_plane.demo.seed import seed

    result = seed(_plane())
    console.print(f"[green]seeded[/] {len(result['servers'])} servers: {', '.join(result['servers'])}")
    _print_stats(_plane())
    console.print("\nNext: [cyan]mcpcp serve[/] then open the dashboard, or `mcpcp servers list`.")


@demo_app.command("reset")
def demo_reset(yes: bool = typer.Option(False, "--yes", help="Skip confirmation.")) -> None:
    """Delete all local state (the SQLite database)."""
    from mcp_control_plane.demo.seed import reset

    plane = _plane()
    if not yes:
        typer.confirm(f"Delete {plane.settings.db_path}?", abort=True)
    reset(plane)
    console.print("[green]reset complete[/]")


if __name__ == "__main__":
    app()
