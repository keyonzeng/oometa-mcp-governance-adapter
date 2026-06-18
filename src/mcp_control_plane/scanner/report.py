"""Scan orchestration and reporting.

``scan()`` ties discovery + static checks together into a :class:`ScanReport`
that the CLI, API and CI integration all render. The report has a machine
summary (counts by severity), a non-zero ``exit_code`` for CI gating, and the
per-server findings for humans.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mcp_control_plane.models import RiskLevel
from mcp_control_plane.scanner.discover import ConfigLocation, discover
from mcp_control_plane.scanner.rules import (
    ConfigFinding,
    ServerScanResult,
    check_server,
)

_ORDER = [RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


@dataclass
class ScanReport:
    results: list[ServerScanResult] = field(default_factory=list)
    locations: list[ConfigLocation] = field(default_factory=list)
    fail_on: RiskLevel = RiskLevel.HIGH

    @property
    def findings(self) -> list[ConfigFinding]:
        return [f for r in self.results for f in r.findings if f.code != "MCP-OK"]

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {lvl.value: 0 for lvl in _ORDER}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def servers_scanned(self) -> int:
        return len(self.results)

    @property
    def worst(self) -> RiskLevel:
        worst = RiskLevel.INFO
        for f in self.findings:
            if _ORDER.index(f.severity) > _ORDER.index(worst):
                worst = f.severity
        return worst

    @property
    def passed(self) -> bool:
        return _ORDER.index(self.worst) < _ORDER.index(self.fail_on)

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1

    def to_dict(self) -> dict:
        return {
            "servers_scanned": self.servers_scanned,
            "severity_counts": self.severity_counts,
            "worst": self.worst.value,
            "passed": self.passed,
            "fail_on": self.fail_on.value,
            "configs": [
                {"client": loc.client, "path": str(loc.path), "scope": loc.scope}
                for loc in self.locations
            ],
            "servers": [
                {
                    "name": r.server.name,
                    "source": r.server.source,
                    "transport": r.server.transport.value,
                    "command": r.server.command,
                    "risk": r.risk.value,
                    "findings": [
                        {
                            "code": f.code,
                            "title": f.title,
                            "severity": f.severity.value,
                            "detail": f.detail,
                            "remediation": f.remediation,
                            "config_path": f.config_path,
                        }
                        for f in r.findings
                    ],
                }
                for r in self.results
            ],
        }


def scan(
    *,
    include_user: bool = True,
    project_root: Path | None = None,
    fail_on: RiskLevel = RiskLevel.HIGH,
) -> ScanReport:
    report = ScanReport(fail_on=fail_on)
    for loc, servers in discover(include_user=include_user, project_root=project_root):
        report.locations.append(loc)
        for server in servers:
            findings = check_server(server)
            report.results.append(ServerScanResult(server=server, findings=findings))
    return report
