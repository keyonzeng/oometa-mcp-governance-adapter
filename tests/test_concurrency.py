"""Regression: the shared SQLite connection must tolerate concurrent threads
(FastAPI serves sync endpoints from a threadpool)."""

from __future__ import annotations

import concurrent.futures as cf

from mcp_control_plane.models import MCPServer, MCPTool


def test_concurrent_reads_and_writes_do_not_corrupt(plane):
    # Seed a few servers and audit events.
    for i in range(10):
        s = MCPServer(name=f"s{i}", tools=[MCPTool(name="read_file", description="read a file")])
        plane.registry.register(s)

    def worker(n: int):
        plane.registry.list()
        plane.audit.record_event("registry", reason=f"w{n}")
        plane.stats()
        plane.audit.verify()
        return plane.db.counts()["servers"]

    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(worker, range(60)))

    assert all(r == 10 for r in results)
    ok, broken = plane.audit.verify()
    assert ok and broken is None
