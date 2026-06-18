"""SQLite-backed persistence for the control plane.

Design choices:
    * Standard-library ``sqlite3`` only — no ORM, no migration framework. The
      governance data model is small and append-heavy; a single file keeps
      self-hosting trivial.
    * Entities are stored as JSON blobs in a thin relational envelope. We index
      the columns we actually query on (status, timestamp, server_id) and treat
      the JSON as the source of truth, so the schema rarely needs to change.
    * The audit table is an append-only hash chain (see ``append_audit``).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from pathlib import Path

from mcp_control_plane.models import (
    Approval,
    AuditEvent,
    MCPServer,
    ServerStatus,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL,
    risk_score  INTEGER NOT NULL DEFAULT 0,
    fingerprint TEXT,
    updated_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(status);

CREATE TABLE IF NOT EXISTS audit_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    id          TEXT UNIQUE NOT NULL,
    timestamp   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    server_id   TEXT,
    hash        TEXT NOT NULL,
    prev_hash   TEXT,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_events(kind);

CREATE TABLE IF NOT EXISTS approvals (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


class Database:
    """Thread-safe wrapper around a single SQLite file."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ----- locked primitives --------------------------------------------- #
    # A single sqlite3.Connection must not be used concurrently from multiple
    # threads (FastAPI runs sync endpoints in a threadpool), so EVERY access —
    # reads included — is serialised through one lock.
    def _fetchone(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def _fetchall(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    # ----- servers -------------------------------------------------------- #
    def upsert_server(self, server: MCPServer) -> MCPServer:
        with self._lock:
            self._conn.execute(
                """INSERT INTO servers (id, name, status, risk_score, fingerprint, updated_at, data)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name, status=excluded.status,
                     risk_score=excluded.risk_score, fingerprint=excluded.fingerprint,
                     updated_at=excluded.updated_at, data=excluded.data""",
                (
                    server.id,
                    server.name,
                    server.status.value,
                    server.risk_score,
                    server.fingerprint(),
                    server.updated_at.isoformat(),
                    server.model_dump_json(),
                ),
            )
            self._conn.commit()
        return server

    def get_server(self, server_id: str) -> MCPServer | None:
        row = self._fetchone("SELECT data FROM servers WHERE id=?", (server_id,))
        return MCPServer.model_validate_json(row["data"]) if row else None

    def find_server_by_name(self, name: str) -> MCPServer | None:
        row = self._fetchone(
            "SELECT data FROM servers WHERE name=? ORDER BY updated_at DESC LIMIT 1", (name,)
        )
        return MCPServer.model_validate_json(row["data"]) if row else None

    def list_servers(self, status: ServerStatus | None = None) -> list[MCPServer]:
        if status:
            rows = self._fetchall(
                "SELECT data FROM servers WHERE status=? ORDER BY risk_score DESC, name",
                (status.value,),
            )
        else:
            rows = self._fetchall("SELECT data FROM servers ORDER BY risk_score DESC, name")
        return [MCPServer.model_validate_json(r["data"]) for r in rows]

    def delete_server(self, server_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM servers WHERE id=?", (server_id,))
            self._conn.commit()
        return cur.rowcount > 0

    # ----- audit (append-only hash chain) --------------------------------- #
    def _last_hash(self) -> str | None:
        row = self._conn.execute(
            "SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["hash"] if row else None

    def append_audit(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            prev = self._last_hash()
            event.prev_hash = prev
            event.hash = event.compute_hash(prev)
            self._conn.execute(
                """INSERT INTO audit_events (id, timestamp, kind, server_id, hash, prev_hash, data)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    event.id,
                    event.timestamp.isoformat(),
                    event.kind,
                    event.server_id,
                    event.hash,
                    event.prev_hash,
                    event.model_dump_json(),
                ),
            )
            self._conn.commit()
        return event

    def list_audit(
        self,
        limit: int = 100,
        kind: str | None = None,
        server_id: str | None = None,
    ) -> list[AuditEvent]:
        q = "SELECT data FROM audit_events"
        clauses, params = [], []
        if kind:
            clauses.append("kind=?")
            params.append(kind)
        if server_id:
            clauses.append("server_id=?")
            params.append(server_id)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY seq DESC LIMIT ?"
        params.append(limit)
        rows = self._fetchall(q, tuple(params))
        return [AuditEvent.model_validate_json(r["data"]) for r in rows]

    def iter_audit_chain(self) -> Iterable[AuditEvent]:
        rows = self._fetchall("SELECT data FROM audit_events ORDER BY seq ASC")
        for r in rows:
            yield AuditEvent.model_validate_json(r["data"])

    def verify_audit_chain(self) -> tuple[bool, str | None]:
        """Recompute the hash chain; return (ok, first_broken_event_id)."""
        prev = None
        for ev in self.iter_audit_chain():
            expected = ev.compute_hash(prev)
            if ev.hash != expected or ev.prev_hash != prev:
                return False, ev.id
            prev = ev.hash
        return True, None

    # ----- approvals ------------------------------------------------------ #
    def upsert_approval(self, approval: Approval) -> Approval:
        with self._lock:
            self._conn.execute(
                """INSERT INTO approvals (id, status, requested_at, data)
                   VALUES (?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET status=excluded.status, data=excluded.data""",
                (
                    approval.id,
                    approval.status.value,
                    approval.requested_at.isoformat(),
                    approval.model_dump_json(),
                ),
            )
            self._conn.commit()
        return approval

    def get_approval(self, approval_id: str) -> Approval | None:
        row = self._fetchone("SELECT data FROM approvals WHERE id=?", (approval_id,))
        return Approval.model_validate_json(row["data"]) if row else None

    def list_approvals(self, status: str | None = None, limit: int = 100) -> list[Approval]:
        if status:
            rows = self._fetchall(
                "SELECT data FROM approvals WHERE status=? ORDER BY requested_at DESC LIMIT ?",
                (status, limit),
            )
        else:
            rows = self._fetchall(
                "SELECT data FROM approvals ORDER BY requested_at DESC LIMIT ?", (limit,)
            )
        return [Approval.model_validate_json(r["data"]) for r in rows]

    # ----- meta ----------------------------------------------------------- #
    def set_meta(self, key: str, value: object) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )
            self._conn.commit()

    def get_meta(self, key: str, default: object = None) -> object:
        row = self._fetchone("SELECT value FROM meta WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    # ----- stats ---------------------------------------------------------- #
    def counts(self) -> dict[str, int]:
        one = self._fetchone
        return {
            "servers": one("SELECT COUNT(*) n FROM servers")["n"],
            "approved": one("SELECT COUNT(*) n FROM servers WHERE status='approved'")["n"],
            "pending_servers": one(
                "SELECT COUNT(*) n FROM servers WHERE status IN ('discovered','pending')"
            )["n"],
            "audit_events": one("SELECT COUNT(*) n FROM audit_events")["n"],
            "pending_approvals": one(
                "SELECT COUNT(*) n FROM approvals WHERE status='pending'"
            )["n"],
        }


_db_singletons: dict[str, Database] = {}
_singleton_lock = threading.Lock()


def get_db(path: str | Path) -> Database:
    """Process-wide singleton per database path."""
    key = str(path)
    with _singleton_lock:
        if key not in _db_singletons:
            _db_singletons[key] = Database(key)
        return _db_singletons[key]
