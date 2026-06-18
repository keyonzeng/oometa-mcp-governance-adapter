from mcp_control_plane.models import AuditEvent


def test_chain_verifies_and_detects_tampering(plane):
    for i in range(5):
        plane.audit.record_event("registry", reason=f"event-{i}")
    ok, broken = plane.audit.verify()
    assert ok and broken is None

    # Tamper with a stored row directly.
    row = plane.db._conn.execute("SELECT id, data FROM audit_events ORDER BY seq LIMIT 1").fetchone()
    ev = AuditEvent.model_validate_json(row["data"])
    ev.reason = "TAMPERED"
    plane.db._conn.execute("UPDATE audit_events SET data=? WHERE id=?", (ev.model_dump_json(), ev.id))
    plane.db._conn.commit()

    ok2, broken2 = plane.audit.verify()
    assert not ok2
    assert broken2 == ev.id
