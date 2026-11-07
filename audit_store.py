"""Save firewall decisions in a local SQLite database."""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


class ApprovalAlreadyUsed(Exception):
    pass


class ApprovalRevoked(Exception):
    pass


def record_decision(request_id, tenant, decision, reasons, policy_version, *, approval_id=None):
    folder = Path(os.environ["LOCALAPPDATA"]) / "AI-Firewall"
    folder.mkdir(parents=True, exist_ok=True)
    database = folder / "audit.sqlite3"

    with closing(sqlite3.connect(database, timeout=3)) as connection:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS decisions (
                    request_id TEXT PRIMARY KEY,
                    recorded_at_utc TEXT NOT NULL,
                    tenant TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    policy_version TEXT NOT NULL
                )
            """)
            if approval_id is not None:
                connection.execute("""CREATE TABLE IF NOT EXISTS redeemed_approvals (
                    tenant TEXT NOT NULL, approval_id TEXT NOT NULL, request_id TEXT NOT NULL,
                    PRIMARY KEY (tenant, approval_id))""")
                inserted = connection.execute(
                    "INSERT INTO redeemed_approvals VALUES (?, ?, ?) "
                    "ON CONFLICT(tenant, approval_id) DO NOTHING",
                    (tenant, approval_id, request_id),
                )
                if inserted.rowcount == 0:
                    previous = connection.execute(
                        "SELECT d.reasons_json FROM redeemed_approvals a "
                        "JOIN decisions d ON d.request_id = a.request_id "
                        "WHERE a.tenant = ? AND a.approval_id = ?",
                        (tenant, approval_id),
                    ).fetchone()
                    if previous and json.loads(previous[0]) == ["share_approval_revoked"]:
                        raise ApprovalRevoked()
                    raise ApprovalAlreadyUsed()
            connection.execute(
                "INSERT INTO decisions "
                "(request_id, recorded_at_utc, tenant, decision, "
                "reasons_json, policy_version) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    datetime.now(timezone.utc).isoformat(),
                    tenant,
                    decision,
                    json.dumps(reasons),
                    policy_version,
                ),
            )
    return database