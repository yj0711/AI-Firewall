"""Save firewall decisions in a local SQLite database."""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def record_decision(request_id, tenant, decision, reasons, policy_version):
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