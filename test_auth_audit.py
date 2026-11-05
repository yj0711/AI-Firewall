import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
import json

from audit_store import record_decision
from gateway import create_app, Principal
from test_gateway import Client


class AuthAuditTests(unittest.TestCase):
    def test_failed_signins_are_traceable_without_exposing_keys(self):
        client = Client(create_app(identities={"demo-valid": Principal("company-a", "reader")},
                                   audit_writer=record_decision))
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, LOCALAPPDATA=folder):
            database = Path(folder) / "AI-Firewall" / "audit.sqlite3"
            for header, reason in [(None, "missing_credentials"),
                                   ("Bearer demo-wrong-key", "invalid_credentials"),
                                   ("Basic demo-wrong-key", "invalid_credentials")]:
                with self.subTest(reason=reason):
                    headers = {"Authorization": header} if header else {}
                    with self.assertLogs("firewall.audit", level="INFO") as captured:
                        response = client.post("/v1/inspect", headers=headers, json={"text": "hello"})
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.json(), {"detail": "authentication required"})
                    with closing(sqlite3.connect(database)) as connection:
                        row = connection.execute(
                            "SELECT tenant, decision, reasons_json, recorded_at_utc FROM decisions WHERE request_id=?",
                            (response.headers["X-Request-ID"],),
                        ).fetchone()
                    self.assertEqual(row[:3], ("unauthenticated", "BLOCK", json.dumps([reason])))
                    self.assertTrue(row[3])
                    self.assertNotIn("demo-wrong-key", str(captured.output))
                    self.assertNotIn(b"demo-wrong-key", database.read_bytes())
