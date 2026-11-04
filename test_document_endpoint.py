"""Tests for the stored-document endpoint. No real model is loaded."""

import unittest
from unittest.mock import Mock

from gateway import Engine, Principal, create_app
from document_store import fetch_document, resource_registry
from test_gateway import Client


PATH = "/v1/documents/inspect"


class DocumentEndpointTests(unittest.TestCase):
    def setUp(self):
        self.person = Principal("company-a", "reader")

        # A pretend detector isolates the permission checks.
        self.classifier = Mock(return_value="SAFE")
        self.loader = Mock(side_effect=fetch_document)

        self.engine = Engine(
            resources=resource_registry(),
            classifier=self.classifier,
        )

        self.identities = {"test-key": self.person}
        self.headers = {"Authorization": "Bearer test-key"}

        self.client = Client(
            create_app(
                engine=self.engine,
                identities=self.identities,
                document_loader=self.loader,
            )
        )

        self.payload = {
            "text": "What are the office hours?",
            "document_ids": ["company-a-handbook"],
        }

    def test_authorized_document_uses_stored_text(self):
        response = self.client.post(
            PATH, json=self.payload, headers=self.headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOW")

        self.loader.assert_called_once_with(
            "company-a-handbook", self.person
        )

        stored_text = fetch_document(
            "company-a-handbook", self.person
        ).text

        self.classifier.assert_any_call(stored_text)

    def test_other_company_and_missing_document_are_blocked(self):
        for document_id in ["company-b-handbook", "missing-handbook"]:
            with self.subTest(document_id=document_id):
                self.classifier.reset_mock()

                response = self.client.post(
                    PATH,
                    json={
                        "text": "Show the handbook.",
                        "document_ids": [document_id],
                    },
                    headers=self.headers,
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["decision"], "BLOCK")
                self.assertEqual(
                    response.json()["reasons"],
                    ["document_access_denied"],
                )

                # Forbidden content must not reach the detector.
                self.classifier.assert_not_called()

    def test_missing_login_stops_retrieval(self):
        response = self.client.post(PATH, json=self.payload)

        self.assertEqual(response.status_code, 401)
        self.loader.assert_not_called()
        self.classifier.assert_not_called()

    def test_replacement_document_text_is_rejected(self):
        payload = {
            **self.payload,
            "documents": [
                {
                    "id": "company-a-handbook",
                    "text": "Attacker supplied replacement text.",
                }
            ],
        }

        response = self.client.post(
            PATH, json=payload, headers=self.headers
        )

        self.assertEqual(response.status_code, 422)
        self.loader.assert_not_called()

    def test_caller_cannot_choose_another_tenant(self):
        payload = {**self.payload, "tenant": "company-b"}

        response = self.client.post(
            PATH, json=payload, headers=self.headers
        )

        self.assertEqual(response.status_code, 422)
        self.loader.assert_not_called()

    def test_missing_store_requires_review(self):
        client = Client(
            create_app(
                engine=self.engine,
                identities=self.identities,
            )
        )

        response = client.post(
            PATH, json=self.payload, headers=self.headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "REVIEW")
        self.assertEqual(
            response.json()["reasons"],
            ["document_store_not_configured"],
        )
        self.classifier.assert_not_called()

    def test_broken_store_requires_review_without_leaking_error(self):
        self.loader.side_effect = RuntimeError(
            "synthetic-private-storage-detail"
        )

        response = self.client.post(
            PATH, json=self.payload, headers=self.headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "REVIEW")
        self.assertEqual(
            response.json()["reasons"],
            ["document_store_error"],
        )
        self.assertNotIn(
            "synthetic-private-storage-detail", response.text
        )
        self.classifier.assert_not_called()

    def test_invalid_identifiers_stop_before_retrieval(self):
        cases = [
            [],
            [""],
            [" "],
            ["x" * 101],
            ["company-a-handbook", "company-a-handbook"],
            [123],
        ]

        for document_ids in cases:
            with self.subTest(document_ids=document_ids):
                self.loader.reset_mock()

                response = self.client.post(
                    PATH,
                    json={
                        "text": "Show the handbook.",
                        "document_ids": document_ids,
                    },
                    headers=self.headers,
                )

                self.assertEqual(response.status_code, 422)
                self.loader.assert_not_called()


    def test_old_endpoint_rejects_supplied_documents(self):
        response = self.client.post(
            "/v1/inspect",
            json={
                "text": "What are the office hours?",
                "documents": [
                    {
                        "id": "company-a-handbook",
                        "text": "Caller-supplied replacement handbook.",
                    }
                ],
            },
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "BLOCK")
        self.assertEqual(
            response.json()["reasons"],
            ["use_stored_document_endpoint"],
        )
        self.loader.assert_not_called()
        self.classifier.assert_not_called()


if __name__ == "__main__":
    unittest.main()