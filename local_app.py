"""Connect the components for a local development application."""

import os

from audit_store import record_decision
from gateway import Engine, Principal, create_app
from document_store import fetch_document, resource_registry
from model_detector import LocalDetector


def build_app():
    # Read the access key from the environment, not from source code.
    token = os.environ.get("FIREWALL_API_KEY")

    if not token or len(token) < 32 or token != token.strip():
        raise RuntimeError(
            "Set FIREWALL_API_KEY to a random key of at least "
            "32 characters, without leading or trailing whitespace."
        )

    print("Loading the local detector...")
    detector = LocalDetector()

    engine = Engine(
        resources=resource_registry(),
        classifier=detector,
    )

    # Local demonstration: this key represents Company A's reader.
    identities = {
        token: Principal("company-a", "reader"),
    }

    return create_app(
        engine=engine,
        identities=identities,
        document_loader=fetch_document,
        audit_writer=record_decision,
    )