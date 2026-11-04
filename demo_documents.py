"""Local demonstration using fictional stored documents."""

from gateway import Engine, Principal, Request
from document_store import fetch_document, resource_registry
from model_detector import LocalDetector


def main():
    print("Loading the local detector...")
    engine = Engine(
        resources=resource_registry(),
        classifier=LocalDetector(),
    )

    # Fictional identity for this demonstration, not a real login.
    person = Principal("company-a", "reader")

    examples = [
        ("Own company's handbook", "company-a-handbook"),
        ("Other company's handbook", "company-b-handbook"),
        ("Unknown document", "missing-handbook"),
    ]

    for title, document_id in examples:
        print(f"\nExample: {title}")

        try:
            document = fetch_document(document_id, person)
        except PermissionError:
            print("Decision: BLOCK")
            print("Reason: Document unavailable or access denied.")
            continue

        request = Request(
            text="What are the office hours?",
            documents=[document],
        )

        decision, reasons = engine.inspect(request, person)

        print(f"Decision: {decision}")
        print(f"Reasons: {', '.join(reasons)}")

        if decision == "ALLOW":
            print("Stored text:", document.text)
        else:
            print("Document text withheld from display.")

    print("\nDemonstration finished.")


if __name__ == "__main__":
    main()