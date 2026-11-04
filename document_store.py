"""A small document store containing only fictional demo data."""

from dataclasses import dataclass
from types import MappingProxyType

from gateway import Document, Principal, Resource


@dataclass(frozen=True)
class StoredDocument:
    tenant: str
    roles: frozenset[str]
    text: str


# Read-only demo records. These are not real company documents.
_DOCUMENTS = MappingProxyType({
    "company-a-handbook": StoredDocument(
        tenant="company-a",
        roles=frozenset({"reader"}),
        text="Company A office hours are Monday to Friday, 9 AM to 5 PM.",
    ),
    "company-b-handbook": StoredDocument(
        tenant="company-b",
        roles=frozenset({"reader"}),
        text="Company B office hours are Monday to Friday, 8 AM to 4 PM.",
    ),
})


def resource_registry() -> dict[str, Resource]:
    """Build gateway permissions from the same document records."""
    return {
        document_id: Resource(
            tenant=record.tenant,
            roles=record.roles,
        )
        for document_id, record in _DOCUMENTS.items()
    }


def fetch_document(document_id: str, principal: Principal) -> Document:
    """Return stored text only when the requester has permission."""
    record = _DOCUMENTS.get(document_id)

    if (
        record is None
        or record.tenant != principal.tenant
        or principal.role not in record.roles
    ):
        # Same error for missing and forbidden documents.
        raise PermissionError("Document unavailable or access denied.")

    return Document(
        id=document_id,
        text=record.text,
    )