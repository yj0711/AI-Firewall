
import os
import re
import json
import secrets
import logging
import sqlite3
from audit_store import ApprovalAlreadyUsed, ApprovalRevoked
import unicodedata
import math
from collections import deque
from threading import Lock
from time import monotonic, time
from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, Depends, HTTPException
from starlette.requests import Request as HTTPRequest
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field

log = logging.getLogger("firewall.audit")
MAX_TEXT = 12000


class Document(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(min_length=1, max_length=100)
    text: str = Field(max_length=MAX_TEXT)


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=MAX_TEXT)
    documents: list[Document] = Field(default_factory=list, max_length=8)


class StoredDocumentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=MAX_TEXT)
    document_ids: list[str] = Field(min_length=1, max_length=8)


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    resource_id: str = Field(min_length=1, max_length=100)
    query: str = Field(min_length=1, max_length=200)


class ShareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    approval_id: str = Field(min_length=1, max_length=100)
    resource_id: str = Field(min_length=1, max_length=100)
    recipient: str = Field(min_length=1, max_length=200)
    task: str = Field(min_length=1, max_length=100)


@dataclass(frozen=True)
class ShareApproval:
    tenant: str
    role: str
    resource_id: str
    recipient: str
    task: str
    expires_at: float


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool: str = Field(min_length=1, max_length=80)
    resource_id: str = Field(min_length=1, max_length=100)


@dataclass(frozen=True)
class Principal:
    tenant: str
    role: str


@dataclass(frozen=True)
class Resource:
    tenant: str
    roles: frozenset[str]


def canonical(text):
    text = unicodedata.normalize("NFKC", text).lower()
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


RULES = {
    "instruction_override": r"\b(?:ignore|disregard)\s+(?:(?:all|the|your)\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts)\b",
    "prompt_disclosure": r"\b(?:reveal|print|show)\s+(?:(?:me|your|the)\s+)*(?:system\s+prompt|hidden\s+instructions)\b",
    "safety_override": r"\b(?:disable|bypass)\s+(?:(?:all|your|the)\s+)*(?:safety|security|content\s+filters)\b",
    "secret_request": r"\b(?:send|leak|upload|reveal)\b.{0,100}\b(?:api\s*keys|passwords|credentials|company\s+files)\b",
}
SECRET_PATTERNS = [r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", r"\bAKIA[A-Z0-9]{16}\b", r"\bghp_[A-Za-z0-9]{36}\b"]


def signals(text):
    plain = canonical(text)
    alternate = plain.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "@": "a", "5": "s"}))
    hits = [name for name, pattern in RULES.items() if re.search(pattern, plain) or re.search(pattern, alternate)]
    # Bounded signature for character-spaced instruction overrides.
    compact = re.sub(r"[^a-z]", "", alternate)
    if any(p in compact for p in ("ignorepreviousinstructions", "ignoreallpreviousinstructions", "revealyoursystemprompt")):
        hits.append("obfuscated_instruction")
    if any(re.search(p, text) for p in SECRET_PATTERNS):
        hits.append("credential_pattern")
    return sorted(set(hits))


class Engine:
    def __init__(self, resources=None, classifier=None):
        self.resources = resources or {}
        self.classifier = classifier

    def authorized(self, principal, resource_id):
        resource = self.resources.get(resource_id)
        return bool(resource and resource.tenant == principal.tenant and principal.role in resource.roles)

    def inspect(self, request, principal):
        if sum(len(d.text) for d in request.documents) + len(request.text) > 24000:
            return "BLOCK", ["aggregate_size_limit"]
        # Check permission BEFORE examining document content.
        if any(not self.authorized(principal, d.id) for d in request.documents):
            return "BLOCK", ["document_access_denied"]
        texts = [request.text] + [d.text for d in request.documents]
        found = sorted({h for text in texts for h in signals(text)})
        if found:
            return "BLOCK", found
        if self.classifier is None:
            return "REVIEW", ["semantic_detector_not_configured"]
        for text in texts:
            try:
                verdict = self.classifier(text)
            except Exception:
                return "REVIEW", ["semantic_detector_error"]
            if verdict == "INJECTION":
                return "BLOCK", ["semantic_injection"]
            if verdict != "SAFE":
                return "REVIEW", ["semantic_detector_unknown"]
        return "ALLOW", ["checks_passed"]

    def tool(self, request, principal):
        # Reference policy: only read-only knowledge search is eligible.
        if request.tool != "knowledge.search":
            return "BLOCK", ["tool_not_authorized"]
        if not self.authorized(principal, request.resource_id):
            return "BLOCK", ["resource_access_denied"]
        return "ALLOW", ["read_only_tool_authorized"]


def create_app(engine=None, identities=None, document_loader=None, audit_writer=None, *, failed_signin_limit=5, share_approvals=None):
    approvals = dict(share_approvals or {})
    redeemed = set()
    redemption_lock = Lock()
    engine = engine or Engine()
    identities = identities or {}
    app = FastAPI(title="AI Firewall reference gateway", docs_url=None, redoc_url=None, openapi_url=None)
    bearer = HTTPBearer(auto_error=False)

    class BodyLimit:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                return await self.app(scope, receive, send)
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > 100000:
                    from starlette.responses import JSONResponse
                    return await JSONResponse({"detail": "request too large"}, status_code=413)(scope, receive, send)
                if not message.get("more_body", False):
                    break
            delivered = False
            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()
            await self.app(scope, replay, send)
    app.add_middleware(BodyLimit)

    # Outermost middleware: reserve capacity before buffering the request body.
    from threading import BoundedSemaphore

    class CapacityLimit:
        def __init__(self, app):
            self.app = app
            self.slots = BoundedSemaphore(4)

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                return await self.app(scope, receive, send)
            if not self.slots.acquire(blocking=False):
                response = JSONResponse({"detail": "server busy"}, status_code=503,
                                        headers={"Retry-After": "1"})
                return await response(scope, receive, send)
            try:
                return await self.app(scope, receive, send)
            finally:
                self.slots.release()

    app.add_middleware(CapacityLimit)

    # Each configured badge has a bounded history of accepted requests.
    recent_requests = {token: deque() for token in identities}
    rate_lock = Lock()

    def check_rate(token):
        with rate_lock:
            now = monotonic()
            history = recent_requests[token]
            while history and now - history[0] >= 60:
                history.popleft()
            if len(history) >= 30:
                retry = max(1, math.ceil(60 - (now - history[0])))
                raise HTTPException(429, "badge rate limit reached",
                                    headers={"Retry-After": str(retry)})
            history.append(now)

    if type(failed_signin_limit) is not int or failed_signin_limit < 1:
        raise ValueError("failed_signin_limit must be a positive integer")
    failed_sources = {}
    failure_lock = Lock()

    def identity(request: HTTPRequest, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if credentials:
            for token, principal in identities.items():
                if secrets.compare_digest(credentials.credentials.encode("utf-8"), token.encode("utf-8")):
                    check_rate(token)
                    return principal
        reason = "invalid_credentials" if "authorization" in request.headers else "missing_credentials"
        source = request.client.host if request.client else "unknown"
        with failure_lock:
            now = monotonic()
            count, deadline = failed_sources.get(source, (0, now + 60))
            if now >= deadline:
                count, deadline = 0, now + 60
            if count >= failed_signin_limit:
                raise HTTPException(429, "sign-in cooldown",
                                    headers={"Retry-After": str(max(1, math.ceil(deadline - now)))})
            if source not in failed_sources and len(failed_sources) >= 4096:
                for peer in [peer for peer, (_, end) in failed_sources.items() if end <= now]:
                    del failed_sources[peer]
                if len(failed_sources) >= 4096:
                    raise HTTPException(503, "sign-in capacity reached", headers={"Retry-After": "1"})
            count += 1
            if count == failed_signin_limit:
                deadline = now + 60
            failed_sources[source] = count, deadline
        reasons = [reason]
        if count == failed_signin_limit:
            reasons.append("signin_cooldown_started")
        receipt = result(None, ("BLOCK", reasons))
        raise HTTPException(
            401, "authentication required",
            headers={"X-Request-ID": receipt["request_id"], "WWW-Authenticate": "Bearer"},
        )

    def result(principal, outcome, *, approval_id=None):
        tenant = principal.tenant if principal is not None else "unauthenticated"
        decision, reasons = outcome
        request_id = str(uuid4())
        policy_version = "reference-1"
        if audit_writer is not None:
            try:
                audit_writer(
                    request_id=request_id,
                    tenant=tenant,
                    decision=decision,
                    reasons=reasons,
                    policy_version=policy_version,
                    **({"approval_id": approval_id} if approval_id is not None else {}),
                )
            except (OSError, sqlite3.Error):
                log.error("Audit write failed for request %s", request_id)
                raise HTTPException(503, "audit storage unavailable") from None
        # Do not log raw prompts, documents, credentials, or model outputs.
        log.info(json.dumps(dict(request_id=request_id, tenant=tenant, decision=decision, reasons=reasons)))
        return dict(request_id=request_id, policy_version=policy_version, decision=decision, reasons=reasons)

    @app.post("/v1/inspect")
    def inspect(request: Request, principal=Depends(identity)):
        if request.documents:
            return result(
                principal,
                ("BLOCK", ["use_stored_document_endpoint"]),
            )

        return result(
            principal,
            engine.inspect(request, principal),
        )
    @app.post("/v1/documents/inspect")
    def inspect_stored_documents(
        request: StoredDocumentRequest,
        principal: Principal = Depends(identity),
    ):
        # Missing configuration must never become permission.
        if document_loader is None:
            return result(
                principal,
                ("REVIEW", ["document_store_not_configured"]),
            )

        # Validate identifiers before asking the document store.
        if any(
            not document_id.strip() or len(document_id) > 100
            for document_id in request.document_ids
        ):
            raise HTTPException(422, "invalid document identifier")

        if len(set(request.document_ids)) != len(request.document_ids):
            raise HTTPException(422, "duplicate document identifiers")

        try:
            documents = [
                document_loader(document_id, principal)
                for document_id in request.document_ids
            ]
        except PermissionError:
            return result(
                principal,
                ("BLOCK", ["document_access_denied"]),
            )
        except Exception:
            # Do not expose internal errors or document contents.
            return result(
                principal,
                ("REVIEW", ["document_store_error"]),
            )

        inspection = Request(
            text=request.text,
            documents=documents,
        )
        return result(
            principal,
            engine.inspect(inspection, principal),
        )


    @app.post("/v1/tools/authorize")
    def tool(request: ToolRequest, principal=Depends(identity)):
        return result(principal, engine.tool(request, principal))

    @app.post("/v1/tools/knowledge/search")
    def search(request: SearchRequest, principal=Depends(identity)):
        query = request.query.strip()
        if not query:
            raise HTTPException(422, "empty search query")
        action = ToolRequest(tool="knowledge.search", resource_id=request.resource_id)
        permission = engine.tool(action, principal)
        if permission[0] != "ALLOW":
            return result(principal, permission)
        if document_loader is None:
            return result(principal, ("REVIEW", ["document_store_not_configured"]))
        try:
            document = document_loader(request.resource_id, principal)
        except PermissionError:
            return result(principal, ("BLOCK", ["document_access_denied"]))
        except Exception:
            return result(principal, ("REVIEW", ["document_store_error"]))
        if not isinstance(document, Document) or document.id != request.resource_id:
            return result(principal, ("REVIEW", ["document_store_mismatch"]))
        inspection = engine.inspect(Request(text=query, documents=[document]), principal)
        if inspection[0] != "ALLOW":
            return result(principal, inspection)
        term = query.casefold()
        matches = [line for line in document.text.splitlines() if term in line.casefold()][:5]
        receipt = result(principal, ("ALLOW", ["knowledge_search_completed"]))
        return {**receipt, "matches": matches}

    @app.post("/v1/approvals/{approval_id}/revoke")
    def revoke_approval(approval_id: str, principal=Depends(identity)):
        slip = approvals.get(approval_id)
        if principal.role != "manager" or slip is None or slip.tenant != principal.tenant:
            return result(principal, ("BLOCK", ["revocation_not_authorized"]))
        if audit_writer is None:
            raise HTTPException(503, "audit storage unavailable")
        try:
            return result(principal, ("ALLOW", ["share_approval_revoked"]), approval_id=approval_id)
        except ApprovalRevoked:
            return result(principal, ("BLOCK", ["share_approval_revoked"]))
        except ApprovalAlreadyUsed:
            return result(principal, ("BLOCK", ["share_approval_used"]))

    @app.post("/v1/tools/share/simulate")
    def simulate_share(request: ShareRequest, principal=Depends(identity)):
        slip = approvals.get(request.approval_id)
        if not engine.authorized(principal, request.resource_id):
            return result(principal, ("BLOCK", ["resource_access_denied"]))
        if (slip is None or slip.tenant != principal.tenant or slip.role != principal.role
                or slip.resource_id != request.resource_id or slip.recipient != request.recipient
                or slip.task != request.task):
            return result(principal, ("BLOCK", ["share_approval_mismatch"]))
        with redemption_lock:
            if time() >= slip.expires_at:
                return result(principal, ("BLOCK", ["share_approval_expired"]))
            if request.approval_id in redeemed:
                return result(principal, ("BLOCK", ["share_approval_used"]))
            try:
                receipt = result(principal, ("ALLOW", ["share_simulated"]), approval_id=request.approval_id)
            except ApprovalRevoked:
                return result(principal, ("BLOCK", ["share_approval_revoked"]))
            except ApprovalAlreadyUsed:
                return result(principal, ("BLOCK", ["share_approval_used"]))
            redeemed.add(request.approval_id)
        return {**receipt, "simulated_share": request.model_dump()}

    @app.post("/v1/output/inspect")
    def output(request: Request, principal=Depends(identity)):
        if request.documents:
            raise HTTPException(422, "output endpoint accepts text only")
        found = signals(request.text)
        return result(principal, ("BLOCK", found) if found else ("REVIEW", ["output_policy_review_required"]))

    # Avoid echoing potentially sensitive inputs in validation failures.
    from fastapi.exceptions import RequestValidationError
    from starlette.responses import JSONResponse
    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"detail": "invalid request"}, status_code=422)

    return app


# Local demo configuration. A server-side identity, never a tenant supplied in JSON.
token = os.environ.get("FIREWALL_API_KEY")
app = create_app(identities={token: Principal("demo", "reader")} if token else {})
