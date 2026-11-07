# AI Firewall

AI Firewall is a local Python prototype for two security decisions: whether a piece of text looks like prompt injection, and whether a caller has permission to act on a document. It began as a [Google Colab experiment](ai_firewall_yj.ipynb). The [FastAPI application](local_app.py) now connects the detector to a small document store and a SQLite audit log.

## What the application does

The demo contains two fictional company handbooks. A Company A reader can search its own handbook. Submitting the same query against Company B's handbook should produce a block. The [search endpoint](gateway.py) checks the caller's tenant and role before loading the document, screens the query and retrieved text, then returns matching lines when inspection allows it. Search is a case-insensitive substring match.

The local application also supports simulated document sharing. An approval is scoped to a tenant, role, document, recipient, task, and expiry time. The application records when an approval is used or revoked so that restarting with the same database preserves that decision. A simulated share produces a receipt. No document is sent to the recipient. The [audit store](audit_store.py) records the request ID, timestamp, tenant, decision, reason codes, and policy version.

The [model adapter](model_detector.py) runs the pretrained [Protect AI DeBERTa classifier](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) locally on CPU. This repository integrates the model and adds rules and application-level controls. The adapter returns `UNKNOWN` for inputs that exceed its limits. The notebook's downstream AI response is a placeholder.

## What the evaluation shows

| Evidence | Result in the repository |
| --- | --- |
| Original notebook evaluation | The saved output shows 10 of 10 hand-written injection examples blocked and 10 of 10 benign examples allowed. Several examples closely match the rules. |
| Character-substitution baseline | The capstone write-up reports 6 of 10 detected. In the published notebook the baseline cell stops with `NameError: name 'attacks' is not defined`. The repository does not reproduce that figure from a clean run. |
| Normalization experiment | A later cell displays 10 of 10 detections in each of five conditions using the same ten underlying examples. That cell does not report a benign retest. The change in false positives after normalization remains unknown. |
| Gateway regression tests | The repository includes tests for document permissions, tool decisions, approval expiry, replay and revocation, and audit behavior. The document endpoint tests substitute a mock classifier so permission decisions can be tested independently of model predictions. |

The twenty starter examples are too few to estimate real-world accuracy. The tests also leave open how often an unseen prompt passes the detector or causes an unauthorized outcome in a deployed application. The most informative next evaluation would freeze a held-out set of requests and record three outcomes separately: detector verdict, authorized action completed, and unauthorized document content returned.

## Run the gateway tests

From the repository root in Windows PowerShell, using Python 3.13:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -v
```

These tests use local fixtures. Running the full classifier requires additional dependencies and cached model weights.

## Run the local application with the classifier

From the same directory and environment:

```powershell
.\.venv\Scripts\python.exe -m pip install torch transformers sentencepiece huggingface_hub
.\.venv\Scripts\python.exe -c "from huggingface_hub import snapshot_download; snapshot_download('protectai/deberta-v3-base-prompt-injection-v2')"
$env:FIREWALL_API_KEY = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
.\.venv\Scripts\python.exe -m uvicorn local_app:build_app --factory --host 127.0.0.1
```

The download requires internet access. On startup the adapter reads the model from the local cache. To exercise manager revocation, set `FIREWALL_MANAGER_KEY` to a second independently generated key before starting the server. The SQLite database lives at `%LOCALAPPDATA%\AI-Firewall\audit.sqlite3`.

Open [the local API documentation](http://127.0.0.1:8000/docs), authorize with the reader key from the server's PowerShell session, and try `POST /v1/tools/knowledge/search` with this body:

```json
{"resource_id": "company-a-handbook", "query": "office hours"}
```

The expected result is an allow decision with the matching handbook line. Change only the resource ID to `company-b-handbook`. The expected result is a block without document content. This comparison tests the permission boundary with the same ordinary text on both requests.

## Scope

The application uses demo identities, fictional records, and a local database. It has no external document-sharing integration or downstream generative model. The repository demonstrates specific controls that can be inspected and tested. Production readiness and robustness against adaptive prompt injection remain unevaluated.
