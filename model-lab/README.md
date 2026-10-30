# SENTINEL-AI synthetic model lab

This folder creates synthetic security-event data for Banking, Healthcare, Education, Government, Corporate, Manufacturing, Retail, and Public Services. It trains one shared multi-domain Random Forest and evaluates it on a held-out portion of the generated records.

## Run it

From `Deepfake-Tracker`:

```powershell
node .\model-lab\train.mjs
```

The script has no third-party dependencies. It uses a fixed seed (`20261030`) so the generated data, split, model, and evaluation can be reproduced.

## Output files

- `data/all_domains.csv`: all 6,400 generated records, with an explicit `train` or `test` split.
- `data/by_domain/*.csv`: one CSV per domain, with the same split markers.
- `artifacts/model.json`: trained Random Forest and its feature definitions.
- `artifacts/evaluation.json`: overall and per-domain holdout metrics.

## Local multi-domain service portal

The separate CivicShield portal in `portal/` is a fictional customer-service demonstration for eight domains. It retains administrator sign-in and a CAPTCHA, then shows four sample people in the selected domain. Banking includes a demo account-number and sample-code lookup that reveals a fictional balance. Healthcare, education, commerce, citizen services, business services, cyber-awareness learning, and IT help-desk portals show corresponding sample service details.

The portal interface does not display threat alerts, agent investigations, security event tables, or a security test lab. Each normal demo user receives only their own profile and one domain-specific text document from the backend; private files are not placed in the public frontend. The document has a stored reference SHA-256 hash, and its authenticated integrity endpoint reports whether the current file matches. Banking checks the signed-in user's account reference and sample code on the server before returning that user's sample balance.

## Living Off the Land demo in the main SENTINEL dashboard

The main `Deepfake-Tracker/index.html` dashboard adds the LotL monitor, user baselines, maintenance schedules, and response center. It shares the local FastAPI service and SQLite database with the service portal. The Python package in `portal/backend/lotl/` separates event validation, behavior scoring, the five agents, orchestration, scenarios, and persistence. Existing dashboard sections continue to provide incident investigation, multi-agent monitoring, SHA-256 comparison, settings, and audit reports.

The monitor accepts CSV activity fields such as timestamp, username, role, IP, device, process category, action, resource, permission level, data volume, session, and change reference. It ignores unrelated fields. Use only synthetic or explicitly authorized logs; do not upload passwords, tokens, or secrets. Four built-in scenarios demonstrate normal work, night activity, gradual deviation, and approved maintenance. A response approval records a safe simulation only; it never changes an account or system. Risk values are explainable demo heuristics, not validated probabilities.

For suspicious LotL incidents, the Verification Agent lists document paths found in the activity records. CSV imports may use `document_path` or `file_path` for the resource and may include `document_hash_before` and `document_hash_after` (64-character SHA-256 hex values) to compare content. Without a document path, the affected document is reported as unknown; without both hashes, integrity is reported as not checked. The agent does not read or alter files, and path identification is only as reliable as the submitted logs.

In a first terminal, create the backend environment once, install its existing dependencies, and start the API:

```powershell
cd .\model-lab\portal\backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

In a second terminal, serve the main dashboard:

```powershell
cd .\Deepfake-Tracker
py -m http.server 4173 --bind 127.0.0.1
```

Alternatively, use your existing local static preview at `http://127.0.0.1:4173/`. The service portal at port 4174 is separate and does not need to run for LotL scenarios.

Run the focused engine and workflow checks from `model-lab/portal/backend`:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Failed passwords, unknown user IDs, and failed CAPTCHA checks are forwarded to the local SENTINEL receiver at `127.0.0.1:8000`. Three failures for a known account, or three unknown IDs from one source in the same domain, within five minutes create one **Unusual login** alert with a timeline, involved user when identifiable, risk explanation, document hash check, and response recommendations. An unrecognized user ID produces a domain-level alert because no account owner can be identified. A reviewer can approve **Require immediate password change** in the SENTINEL notification panel. Approval revokes the user's current sessions and requires a new password at their next sign-in. All sample records are fictional; do not enter real personal, health, government, or financial data. The portal does not connect to real organizations or government services.

From `Deepfake-Tracker`, create the Python environment and install backend dependencies:

```powershell
cd .\model-lab\portal\backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

In a second terminal, build and serve the frontend:

```powershell
cd .\model-lab\portal\client
npm install
npm run build
npm run serve
```

Open the service portal at `http://127.0.0.1:4174/`. The SENTINEL security dashboard runs separately at `http://127.0.0.1:4173/`. Each service has four normal sample user IDs: `business_user_1001`–`business_user_1004`, `bank_user_1001`–`bank_user_1004`, `health_user_1001`–`health_user_1004`, `education_user_1001`–`education_user_1004`, `shop_user_1001`–`shop_user_1004`, `cyber_user_1001`–`cyber_user_1004`, `citizen_user_1001`–`citizen_user_1004`, and `it_user_1001`–`it_user_1004`. The shared sample password is `ServiceDemo-2026!`; sign-in also requires the generated CAPTCHA.

The production bundle is served by `npm run serve`. API and CSV routes are proxied by the local portal server to FastAPI.

Each row includes a synthetic scenario label for analysis, but the model does not use that label, event ID, time, split marker, or target when training. It uses event indicators and a one-hot domain representation. The held-out rows are stratified by domain and target class.

## Features and target

Inputs include failed logins, successful access after failures, unfamiliar region, after-hours activity, restricted access attempts, request-rate ratio, malware alerts, document hash mismatch, sensitive-resource access, privilege changes, unique source IPs, source reputation, managed-device status, five-minute event volume, and domain.

The `suspicious` target is assigned by the synthetic scenario generator. Scenarios include credential abuse, unauthorized access, excessive requests, malware activity, document tampering, privilege misuse, and data exfiltration. Benign records also contain occasional unusual-but-legitimate events to create overlap.

## Important limits

This experiment measures performance only on data produced by this generator. The generator defines the label and many input patterns, so high holdout scores can reflect that shared design. They do not establish real-world accuracy, production readiness, or generalization to unseen attack behavior. Before operational use, evaluate on independently collected and authorized data, review class imbalance and false negatives with domain experts, calibrate alert thresholds, and test model and data drift. This is a prototype classifier; it does not connect to live systems or take response actions.
