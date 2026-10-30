# SENTINEL-AI security operations dashboard

A local administrator-console prototype following the supplied workflow reference. It provides one aggregate workspace and separate dashboards for Banking, Healthcare, Education, Government, Corporate, Manufacturing, Retail, and Public Services. Its Living Off the Land (LotL) monitor uses the local FastAPI service and SQLite for synthetic activity, scenarios, incidents, schedules, and audit records.

## Open

Run the main dashboard on `http://127.0.0.1:4173` and the local API on `http://127.0.0.1:8000` as described in [`model-lab/README.md`](model-lab/README.md). The LotL monitor needs both services. Other dashboard pages remain available as before.

## Workflow included

- Eight organization-specific administrator sign-in paths with four unique IDs per domain (32 total)
- A generated CAPTCHA is required; a wrong CAPTCHA shows ACCESS DENIED and blocks the demo sign-in
- Shared demo password for all 32 accounts: `Sentinel-Demo-2026!`
- Domain-scoped dashboards and an all-domain admin overview
- Login, system, document, network, security-alert, and application log categories
- CSV log import and synthetic event loading
- Local detection for repeated failed logins, unfamiliar IPs, unauthorized access, high request volume, malware alerts, and document modifications
- Five investigation agents: Detection, Investigation, Risk Assessment, Document Verification, and Response
- Integration Center describing CERT-In, RBI, ABDM, and MeitY roles plus source-system requirements for all eight domains
- Incident timeline, explainable risk score, SHA-256 evidence comparison, and response recommendations
- Action checkboxes, administrator approval, simulated execution, and outcome verification
- Incident report output and audit log download
- LotL behavior checks for timing, resource sensitivity, permissions, device/IP changes, exports, action sequences, maintenance scope, and cross-session deviations
- Four runnable LotL scenarios, persisted synthetic activity, per-user baselines, maintenance scheduling, five-agent findings, business-aware response, human decisions, simulated verification, and audit history

## Synthetic datasets and model

The reproducible dataset generator, eight domain CSVs, trained Random Forest artifact, held-out evaluation, and separate local training portal are in [`model-lab`](model-lab/README.md). Run `node .\model-lab\train.mjs` to regenerate the data/model, then `node .\model-lab\portal\server.mjs` and open `http://localhost:4174/portal/` to browse the portal. The portal is a fictional training site, not a government service.

## Demo limitations

The account directory, password check, and CAPTCHA run entirely in browser code and are for demonstration only; they are not secure authentication controls. The LotL API is a local synthetic-data demo, not an authenticated production service. No government or organization connector is configured. LotL scores are illustrative heuristics, not validated attack probabilities. File hashes are computed locally in the browser. Approved responses are simulations and do not affect external systems. Live connectors need explicit authorization, API documentation, a sandbox, and production security controls.
