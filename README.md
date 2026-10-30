# SENTINEL-AI security operations dashboard

A frontend-only administrator console following the supplied workflow reference. It provides one aggregate admin workspace and separate dashboards for Banking, Healthcare, Education, Government, Corporate, Manufacturing, Retail, and Public Services.

## Open

Open `index.html` in a modern browser or use the local preview at `http://localhost:4173`.

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

## Demo limitations

The account directory, password check, and CAPTCHA run entirely in browser code and are for demonstration only; they are not secure authentication controls. No government or organization connector is configured. The source data and agent results are synthetic; detection uses browser-side rules rather than AI models. File hashes are computed locally in the browser. Response execution changes only the demo page state and does not affect external systems. Live connectors need authorized API documentation, a sandbox, and a secure backend.
