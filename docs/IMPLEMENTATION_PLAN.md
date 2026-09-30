# Implementation Plan — SecureMailScope (PS 26159)

## 1. Objective

Passive, offline analysis of packet captures (.pcap) containing SMTP/IMAP/POP3
traffic to assess the cryptographic security posture of email transport —
STARTTLS/implicit TLS usage, negotiated TLS version and cipher suite,
certificate validity and chain trust, forward secrecy — and turn that into
prioritized, explainable findings with role-appropriate reporting. See
`docs/PS_TRACEABILITY_MATRIX.md` for the outcome-by-outcome mapping to
features/API/UI.

## 2. Architecture at a glance

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  React SPA  │─────▶│  FastAPI backend │─────▶│  SQLite/Postgres │
│  (Vite,     │◀─────│  (JWT auth, RBAC)│◀─────│  (SQLAlchemy)    │
│  Tailwind)  │      └────────┬─────────┘      └──────────────────┘
└─────────────┘               │
                    ┌──────────┴───────────┐
                    │  Analysis pipeline    │
                    │  (background task)    │
                    │  pcap_engine.py       │
                    │   → findings_engine   │
                    │   → risk_engine (ML)  │
                    └───────────────────────┘
```

Full component/data-flow diagrams: `docs/ARCHITECTURE.md`.

## 3. Build phases (what was built, in dependency order)

**Phase 1 — Core analysis engine** (`backend/app/services/pcap_engine.py`)
- TCP stream reconstruction from raw pcap (seq-aware reorder/dedup/gap
  tracking), STARTTLS command/response detection, TLS record + handshake
  parsing (ClientHello/ServerHello/Certificate), X.509 parsing.
- Rationale for building this first: everything downstream (findings, risk
  scoring, reporting) is a transformation of this engine's output — it has
  to be correct before anything built on top of it is meaningful.

**Phase 2 — Findings & risk scoring**
- `findings_engine.py`: rule-based findings against a real IANA cipher
  registry and the Mozilla root store (`crypto_reference.py`).
- `risk_engine.py`: hybrid scoring — rule-based (70%) blended with an
  IsolationForest anomaly detector (30%) — with per-reason point weights
  and a top-contributing-feature explanation for anomalies, so a score is
  never just an opaque number.

**Phase 3 — Persistence & API**
- SQLAlchemy models (`models.py`), FastAPI routers for cases/sessions/
  findings/reports, background-task analysis so upload returns immediately
  and the frontend polls status.

**Phase 4 — Auth & RBAC**
- JWT access+refresh tokens, bcrypt password hashing, account lockout,
  per-IP rate limiting on auth endpoints, 4 roles (Admin / SOC Analyst /
  Forensic Investigator / Compliance Officer) enforced server-side on
  every endpoint (not just hidden in the UI) — verified by
  `tests/test_rbac_matrix.py`, which asserts every protected route against
  every role, not just the "happy path" role.

**Phase 5 — Forensic/investigator UX**
- Case Detail: session inventory, explainable risk-factor breakdown,
  forensic timeline, certificate fingerprinting + cross-case reuse
  detection, IOC extraction, investigator notes/comments, remediation
  tracking (open→assigned→fixed→verified), evidence chain-of-custody view
  (upload→hash→access→export→remediation history in one place), org-
  configurable cipher/TLS policy engine with automatic compliance
  evaluation, PCAP evidence viewer (which packets support a finding).
- Dashboard: risk trend over time, historical baseline comparison.

**Phase 6 — Production hardening**
- Tamper-evident hash-chained audit log (every login/upload/delete/export/
  admin action), evidence-integrity SHA-256 hashing of uploads embedded in
  every report, fail-fast production config validation (refuses to boot
  without a real `SECRET_KEY`/`CORS_ORIGINS` in production rather than
  silently running insecurely), security headers, CORS lockdown.

**Phase 7 — Deployment packaging** *(this pass)*
- `.gitignore`, `.env.example` at root/backend/frontend, `render.yaml`
  Blueprint, `Dockerfile` fixed to respect PaaS-assigned `$PORT`,
  frontend API base URL made configurable for split-origin deployment
  (was hardcoded to same-origin `/api`, which only works for the
  docker-compose topology) — see `docs/DEPLOYMENT_RENDER.md`.

## 4. Data flow for a single case

1. `POST /api/cases/upload` — file streamed to disk under a size cap;
   SHA-256 computed immediately (evidence integrity); DB row created;
   background task queued; request returns immediately.
2. Background task: `extract_capture_metadata()` (packet count/duration/
   link type) → `analyze_pcap()` (per-session TLS/cert/protocol facts) →
   `score_all_sessions()` (risk score + anomaly + explanations) →
   `generate_findings_for_session()` (against crypto reference + org
   policy) → case-level rollup (grade, counts) written to DB.
3. Frontend polls `GET /api/cases/{id}` until `status: completed`, then
   fetches sessions/findings/timeline/IOCs/comments as the analyst
   navigates tabs.
4. Every access to another user's case, every report export, every
   finding remediation change, is written to the audit log — visible via
   `GET /api/cases/{id}/custody` (this case only) or
   `GET /api/admin/audit-logs` (org-wide, Admin/Compliance Officer).

## 5. Testing strategy

- **Unit** — individual functions (`test_crypto_reference.py`,
  `test_cert_chain_validation.py`, `test_stream_reassembly.py`,
  `test_upgrade3_additions.py`).
- **End-to-end pipeline** — real synthetic pcaps run through the actual
  `analyze_pcap()` entrypoint (`test_pcap_corpus_e2e.py`), not mocked
  intermediate functions, so a change that breaks the pipeline's wiring
  (not just one function's logic) is caught.
- **RBAC/API matrix** — every protected endpoint tested against every
  role via FastAPI's `TestClient`, asserting both the allowed roles get
  200/2xx and every other role gets 403 (`test_rbac_matrix.py`).
- **Tamper-evidence** — audit chain hash verification, including that
  tampering with a field or deleting a row is actually detected
  (`test_audit_chain.py`).
- **Performance** — `scripts/benchmark.py` generates synthetic multi-session
  captures at several sizes and measures actual wall-clock time and peak
  memory of the real `analyze_pcap()` pipeline (not a mock). A smaller
  version of this same benchmark also runs as `pytest -m benchmark`
  (excluded from the default `pytest` run — see `pytest.ini` — since it's
  slower than a unit test should be). Full results, methodology, and
  interpretation: `docs/BENCHMARK_RESULTS.md`.

Run everything: `cd backend && pip install -r requirements-dev.txt && pytest`.

## 6. Deployment strategy

See `docs/DEPLOYMENT_RENDER.md` for the full step-by-step. Summary: GitHub
is the source of truth; Render's Blueprint (`render.yaml`) builds the
backend as a Docker web service (with a persistent disk for SQLite +
uploads) and the frontend as a static site, wired together via two
environment variables (`CORS_ORIGINS` on the backend, `VITE_API_BASE_URL`
on the frontend) that necessarily require one manual step post-first-deploy,
since Render can't assign a service's URL before the service exists.

## 7. Known limitations (stated, not hidden)

See the "Known limitations" section of `docs/PS_TRACEABILITY_MATRIX.md`:
no IP-level fragmentation reassembly, no external threat-intelligence
enrichment (deliberate — this is an offline/passive forensic tool), static
(not admin-editable) compliance-standard mapping, and TCP state tracking
that covers FIN/RST/established but not a full RFC 793 state machine.
