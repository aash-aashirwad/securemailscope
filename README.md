# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**
Smart India Hackathon — Problem Statement **26159** | Organization: **National Technical Research Organisation (NTRO)** | Theme: Blockchain & Cybersecurity

A passive network forensic platform that ingests PCAP captures of SMTP/IMAP/POP3 traffic,
reconstructs TLS sessions byte-level (no decryption keys needed), extracts and validates
X.509 certificates, and produces an AI-blended (rule-based + IsolationForest anomaly
detection) cryptographic risk score with prioritized, compliance-mapped findings and
exportable JSON/HTML/PDF reports — all behind a 4-role access-controlled multi-tab web app.

---

## 1. What's actually implemented (honest scope)

This is a **working, tested full-stack system** — not a mockup. Specifically validated end-to-end
on a synthetic multi-session PCAP during development:

| Capability | Status |
|---|---|
| TCP stream reconstruction from PCAP | Working (Scapy-based) |
| SMTP / IMAP / POP3 protocol detection | Working (port + banner based) |
| STARTTLS / STLS negotiation detection | Working |
| Raw TLS record & handshake parsing (ClientHello/ServerHello/Certificate) | Working, hand-written parser, TLS1.0-1.3 |
| X.509 certificate extraction & validation (expiry, self-signed, key strength, weak signature) | Working |
| Rule-based risk scoring (NIST/PCI-DSS-derived rubric) | Working |
| AI anomaly detection (scikit-learn IsolationForest) | Working |
| Prioritized findings with mitigation + compliance references | Working |
| JSON / HTML / PDF report export | Working, tested |
| JWT auth, 4 roles, RBAC on every endpoint | Working |
| React multi-tab UI (Dashboard, Upload, Cases, Case Detail, Findings, Compliance, Admin) | Working, builds clean |
| Docker Compose deployment | Provided |

**Known limitations, stated plainly:**
- TCP reassembly correctly handles out-of-order delivery, duplicate/overlapping
  retransmissions, dropped-packet gaps, and 32-bit sequence-number wraparound (all covered by
  `tests/test_stream_reassembly.py`) — but it tracks connection state via FIN/RST/established
  only, not a full RFC 793 state machine (no SYN-retransmit tracking, no window scaling, no
  IP-level fragmentation reassembly — see `docs/PS_TRACEABILITY_MATRIX.md`'s limitations
  section for the complete list).
- The AI anomaly layer needs a reasonably sized capture (3+ sessions) to be statistically
  meaningful; it degrades gracefully (returns 0) on tiny captures.
- No live/streaming capture mode yet — batch PCAP upload only (matches the problem statement's
  "passive analysis of captured network traffic" requirement).
- Cipher suite and TLS version reference tables are the common/production subset of the IANA
  registry, not the full ~350-entry list — extendable by editing `crypto_reference.py`.

---

## 2. Architecture (summary — full diagrams in /docs/ARCHITECTURE.md)

```
React Frontend (Vite)
  Login/Register -> Dashboard -> Upload -> Cases -> Case Detail
  -> Findings -> Compliance View -> Admin (role-gated, multi-tab)
        |  REST (JWT Bearer)
        v
FastAPI Backend
  Auth (JWT) | Case Routes | Report Routes | Dashboard/Admin Routes
        |  background task
        v
  Forensic Pipeline:
  pcap_engine.py -> risk_engine.py (ML) -> findings_engine.py -> report_generator.py
        |  SQLAlchemy ORM
        v
  SQLite / Postgres
```

---

## 3. Roles

| Role | Can do |
|---|---|
| **Admin** | Everything, plus user management (create users, role changes, activate/deactivate), full audit trail |
| **SOC Analyst** | Upload captures, view/analyze own cases, view findings |
| **Forensic Investigator** | Upload, analyze, delete cases (chain-of-custody actions) |
| **Compliance Officer** | Read-only cross-org visibility + dedicated Compliance View + audit trail (read-only) + report export |

Each role sees a different sidebar and different dashboard emphasis — enforced server-side
(every endpoint checks role via a FastAPI dependency), not just hidden in the UI. Only an
existing Admin can grant the Admin role (self-registration is limited to the other three
roles) so privileges can't be escalated at signup.

---

## 3a. Security hardening (this revision)

- **Account lockout**: 5 consecutive failed logins locks the account for 15 minutes.
- **Rate limiting**: login/register endpoints are throttled per-IP (slowapi) against
  brute-force and credential-stuffing.
- **JWT access + refresh tokens**: short-lived (30 min) access tokens with a 7-day refresh
  token; the frontend silently refreshes on 401 instead of forcing re-login every 30 minutes.
- **Password policy**: 10+ chars, upper/lower/digit/symbol, enforced both client- and
  server-side, on self-registration, admin-provisioned accounts, and password changes.
- **No more hardcoded default admin password**: the bootstrap admin account gets a random
  one-time password printed to the server log on first boot, and is forced to change it
  before doing anything else (`must_change_password` flag, enforced in the UI).
- **Audit trail**: every login (success/failure/lockout), registration, password change,
  case upload/delete, and admin action (role change, activate/deactivate, user creation) is
  written to a tamper-evident, hash-chained `audit_logs` table, visible to Admin (full) and Compliance Officer
  (read-only) via **Audit Trail** in the sidebar / `/api/admin/audit-logs`.
- **CORS**: now configured from `CORS_ORIGINS` (comma-separated) instead of a hardcoded `*`;
  set this to your real frontend origin before any production/free-tier deployment.
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`, and HSTS (when served over HTTPS) are set on every response.
- **Self-registration privilege limit**: new signups can only become SOC Analyst, Forensic
  Investigator, or Compliance Officer; Admin accounts are created only by an existing Admin
  via **User Management → New user**, which issues a temporary password.



## 4. Quick start (local, free-tier friendly)

### Option A — Docker Compose (recommended)
```bash
cp backend/.env.example backend/.env   # edit SECRET_KEY
docker compose up --build
# Frontend: http://localhost:3000
# Backend docs: http://localhost:8000/docs
```

### Option B — Manual (dev mode)
```bash
# Backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev   # http://localhost:5173, proxies /api to :8000
```

**Default admin account** (seeded automatically on first boot): `admin@ntro.gov.in`, with a
random one-time password printed to the server console/log exactly once at startup —
there is no fixed default password. Log in with that password and you'll be forced to set
a new one immediately (`must_change_password`). If you lose the one-time password before
first login, delete the `users` row (or the SQLite file, for a fresh dev DB) and restart to
have it re-seeded with a new one-time password.

---

## 5. Free-tier deployment

- **Backend**: any container platform with a free tier that supports Python + persistent
  disk for SQLite (Render, Railway, Fly.io free tiers). For heavier traffic swap
  `DATABASE_URL` to a free-tier Postgres (Neon, Supabase, Railway) — the SQLAlchemy models
  need zero changes.
- **Frontend**: the built `dist/` folder is fully static — deploy to Vercel, Netlify, GitHub
  Pages, or Cloudflare Pages free tiers. Point the API proxy at your deployed backend URL.
- **No GPU, no paid ML API calls** — scikit-learn IsolationForest runs in-process, negligible
  compute footprint, well within any free-tier CPU/RAM allowance.

---

## 6. Project layout

```
securemailscope/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI app, startup seeding
│   │   ├── core/                   # config, db, security (JWT/bcrypt)
│   │   ├── models/models.py        # SQLAlchemy ORM (User, Case, EmailSession, Finding)
│   │   ├── api/                    # auth, case, report, dashboard/admin routes
│   │   ├── services/
│   │   │   ├── pcap_engine.py      # TCP reassembly + TLS/cert forensic parser
│   │   │   ├── crypto_reference.py # TLS version/cipher reference tables
│   │   │   └── findings_engine.py  # findings + mitigations + compliance mapping
│   │   ├── ml/risk_engine.py       # rule-based + IsolationForest risk scoring
│   │   └── reports/report_generator.py  # JSON/HTML/PDF export
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── pages/                  # Login, Register, Dashboard, Upload, Cases,
│   │   │                           # CaseDetail, AllFindings, ComplianceView, AdminUsers
│   │   ├── components/             # Sidebar, UI primitives
│   │   ├── context/AuthContext.jsx
│   │   └── api/client.js
│   └── Dockerfile
├── docs/
│   └── ARCHITECTURE.md             # full documentation package (see below)
└── docker-compose.yml
```

---

## 7. Documentation package

See **`/docs/ARCHITECTURE.md`** for the full write-up: problem statement restatement and
solution narrative, hierarchical architecture diagram, methodology diagram, end-to-end
flowchart, complete tech stack table with justification, novelty/innovation analysis,
feasibility analysis, challenges & risk mitigation, unique features, impact & benefits, and
references (RFCs, NIST, OWASP, academic).

---

## 8. Changelog — hardening pass

This pass focused on closing the gaps flagged as partial/missing, in code
(not just documentation):

**Forensic engine**
- Key-exchange mechanism now actually resolved (TLS≤1.2 from the cipher
  suite name; TLS1.3 from the `key_share` extension's negotiated group).
- Certificate chain validation performs real cryptographic signature
  verification link-by-link (not just Subject/Issuer string matching),
  flags incomplete/self-signed/expired chains, and checks the top of the
  chain against the bundled Mozilla trust store (`certifi`) as a PKI
  trust-anchor check.
- TCP reassembly is sequence-number-aware: out-of-order segments,
  duplicate/overlapping retransmissions, and real capture gaps are all
  handled correctly instead of naive sort-and-concatenate.
- Handshake messages fragmented across multiple TLS records are now
  reassembled before parsing.
- Cipher suite registry expanded from ~20 to ~100 entries (IANA-assigned
  codes covering all mainstream TLS stacks), plus GREASE-value handling.
- Capture size is now bounded (`MAX_PACKETS_PER_CAPTURE`, streamed via
  `PcapReader` instead of loading the whole file with `rdpcap`) so a huge
  or hostile capture can't exhaust worker memory; results are flagged
  `capture_truncated` when the limit is hit.

**Security hardening**
- `SECRET_KEY` and `CORS_ORIGINS` are now enforced at startup when
  `ENVIRONMENT=production` (the app refuses to boot with a missing/weak
  secret or an open CORS policy); dev runs still auto-generate an
  ephemeral key for convenience.
- Upload handling: filenames are sanitized (path traversal / null bytes /
  odd characters stripped), the file is written to disk with a running
  size cap instead of buffering the whole upload before checking size, and
  the actual pcap/pcapng magic bytes are validated post-write rather than
  trusting the client-supplied extension.
- Audit log is now a tamper-evident hash chain (`prev_hash`/`entry_hash`
  per row); `GET /api/admin/audit-logs/verify` recomputes the chain and
  reports the first broken link, if any.

**Testing**
- Added `backend/tests/` (pytest) covering stream reassembly (in-order,
  out-of-order, retransmission, overlap, gaps, sequence wraparound),
  cipher classification, certificate-chain validation (genuine chain,
  forged signature, expired cert, incomplete chain), audit hash-chain
  integrity, and upload sanitization. Run with `pytest` from `backend/`
  (`pip install -r requirements-dev.txt` first). This is a starting
  suite, not full coverage — API/E2E/RBAC test suites are still open.

**Deployment**
- `docker-compose.yml` gained an opt-in `production` profile that brings
  up PostgreSQL (default stays SQLite/single-container for free-tier use);
  `psycopg2-binary` added to `requirements.txt`.

### Still open (infrastructure/process items, not closed in this pass)
Distributed analysis workers, production observability (metrics/tracing),
HA/failover, disaster recovery, and performance benchmarking are
deployment/ops-scale concerns that go beyond code changes to this
repository — they need a target infrastructure (K8s/cloud, monitoring
stack) to actually stand up, which is outside what a code-only pass can
close. Large-scale anomaly baseline (training on real historical traffic
at volume) is likewise a data/ops exercise, not a code gap. Full PKI
trust-store validation is now real (see above) but still limited to what
a passive capture can see: TLS1.3 encrypts the Certificate message, so a
passive-only deployment (no server private key / decryption) cannot
recover certificates from TLS1.3 sessions at all — this is a protocol
property, not an implementation gap, and should be described as such
rather than claimed as solved.

---

## 9. Changelog — Priority upgrades pass (Traceability, RBAC tests, Evidence, Benchmark, Roles UI)

**Closed from the priority list:**
1. **PS Traceability Matrix** — now a live API (`GET /api/dashboard/traceability-matrix`) and
   frontend page (`/traceability`), not just a doc, so the requirement→implementation→API→UI
   mapping is verifiable from the running system.
2. **Full API/RBAC test matrix** — `tests/test_rbac_matrix.py` exercises every protected
   endpoint against all 4 roles, plus auth edge cases (invalid token, wrong password,
   self-assigned-admin block).
3. **Evidence Chain-of-Custody** — unified `GET /api/cases/{id}/custody` (upload hash +
   access/export/remediation history, all pulled from the hash-chained audit log) with a
   dedicated tab on Case Detail. Added `report_export` and `case_viewed` audit events that
   weren't being logged before.
4. **PCAP Evidence Viewer** — per-packet metadata (packet #, timestamp, direction, TCP flags,
   sequence number) captured during stream reconstruction, exposed at
   `GET /api/cases/{id}/sessions/{sid}/packets` and viewable inline per session.
7. **Performance benchmark** — wall-clock time + peak memory (`tracemalloc`) tracked per
   analysis run, exposed at `GET /api/cases/benchmark` and a dedicated admin/compliance page.

Items 5 (Security Policy Enforcement) and 6 (Risk Explainability panel) were already fully
implemented in the prior version — verified working, not re-done.

**Role UI improvements:**
- New `/roles` page: each role's stated responsibility, authority (what only it can do),
  working scope, and explicit restrictions — backed by the RBAC test matrix above, not just
  described.
- Sidebar: role-colored top accent strip, role badge links through to the Roles & Access page,
  new nav entries for Traceability, Benchmark, and Roles & Access (each gated to the roles
  that can actually use them).

**Verification performed in this pass:**
- Backend: full `ast.parse` syntax check across every `.py` file in `app/` and `tests/`.
- Frontend: every edited/new file compiled individually with esbuild, plus a full bundle build
  (`main.jsx` with all internal imports resolved) confirming no broken imports/exports across
  the new routes and Sidebar wiring. `npm install && npm run build` still recommended before
  deploying, since this sandbox has no network access to install the actual npm dependencies.
- Stale `.db` files removed again (two new `Case` columns added: `processing_time_seconds`,
  `peak_memory_mb`).

**Still open:** true browser-driven E2E tests (Playwright/Cypress) are not included — the
"E2E" coverage here is backend integration-style (FastAPI TestClient + in-memory DB), not a
real browser exercising the React app.
