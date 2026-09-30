# Problem Statement Traceability Matrix — PS 26159

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

This maps every outcome named in Problem Statement 26159 to the concrete feature, backend
API, and UI surface that implements it, so coverage can be verified item-by-item rather than
taken on faith. "Evidence" points at the exact file/route/component; where a test exists for
that item, its path is listed under "Tests."

| # | PS Outcome | Feature | API | UI | Tests |
|---|---|---|---|---|---|
| 1 | SMTP identification | Port/banner-based protocol detection | `POST /api/cases/upload` → background analysis | Case Detail → Session Inventory | `tests/test_pcap_corpus_e2e.py` |
| 2 | IMAP identification | Same engine, IMAP ports/banner | " | " | " |
| 3 | POP3 identification | Same engine, POP3 ports/banner | " | " | " |
| 4 | STARTTLS negotiation detection & validation | `analyze_stream_tls()` STARTTLS command/response parsing | `GET /api/cases/{id}/sessions` (`starttls_used`, `starttls_success`) | Session detail → Encryption panel | `tests/test_stream_reassembly.py` (buffer correctness underlying it) |
| 5 | Complete TCP stream reconstruction | `StreamBuffer`: seq-aware reorder, dedup, overlap-trim, gap tracking; `TCPStream`: FIN/RST connection-state tracking | `GET /api/cases/{id}/sessions` (`reassembly_gaps`, `tcp_connection_state`) | Session detail → Connection state badge | `tests/test_stream_reassembly.py` |
| 6 | TLS handshake reconstruction | `_parse_handshake_messages()` cross-record handshake reassembly | " | " | `tests/test_stream_reassembly.py` |
| 7 | Negotiated TLS versions | ClientHello/ServerHello version parsing | `sessions[].tls_version` | Session detail | `tests/test_pcap_corpus_e2e.py` |
| 8 | Negotiated cipher suites | ServerHello cipher parsing against `crypto_reference.py` IANA registry | `sessions[].cipher_suite` | Session detail | `tests/test_crypto_reference.py` |
| 9 | Key-exchange mechanisms | TLS1.3 `key_share` / TLS≤1.2 cipher-implied KEX extraction | `sessions[].key_exchange` | Session detail | `tests/test_crypto_reference.py` |
| 10 | X.509 extraction | `analyze_certificate()` (subject/issuer/validity/key/sig algo/fingerprint) | `sessions[].cert_*` | Session detail → Certificate panel | `tests/test_cert_chain_validation.py` |
| 11 | Certificate-chain validation | `validate_certificate_chain()` — real cryptographic signature verification against the Mozilla root store, **plus** TLS1.3 observability model so an encrypted-and-thus-unobservable chain is never reported as invalid | `sessions[].cert_chain_valid`, `cert_observable`, `observability_note` | Session detail; suppressed/relabeled for TLS1.3 | `tests/test_cert_chain_validation.py`, `tests/test_upgrade3_additions.py` |
| 12 | Certificate expiration | `analyze_certificate()` validity window check | `sessions[].cert_expired` | Session detail | `tests/test_cert_chain_validation.py` |
| 13 | Public-key algorithm | `analyze_certificate()` | `sessions[].cert_key_algo` | Session detail | `tests/test_cert_chain_validation.py` |
| 14 | Public-key length | " | `sessions[].cert_key_size` | Session detail | " |
| 15 | Digital signature algorithm | " | `sessions[].cert_sig_algo` | Session detail | " |
| 16 | Weak crypto / deprecated TLS detection | `findings_engine.py` rule engine against `crypto_reference.py` | `GET /api/cases/{id}/findings` | Findings tab | `tests/test_crypto_reference.py` |
| 17 | Insecure protocol configurations | Rule engine + org-configurable cipher/TLS policy engine (`SecurityPolicy`) | `findings[]`, `GET/PUT /api/admin/policy` | Findings tab; Admin → Security Policy | — |
| 18 | Forward secrecy | Cipher-suite KEX classification | `sessions[].forward_secrecy` | Session detail | `tests/test_crypto_reference.py` |
| 19 | AI cryptographic risk scoring | Hybrid rule-based (70%) + IsolationForest anomaly (30%) blend, with per-reason point weights and top-contributing-feature explanation | `sessions[].risk_score`, `weighted_reasons`, `anomaly_explanation` | Session detail → "Risk factors (explainable)" | — |
| 20 | AI TLS anomaly detection | `run_anomaly_detection()` (IsolationForest) | `sessions[].anomaly_score`, `is_anomalous` | Session detail | — |
| 21 | Prioritized security findings | Severity-sorted findings with remediation tracking (open→assigned→fixed→verified) | `findings[]`, `PATCH /api/cases/findings/{id}/remediation` | Findings tab | — |
| 22 | Comprehensive security posture | Case-level grade/score rollup, historical baseline, risk trend | `GET /api/dashboard/summary`, `/risk-trend`, `/baseline` | Dashboard | — |
| 23 | JSON/PDF/HTML report + dashboard | `report_generator.py`, evidence-hash-stamped | `GET /api/reports/{id}/{json,pdf,html}` | Case Detail → export buttons | — |

## Beyond the PS's explicit list (hardening & investigator UX)

| Feature | Why it's here | API / UI |
|---|---|---|
| Non-standard port detection | Real mail relays don't always sit on well-known ports; banner-sniffing catches SMTP/IMAP/POP3 elsewhere | `sessions[].non_standard_port`; badge in Session Inventory |
| PCAP capture metadata | Packet count, duration, link type, capture window, for forensic context | `case.capture_*`; Case Detail metadata card |
| Certificate fingerprinting + cross-case reuse | Correlates infrastructure/relay reuse across investigations | `GET /api/cases/{id}/certificates/reuse`; Certificates tab |
| IOC extraction | Domains/IPs/cert fingerprints, for SOC triage/export | `GET /api/cases/{id}/iocs`; Certificates & IOCs tab |
| Forensic evidence timeline | Chronological capture→session→TLS→cert→finding view | `GET /api/cases/{id}/timeline`; Timeline tab |
| Case collaboration | Investigator notes/comments thread | `GET/POST /api/cases/{id}/comments`; Investigator Notes tab |
| Evidence integrity hashing | SHA-256 of the raw upload, embedded in every report, for chain-of-custody | `case.file_sha256`; report headers |
| Tamper-evident audit trail | Hash-chained log of every login/upload/delete/admin action, independently verifiable | `GET /api/admin/audit-logs`, `/audit-logs/verify`; Audit Trail page |
| Role-based access control | 4 roles (Admin/SOC Analyst/Forensic Investigator/Compliance Officer), each with distinct UI/authority | see README §3 |
| Account lockout, rate limiting, refresh tokens, password policy | Production auth hardening | `auth_routes.py` |

## Known limitations (stated, not hidden)

- **IP-level fragmentation reassembly** is not implemented — a capture with fragmented IP
  packets (as opposed to TCP segmentation, which *is* handled) will show gaps for those
  sessions rather than silently misreconstructing them.
- **Threat-intelligence enrichment** (external domain/IP reputation lookups) is deliberately
  not implemented — this tool is designed for offline/air-gapped passive forensic analysis,
  and calling out to a paid external API would break that model and the free-tier deployment
  target.
- **Custom compliance framework mapping** is static (NIST/PCI-DSS/RBI references are
  hardcoded per finding type) rather than admin-editable; the cipher/TLS policy engine *is*
  admin-editable and covers the more commonly-requested case (raising the bar above the
  built-in baseline).
- **TCP state tracking** covers FIN/RST/established, not a full RFC 793 state machine
  (SYN retransmits, window scaling, etc.) — sufficient for flagging abnormal terminations,
  not a complete TCP diagnostic tool.
