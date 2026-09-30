"""
Converts scored session data into prioritized, actionable findings with
concrete mitigation guidance and compliance framework references
(NIST SP 800-52r2, PCI-DSS 4.0, RBI Cyber Security Framework, CERT-In
guidelines) -- directly supporting the "Recommendation of mitigation
measures" and "Prioritized security findings" deliverables.
"""

RECOMMENDATIONS = {
    "plaintext": (
        "Enforce mandatory TLS for all mail submission and retrieval. Disable "
        "plaintext AUTH on ports 25/110/143 and require STARTTLS or migrate to "
        "implicit-TLS ports (465/993/995)."
    ),
    "deprecated_tls": (
        "Disable SSLv3/TLS1.0/TLS1.1 at the MTA/IMAP/POP3 daemon configuration. "
        "Enforce a minimum of TLS 1.2, and prefer TLS 1.3 where client support allows."
    ),
    "weak_cipher": (
        "Remove RC4, 3DES, DES, NULL, EXPORT and anonymous cipher suites from the "
        "server's cipher preference list. Adopt an AEAD-only cipher policy "
        "(AES-GCM / ChaCha20-Poly1305)."
    ),
    "no_fs": (
        "Reconfigure cipher suite ordering to prioritize ECDHE/DHE key exchange "
        "so that a future key compromise cannot retroactively decrypt captured traffic."
    ),
    "cert_expired": (
        "Renew the X.509 certificate immediately and implement automated renewal "
        "(e.g. ACME/Let's Encrypt or internal PKI auto-enrollment) with expiry monitoring."
    ),
    "cert_self_signed": (
        "Replace self-signed certificates with certificates issued by a trusted "
        "internal or public Certificate Authority to prevent MITM and establish chain of trust."
    ),
    "cert_weak_key": (
        "Reissue the certificate with an RSA key of at least 2048 bits (3072+ "
        "recommended) or an EC key on P-256 or stronger."
    ),
    "cert_weak_sig": (
        "Reissue the certificate using SHA-256 or stronger signature hashing; "
        "MD5/SHA-1 signed certificates are vulnerable to collision-based forgery."
    ),
    "starttls_missing": (
        "Implement STARTTLS (RFC 3207 for SMTP, RFC 2595 for IMAP/POP3) and reject "
        "or flag clients that do not negotiate it before authentication."
    ),
    "downgrade": (
        "Audit for active downgrade/MITM interference on the network path; enforce "
        "server-side minimum TLS version to eliminate silent protocol downgrade."
    ),
    "chain_invalid": (
        "Repair the server's certificate chain: ensure the full intermediate chain "
        "(not just the leaf) is served, that each certificate is signed by the next "
        "certificate's key, and that no certificate in the path is forged or expired."
    ),
    "static_kex": (
        "Disable static-RSA/ECDH key exchange cipher suites; require ECDHE/DHE-only "
        "suites so a future private-key compromise cannot retroactively decrypt "
        "captured traffic."
    ),
}

COMPLIANCE_MAP = {
    "plaintext": "PCI-DSS 4.0 Req 4.2.1; NIST SP 800-52r2 §3; CERT-In Advisory",
    "deprecated_tls": "NIST SP 800-52r2 §3.1 (TLS1.2 min); PCI-DSS 4.0 Req 4.2.1",
    "weak_cipher": "OWASP TLS Cheat Sheet; NIST SP 800-52r2 §3.3",
    "no_fs": "NIST SP 800-52r2 §3.3.1 (PFS recommended)",
    "cert_expired": "CA/Browser Forum Baseline Requirements §6.3.2",
    "cert_self_signed": "RFC 5280; Internal PKI Policy",
    "cert_weak_key": "NIST SP 800-57 Part 1 (min 2048-bit RSA)",
    "cert_weak_sig": "NIST SP 800-131A (SHA-1 deprecated)",
    "starttls_missing": "RFC 3207 / RFC 2595",
    "downgrade": "RFC 7457 (TLS attack taxonomy)",
    "chain_invalid": "RFC 5280 §6 (Certification Path Validation)",
    "static_kex": "NIST SP 800-52r2 §3.3.1 (PFS recommended)",
}


def _sev_from_score(contribution_flag: bool, base_severity: str) -> str:
    return base_severity if contribution_flag else None


def generate_findings_for_session(session: dict, policy: dict = None) -> list:
    findings = []
    cert_observable = session.get("cert_observable")
    # TLS 1.3 observability model: when the certificate genuinely isn't
    # observable from a passive capture (expected, secure behavior), skip
    # every certificate-derived finding below rather than drawing a false
    # conclusion from data the capture structurally cannot see.
    cert_data_usable = cert_observable is not False

    if session.get("plaintext_only"):
        findings.append({
            "category": "Encryption Absent", "severity": "critical",
            "title": "Cleartext email session with no TLS/STARTTLS",
            "description": (
                f"{session['protocol']} session {session['stream_id']} transmitted "
                "credentials and/or message content without any transport encryption."
            ),
            "recommendation": RECOMMENDATIONS["plaintext"],
            "compliance_refs": COMPLIANCE_MAP["plaintext"],
        })

    if session.get("tls_negotiated") and session.get("tls_version") in {"SSLv3", "TLSv1.0", "TLSv1.1", None}:
        findings.append({
            "category": "Weak TLS Version", "severity": "high",
            "title": f"Deprecated protocol version negotiated ({session.get('tls_version') or 'undetermined'})",
            "description": f"Session {session['stream_id']} negotiated an obsolete/undetected TLS version, vulnerable to known downgrade and padding-oracle attacks.",
            "recommendation": RECOMMENDATIONS["deprecated_tls"],
            "compliance_refs": COMPLIANCE_MAP["deprecated_tls"],
        })

    if session.get("cipher_strength") == "weak":
        findings.append({
            "category": "Weak Cipher Suite", "severity": "high",
            "title": f"Weak cipher suite in use: {session.get('cipher_suite')}",
            "description": f"Session {session['stream_id']} negotiated a cipher suite with known cryptographic weaknesses.",
            "recommendation": RECOMMENDATIONS["weak_cipher"],
            "compliance_refs": COMPLIANCE_MAP["weak_cipher"],
        })

    if session.get("tls_negotiated") and not session.get("forward_secrecy") and session.get("cipher_suite"):
        findings.append({
            "category": "No Forward Secrecy", "severity": "medium",
            "title": "Cipher suite lacks Perfect Forward Secrecy",
            "description": f"Session {session['stream_id']} used {session.get('cipher_suite')}, which does not provide forward secrecy.",
            "recommendation": RECOMMENDATIONS["no_fs"],
            "compliance_refs": COMPLIANCE_MAP["no_fs"],
        })

    if session.get("cert_expired") and cert_data_usable:
        findings.append({
            "category": "Certificate Expired", "severity": "critical",
            "title": "Server certificate has expired",
            "description": f"Certificate for {session.get('cert_subject')} expired on {session.get('cert_valid_to')}.",
            "recommendation": RECOMMENDATIONS["cert_expired"],
            "compliance_refs": COMPLIANCE_MAP["cert_expired"],
        })

    if session.get("cert_self_signed") and cert_data_usable:
        findings.append({
            "category": "Certificate Trust", "severity": "medium",
            "title": "Self-signed certificate in use",
            "description": f"Certificate for {session.get('cert_subject')} is self-signed, offering no third-party validation.",
            "recommendation": RECOMMENDATIONS["cert_self_signed"],
            "compliance_refs": COMPLIANCE_MAP["cert_self_signed"],
        })

    if session.get("cert_weak_key") and cert_data_usable:
        findings.append({
            "category": "Weak Key Strength", "severity": "high",
            "title": f"Weak certificate public key ({session.get('cert_key_size')}-bit {session.get('cert_key_algo')})",
            "description": f"Certificate for {session.get('cert_subject')} uses an undersized key vulnerable to factorization/discrete-log attacks.",
            "recommendation": RECOMMENDATIONS["cert_weak_key"],
            "compliance_refs": COMPLIANCE_MAP["cert_weak_key"],
        })

    if session.get("cert_weak_signature") and cert_data_usable:
        findings.append({
            "category": "Weak Signature Algorithm", "severity": "high",
            "title": f"Weak certificate signature algorithm ({session.get('cert_sig_algo')})",
            "description": f"Certificate for {session.get('cert_subject')} is signed using a deprecated hash algorithm.",
            "recommendation": RECOMMENDATIONS["cert_weak_sig"],
            "compliance_refs": COMPLIANCE_MAP["cert_weak_sig"],
        })

    if (not session.get("implicit_tls") and not session.get("starttls_used") and not session.get("tls_negotiated")):
        findings.append({
            "category": "STARTTLS Missing", "severity": "medium",
            "title": "STARTTLS opportunistic encryption not offered/used",
            "description": f"Session {session['stream_id']} on plaintext port {session.get('dst_port')} never attempted a STARTTLS upgrade.",
            "recommendation": RECOMMENDATIONS["starttls_missing"],
            "compliance_refs": COMPLIANCE_MAP["starttls_missing"],
        })

    if session.get("cert_chain_valid") is False and cert_data_usable:
        findings.append({
            "category": "Certificate Chain Invalid", "severity": "critical",
            "title": "Certificate chain failed cryptographic validation",
            "description": (
                f"Session {session['stream_id']}: " +
                "; ".join(session.get("cert_chain_errors", [])[:3])
            ),
            "recommendation": RECOMMENDATIONS["chain_invalid"],
            "compliance_refs": COMPLIANCE_MAP["chain_invalid"],
        })

    if session.get("key_exchange") and "static" in str(session.get("key_exchange")).lower():
        findings.append({
            "category": "Static Key Exchange", "severity": "medium",
            "title": f"Static key exchange mechanism in use ({session.get('key_exchange')})",
            "description": (
                f"Session {session['stream_id']} negotiated a non-ephemeral key exchange, "
                "so a future compromise of the server's private key would allow "
                "retroactive decryption of this captured traffic."
            ),
            "recommendation": RECOMMENDATIONS["static_kex"],
            "compliance_refs": COMPLIANCE_MAP["static_kex"],
        })

    if session.get("capture_truncated"):
        findings.append({
            "category": "Incomplete Capture", "severity": "low",
            "title": "Capture exceeded the packet-count analysis limit",
            "description": (
                f"Session {session['stream_id']} comes from a capture that was truncated "
                "at the configured MAX_PACKETS_PER_CAPTURE resource limit. This session's "
                "posture assessment reflects only the packets processed before truncation."
            ),
            "recommendation": "Split the capture into smaller pcaps, or raise "
                               "MAX_PACKETS_PER_CAPTURE if the deployment has memory "
                               "headroom to process larger captures in one pass.",
            "compliance_refs": "N/A — capture integrity notice",
        })

    if session.get("reassembly_gaps", 0) > 0:
        findings.append({
            "category": "Incomplete Capture", "severity": "low",
            "title": "TCP stream reassembly gap detected",
            "description": (
                f"Session {session['stream_id']} has {session['reassembly_gaps']} "
                "byte-range gap(s) in the reconstructed stream (packets missing from the "
                "capture). Findings for this session may be based on partial data."
            ),
            "recommendation": "Re-capture with a tap/mirror port that guarantees full "
                               "packet capture, or verify capture buffer sizing.",
            "compliance_refs": "N/A — capture integrity notice",
        })

    if session.get("is_anomalous"):
        findings.append({
            "category": "AI-Detected Anomaly", "severity": "medium",
            "title": "Statistically anomalous TLS behavior detected",
            "description": (
                f"Session {session['stream_id']} deviates significantly from the "
                f"cryptographic baseline observed across this capture "
                f"(anomaly score {session.get('anomaly_score')})."
                + (f" Primary driver: {session['anomaly_explanation']}." if session.get("anomaly_explanation") else "")
            ),
            "recommendation": "Manually review this session for signs of active interception, misconfiguration, or a rogue mail relay.",
            "compliance_refs": "N/A — behavioral/statistical detection",
        })

    if cert_observable is False:
        findings.append({
            "category": "TLS 1.3 Observability", "severity": "info",
            "title": "Certificate not observable (TLS 1.3 handshake encryption) — expected behavior",
            "description": session.get("observability_note") or (
                f"Session {session['stream_id']} negotiated TLS 1.3; certificate and "
                "post-ServerHello handshake data are encrypted and not visible to passive "
                "capture. This is correct, secure TLS 1.3 behavior, not a finding against "
                "the server."
            ),
            "recommendation": "No action needed. For certificate posture visibility on TLS "
                               "1.3 traffic, use active/endpoint-based inspection (e.g. query "
                               "the server's certificate directly) rather than passive capture.",
            "compliance_refs": "RFC 8446 §5.1 (TLS 1.3 encrypted handshake)",
        })

    if session.get("non_standard_port"):
        findings.append({
            "category": "Non-Standard Port", "severity": "low",
            "title": f"{session.get('protocol')} traffic detected on non-standard port {session.get('dst_port')}",
            "description": (
                f"Session {session['stream_id']} was identified as {session.get('protocol')} "
                "by its protocol greeting banner rather than by well-known port number, "
                "which can indicate a relay, proxy, or misconfiguration worth reviewing."
            ),
            "recommendation": "Confirm this is an intended mail relay/proxy configuration; "
                               "document non-standard listeners in the network security baseline.",
            "compliance_refs": "N/A — network configuration notice",
        })

    if session.get("tcp_connection_state") == "reset":
        findings.append({
            "category": "Abnormal Connection Termination", "severity": "low",
            "title": "Session ended with a TCP RST rather than a graceful close",
            "description": (
                f"Session {session['stream_id']} was terminated with a TCP RST. This can be "
                "benign (client abort, timeout) but can also indicate a blocked/interfered "
                "connection, worth correlating with other findings on the same host pair."
            ),
            "recommendation": "Review firewall/IPS logs for this host pair around the session "
                               "timestamp if this pattern recurs across multiple sessions.",
            "compliance_refs": "N/A — network behavior notice",
        })

    # --- Organization-defined cipher/TLS policy (cipher/TLS policy engine) ---
    if policy and session.get("tls_negotiated") and not session.get("plaintext_only"):
        min_ver_rank = {"TLSv1.3": 4, "TLSv1.2": 3, "TLSv1.1": 2, "TLSv1.0": 1, "SSLv3": 0}
        policy_min = policy.get("min_tls_version", "TLSv1.2")
        sess_ver = session.get("tls_version")
        if sess_ver and min_ver_rank.get(sess_ver, -1) < min_ver_rank.get(policy_min, 3):
            findings.append({
                "category": "Organizational Policy Violation", "severity": "high",
                "title": f"TLS version below organization policy minimum ({policy_min})",
                "description": (
                    f"Session {session['stream_id']} negotiated {sess_ver}, below this "
                    f"organization's configured minimum of {policy_min}."
                ),
                "recommendation": "Bring this endpoint's TLS configuration into compliance "
                                   "with the organization's cipher/TLS policy.",
                "compliance_refs": "Internal Security Policy (org-configured)",
            })
        banned = policy.get("banned_ciphers") or []
        cipher = session.get("cipher_suite") or ""
        hit = next((b for b in banned if b and b.upper() in cipher.upper()), None)
        if hit:
            findings.append({
                "category": "Organizational Policy Violation", "severity": "high",
                "title": f"Cipher suite banned by organization policy ({hit})",
                "description": (
                    f"Session {session['stream_id']} negotiated {cipher}, which matches "
                    f"this organization's banned-cipher policy entry '{hit}'."
                ),
                "recommendation": "Remove this cipher from the server's offered suite list.",
                "compliance_refs": "Internal Security Policy (org-configured)",
            })
        if policy.get("require_forward_secrecy") and session.get("cipher_suite") and not session.get("forward_secrecy"):
            findings.append({
                "category": "Organizational Policy Violation", "severity": "medium",
                "title": "Forward secrecy required by policy but not provided",
                "description": (
                    f"Session {session['stream_id']} used {session.get('cipher_suite')}, "
                    "which lacks forward secrecy; this organization's policy requires it."
                ),
                "recommendation": "Prioritize ECDHE/DHE suites to satisfy the organization's "
                                   "forward-secrecy requirement.",
                "compliance_refs": "Internal Security Policy (org-configured)",
            })

    return findings
