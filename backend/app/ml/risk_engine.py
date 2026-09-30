"""
AI-Assisted Cryptographic Risk Engine
--------------------------------------
Two complementary layers, matching the problem statement's requirement for
both deterministic risk classification AND AI-based anomaly detection:

1. RULE-BASED WEIGHTED SCORING (explainable, deterministic, audit-friendly)
   Produces a 0-100 risk score per session using a weighted rubric derived
   from NIST SP 800-52r2 / OWASP TLS Cheat Sheet / PCI-DSS 4.0 crypto
   requirements. This is what a SOC analyst can defend in a compliance
   report -- fully explainable, no black box.

2. UNSUPERVISED ANOMALY DETECTION (IsolationForest, scikit-learn)
   Learns the "normal" distribution of numeric TLS features across all
   sessions found in a capture and flags statistical outliers (e.g. a
   single session negotiating a stale cipher while every other host in
   the same capture uses modern suites) -- catching *contextual*
   anomalies that fixed rules alone would miss.

The final "AI risk score" blends both layers.
"""

from typing import List, Dict
import numpy as np
from sklearn.ensemble import IsolationForest

# ---- Rule-based weighted rubric ----------------------------------------

WEIGHTS = {
    "plaintext_only": 40,
    "deprecated_tls_version": 30,
    "weak_cipher": 25,
    "no_forward_secrecy": 10,
    "cert_expired": 20,
    "cert_self_signed": 12,
    "cert_weak_key": 18,
    "cert_weak_signature": 15,
    "starttls_not_used_on_plaintext_port": 15,
    "client_server_version_downgrade": 15,
}

DEPRECATED_VERSIONS = {"SSLv3", "TLSv1.0", "TLSv1.1", None}


def score_session_rule_based(session: Dict) -> Dict:
    score = 0
    reasons = []
    weighted_reasons = []  # explainable AI: each reason paired with its point contribution

    def _add(points, text):
        nonlocal score
        score += points
        reasons.append(text)
        weighted_reasons.append({"reason": text, "points": points})

    if session.get("plaintext_only"):
        _add(WEIGHTS["plaintext_only"], "No TLS/STARTTLS encryption negotiated — session transmitted in cleartext")

    tls_version = session.get("tls_version")
    if session.get("tls_negotiated") and tls_version in DEPRECATED_VERSIONS:
        _add(WEIGHTS["deprecated_tls_version"], f"Deprecated/unknown TLS version negotiated: {tls_version or 'undetected'}")

    if session.get("cipher_strength") == "weak":
        _add(WEIGHTS["weak_cipher"], f"Weak cipher suite negotiated: {session.get('cipher_suite')}")

    if session.get("tls_negotiated") and not session.get("forward_secrecy") and session.get("cipher_suite"):
        _add(WEIGHTS["no_forward_secrecy"], "Negotiated cipher suite does not provide forward secrecy")

    cert_usable = session.get("cert_observable") is not False
    if session.get("cert_expired") and cert_usable:
        _add(WEIGHTS["cert_expired"], "Server certificate is expired")

    if session.get("cert_self_signed") and cert_usable:
        _add(WEIGHTS["cert_self_signed"], "Self-signed certificate in use (chain of trust not established)")

    if session.get("cert_weak_key") and cert_usable:
        _add(WEIGHTS["cert_weak_key"], f"Weak public key size ({session.get('cert_key_size')} bits, {session.get('cert_key_algo')})")

    if session.get("cert_weak_signature") and cert_usable:
        _add(WEIGHTS["cert_weak_signature"], f"Weak certificate signature algorithm: {session.get('cert_sig_algo')}")

    if (not session.get("implicit_tls") and not session.get("starttls_used")
            and not session.get("tls_negotiated")):
        _add(WEIGHTS["starttls_not_used_on_plaintext_port"], "Plaintext port used without STARTTLS opportunistic upgrade")

    client_v = session.get("client_offered_version")
    if client_v and tls_version and client_v != tls_version and tls_version in DEPRECATED_VERSIONS:
        _add(WEIGHTS["client_server_version_downgrade"], f"Possible downgrade: client offered {client_v}, server negotiated {tls_version}")

    score = min(score, 100)
    return {"rule_score": score, "reasons": reasons, "weighted_reasons": weighted_reasons}


def _grade_from_score(score: float) -> str:
    if score >= 75:
        return "F"
    if score >= 55:
        return "D"
    if score >= 35:
        return "C"
    if score >= 15:
        return "B"
    return "A"


def _extract_numeric_features(session: Dict) -> List[float]:
    tls_ver_rank = {"TLSv1.3": 4, "TLSv1.2": 3, "TLSv1.1": 2, "TLSv1.0": 1, "SSLv3": 0}
    return [
        1.0 if session.get("plaintext_only") else 0.0,
        tls_ver_rank.get(session.get("tls_version"), -1),
        1.0 if session.get("cipher_strength") == "weak" else (0.5 if session.get("cipher_strength") == "moderate" else 0.0),
        1.0 if session.get("forward_secrecy") else 0.0,
        1.0 if session.get("cert_expired") else 0.0,
        1.0 if session.get("cert_self_signed") else 0.0,
        float(session.get("cert_key_size") or 0),
        1.0 if session.get("starttls_used") else 0.0,
        float(session.get("packet_count") or 0),
    ]


_FEATURE_NAMES = [
    "plaintext_only", "tls_version_rank", "cipher_weakness", "forward_secrecy",
    "cert_expired", "cert_self_signed", "cert_key_size", "starttls_used", "packet_count",
]


def run_anomaly_detection(sessions: List[Dict]) -> List[float]:
    """Returns an anomaly score in [0,1] per session (1 = most anomalous).
    Falls back gracefully for very small captures where IsolationForest
    isn't statistically meaningful."""
    if len(sessions) < 3:
        return [0.0] * len(sessions)

    X = np.array([_extract_numeric_features(s) for s in sessions])
    contamination = min(0.3, max(0.05, 2 / len(sessions)))
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    model.fit(X)
    raw_scores = model.decision_function(X)  # higher = more normal
    # normalize to 0..1 where 1 = most anomalous
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s - min_s < 1e-9:
        return [0.0] * len(sessions)
    normalized = 1 - (raw_scores - min_s) / (max_s - min_s)
    return normalized.tolist()


def _explain_anomaly(X: np.ndarray, index: int) -> str:
    """Explainable AI: rather than reporting only a bare anomaly score,
    identifies which single feature deviates furthest (in standard
    deviations) from the capture's own mean for that feature -- giving an
    analyst a concrete reason ("negotiated TLS version is unusually low
    versus this capture's baseline") instead of an opaque number."""
    if X.shape[0] < 3:
        return None
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std < 1e-9] = 1.0
    z = (X[index] - mean) / std
    worst_idx = int(np.argmax(np.abs(z)))
    direction = "lower" if z[worst_idx] < 0 else "higher"
    return f"{_FEATURE_NAMES[worst_idx]} is unusually {direction} than this capture's baseline (z={z[worst_idx]:.2f})"


def score_all_sessions(sessions: List[Dict], policy: Dict = None) -> List[Dict]:
    """Blends rule-based scoring (70% weight) with anomaly detection
    (30% weight) into a final 0-100 AI risk score per session."""
    anomaly_scores = run_anomaly_detection(sessions)
    X = np.array([_extract_numeric_features(s) for s in sessions]) if sessions else np.empty((0, 0))
    results = []
    for i, (session, anomaly) in enumerate(zip(sessions, anomaly_scores)):
        rule_result = score_session_rule_based(session)
        rule_score = rule_result["rule_score"]
        blended = min(100, round(0.7 * rule_score + 0.3 * (anomaly * 100), 1))
        is_anomalous = anomaly > 0.6
        results.append({
            **session,
            "risk_score": blended,
            "rule_score": rule_score,
            "anomaly_score": round(anomaly, 3),
            "is_anomalous": is_anomalous,
            "anomaly_explanation": _explain_anomaly(X, i) if is_anomalous else None,
            "risk_grade": _grade_from_score(blended),
            "reasons": rule_result["reasons"],
            "weighted_reasons": rule_result["weighted_reasons"],
        })
    return results


def compute_case_summary(scored_sessions: List[Dict]) -> Dict:
    if not scored_sessions:
        return {
            "overall_risk_score": 0, "risk_grade": "N/A", "total_sessions": 0,
            "encrypted_sessions": 0, "plaintext_sessions": 0,
        }
    scores = [s["risk_score"] for s in scored_sessions]
    overall = round(sum(scores) / len(scores), 1)
    encrypted = sum(1 for s in scored_sessions if not s.get("plaintext_only"))
    plaintext = len(scored_sessions) - encrypted
    return {
        "overall_risk_score": overall,
        "risk_grade": _grade_from_score(overall),
        "total_sessions": len(scored_sessions),
        "encrypted_sessions": encrypted,
        "plaintext_sessions": plaintext,
    }
