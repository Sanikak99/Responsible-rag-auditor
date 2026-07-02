import re
from typing import List, Dict, Any


PII_PATTERNS = [
    {
        "name": "Email Address",
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "severity": "HIGH",
        "framework_ref": "DPDP Act 2023 — Section 2(t) personal data",
        "description": "Email addresses are personal data under DPDP Act 2023"
    },
    {
        "name": "Indian Mobile Number",
        "pattern": r"\b[6-9]\d{9}\b",
        "severity": "HIGH",
        "framework_ref": "DPDP Act 2023 — Section 2(t)",
        "description": "10-digit Indian mobile numbers starting with 6-9"
    },
    {
        "name": "Aadhaar Number",
        "pattern": r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
        "severity": "CRITICAL",
        "framework_ref": "Aadhaar Act 2016 + DPDP Act 2023 — sensitive personal data",
        "description": "12-digit Aadhaar UID — extremely sensitive, regulated by UIDAI"
    },
    {
        "name": "PAN Card Number",
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "severity": "HIGH",
        "framework_ref": "Income Tax Act + DPDP Act 2023",
        "description": "10-character Indian PAN card number"
    },
    {
        "name": "Credit/Debit Card Number",
        "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "severity": "CRITICAL",
        "framework_ref": "PCI-DSS + RBI Payment Security Guidelines",
        "description": "16-digit card number — RBI mandates masking in logs"
    },
    {
        "name": "Indian Passport Number",
        "pattern": r"\b[A-PR-WY][1-9]\d{7}\b",
        "severity": "HIGH",
        "framework_ref": "DPDP Act 2023 — sensitive personal data",
        "description": "8-character Indian passport number"
    },
    {
        "name": "IFSC Code",
        "pattern": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        "severity": "MEDIUM",
        "framework_ref": "RBI Banking Regulations",
        "description": "11-character bank IFSC code — financial identifier"
    },
    {
        "name": "Indian Pincode",
        "pattern": r"\b[1-9][0-9]{5}\b",
        "severity": "LOW",
        "framework_ref": "DPDP Act 2023 — location data",
        "description": "6-digit Indian postal pincode — indirect location identifier"
    },
    {
        "name": "IPv4 Address",
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "severity": "MEDIUM",
        "framework_ref": "GDPR Recital 30 — online identifiers",
        "description": "IP addresses are personal data under GDPR and DPDP Act"
    },
]


def scan_text(text: str) -> List[Dict[str, Any]]:
    """
    Scan a single piece of text for all PII patterns.
    Returns list of findings with matched value, pattern name, severity.
    
    The matched value is MASKED in output — we never log the actual PII,
    only the fact that it was found. This is itself a data privacy best
    practice called 'data minimisation in audit logs'.
    """
    findings = []

    for pii in PII_PATTERNS:
        matches = re.findall(pii["pattern"], text)
        if matches:
            findings.append({
                "pii_type": pii["name"],
                "severity": pii["severity"],
                "count": len(matches),
                "masked_sample": _mask(matches[0]),
                "framework_ref": pii["framework_ref"],
                "description": pii["description"]
            })

    return findings


def _mask(value: str) -> str:
    """
    Mask a PII value for safe logging.
    Standard practice: show first 3 characters, mask the rest with *.
    Banks use this format in transaction logs under RBI guidelines.
    """
    value = str(value).replace(" ", "")
    if len(value) <= 3:
        return "***"
    return value[:3] + "*" * (len(value) - 3)


def run_pii_check(
    query: str,
    retrieved_chunks: List[str],
    generated_answer: str
) -> Dict[str, Any]:
    """
    Main entry point for Module 1.
    Scans all three inputs separately so we know WHERE the PII came from.
    
    Knowing the source is critical:
    - PII in query   → user submitted personal data (consent issue)
    - PII in chunks  → knowledge base has a data contamination problem
    - PII in answer  → model is leaking data from its context (highest risk)
    """
    query_findings      = scan_text(query)
    answer_findings     = scan_text(generated_answer)
    chunk_findings      = []

    for i, chunk in enumerate(retrieved_chunks):
        findings = scan_text(chunk)
        if findings:
            chunk_findings.append({
                "chunk_index": i,
                "findings": findings
            })

    all_findings = query_findings + answer_findings
    for cf in chunk_findings:
        all_findings += cf["findings"]

    severities = [f["severity"] for f in all_findings]
    risk_level = _calculate_risk_level(severities)

    pii_detected = len(all_findings) > 0

    return {
        "module": "PII Detection",
        "status": "FAIL" if pii_detected else "PASS",
        "risk_level": risk_level,
        "pii_detected": pii_detected,
        "summary": _build_summary(query_findings, chunk_findings, answer_findings),
        "details": {
            "query_findings": query_findings,
            "chunk_findings": chunk_findings,
            "answer_findings": answer_findings,
        },
        "recommendation": _build_recommendation(pii_detected, answer_findings, chunk_findings),
        "framework_mappings": [
            "DPDP Act 2023 (India) — data minimisation",
            "RBI Cybersecurity Framework — PII protection",
            "NIST AI RMF — Privacy (MANAGE 2.2)",
            "ISO 27001 — Information Classification"
        ]
    }


def _calculate_risk_level(severities: List[str]) -> str:
    """Standard 4-level risk classification used in enterprise risk management."""
    if "CRITICAL" in severities:
        return "CRITICAL"
    elif "HIGH" in severities:
        return "HIGH"
    elif "MEDIUM" in severities:
        return "MEDIUM"
    elif "LOW" in severities:
        return "LOW"
    return "NONE"


def _build_summary(query_f, chunk_f, answer_f) -> str:
    parts = []
    if query_f:
        types = list(set(f["pii_type"] for f in query_f))
        parts.append(f"Query contains {', '.join(types)}")
    if chunk_f:
        parts.append(f"{len(chunk_f)} retrieved chunk(s) contain PII")
    if answer_f:
        types = list(set(f["pii_type"] for f in answer_f))
        parts.append(f"Generated answer exposes {', '.join(types)} — HIGHEST RISK")
    if not parts:
        return "No PII detected across query, chunks, and answer."
    return " | ".join(parts)


def _build_recommendation(pii_detected, answer_f, chunk_f) -> str:
    if not pii_detected:
        return "No action required. Pipeline is PII-clean for this query."
    recs = []
    if answer_f:
        recs.append("URGENT: Redact PII from generated answer before displaying to user.")
    if chunk_f:
        recs.append("Review knowledge base for accidental PII ingestion. Apply data sanitisation pipeline at indexing time.")
    return " ".join(recs)
