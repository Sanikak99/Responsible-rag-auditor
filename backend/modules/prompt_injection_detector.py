import re
from typing import List, Dict, Any, Tuple


# ── Pattern Definitions ──────────────────────────────────────────────────────
# Each pattern has: name, pattern, severity, category, explanation

INJECTION_PATTERNS = [

    # ── Category 1: Instruction Override ────────────────────────────────────
    # These phrases directly attempt to override the system's instructions.
    {
        "name": "Ignore Instructions",
        "pattern": r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(instruction|prompt|rule|guideline|restriction|system|previous|above|all)\b",
        "severity": "HIGH",
        "category": "Instruction Override",
        "explanation": "Attempt to make the model ignore its system prompt or guidelines."
    },
    {
        "name": "Previous Instructions Override",
        "pattern": r"\b(ignore|disregard|forget).{0,20}\b(previous|prior|above|earlier|all)\b",
        "severity": "HIGH",
        "category": "Instruction Override",
        "explanation": "Classic prompt injection pattern targeting RAG system prompts."
    },

    # ── Category 2: Role Assumption / Jailbreak ──────────────────────────────
    # Attempting to make the model assume a different identity/persona.
    {
        "name": "Role Assumption",
        "pattern": r"\b(you are now|act as|pretend (to be|you are)|roleplay as|simulate|imagine you are|you must now)\b",
        "severity": "HIGH",
        "category": "Role Assumption",
        "explanation": "Attempting to make the model assume an unrestricted persona (e.g., 'DAN' jailbreak)."
    },
    {
        "name": "Restriction Removal",
        "pattern": r"\b(no restriction|without restriction|remove (your )?filter|unrestricted mode|developer mode|jailbreak|DAN mode)\b",
        "severity": "HIGH",
        "category": "Jailbreak Attempt",
        "explanation": "Explicit attempt to remove safety filters or enter 'jailbreak' mode."
    },

    # ── Category 3: System Prompt Extraction ─────────────────────────────────
    # Attempting to extract confidential system prompts.
    {
        "name": "System Prompt Extraction",
        "pattern": r"\b(reveal|show|print|output|display|repeat|tell me|what is).{0,30}\b(system prompt|instructions|prompt|configuration|initial prompt)\b",
        "severity": "HIGH",
        "category": "Data Extraction",
            "explanation": "Attempting to extract the confidential system prompt — a common reconnaissance step."
    },
    {
        "name": "Confidential Data Extraction",
        "pattern": r"\b(reveal|leak|expose|show).{0,30}\b(password|secret|key|token|api key|credential|internal)\b",
        "severity": "HIGH",
        "category": "Data Extraction",
        "explanation": "Attempting to extract sensitive configuration data."
    },

    # ── Category 4: Context Poisoning ────────────────────────────────────────
    # Embedding instructions inside what looks like normal content.
    {
        "name": "Hidden Instruction Embedding",
        "pattern": r"(<!--.*?-->|<\s*script.*?>|\[INST\]|\[\/INST\]|<<SYS>>|<\|system\|>|\|<endoftext>\|)",
        "severity": "HIGH",
        "category": "Context Poisoning",
        "explanation": "HTML comments, script tags, or special tokens used to hide malicious instructions."
    },
    {
        "name": "Delimiter Injection",
        "pattern": r"(###\s*(system|instruction|human|assistant)|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\])",
        "severity": "HIGH",
        "category": "Context Poisoning",
        "explanation": "Using LLM conversation delimiters to inject fake system/assistant turns."
    },

    # ── Category 5: Indirect / RAG-specific Injection ────────────────────────
    {
        "name": "Indirect Instruction in Query",
        "pattern": r"\b(the document says|according to the text|as stated above).{0,50}(ignore|disregard|override|you should|you must)\b",
        "severity": "MEDIUM",
        "category": "Indirect Injection",
        "explanation": "Attempt to make the model follow instructions disguised as retrieved content."
    },

    # ── Category 6: Social Engineering ───────────────────────────────────────
    {
        "name": "Authority Impersonation",
        "pattern": r"\b(I am (your|the) (developer|creator|admin|trainer|anthropic|openai|engineer)|this is (anthropic|openai|your creator))\b",
        "severity": "MEDIUM",
        "category": "Social Engineering",
        "explanation": "Claiming false authority to override safety measures."
    },
    {
        "name": "Hypothetical Bypass",
        "pattern": r"\b(hypothetically|in a fictional world|for a story|for educational purposes|theoretically).{0,50}(how to|explain|tell me|show me)\b",
        "severity": "LOW",
        "category": "Social Engineering",
        "explanation": "Using hypothetical framing to extract restricted information."
    },
]


# ── Heuristic Checks ─────────────────────────────────────────────────────────

def _check_excessive_length(query: str) -> List[Dict]:
    """
    Unusually long queries can indicate injection payloads being smuggled in.
    Legitimate educational queries rarely exceed 500 characters.
    This is a heuristic — not conclusive, but worth flagging.
    """
    if len(query) > 800:
        return [{
            "name": "Excessive Query Length",
            "severity": "LOW",
            "category": "Anomaly",
            "explanation": f"Query is {len(query)} characters. Very long queries may contain hidden injection payloads.",
            "matched_text": f"[{len(query)} characters]"
        }]
    return []


def _check_mixed_languages_suspicion(query: str) -> List[Dict]:
    """
    Rapid language switching within a query can be an attempt to confuse
    the model's safety filters (which may be language-specific).
    """
    latin_words = len(re.findall(r'\b[a-zA-Z]+\b', query))
    non_latin = len(re.findall(r'[^\x00-\x7F]', query))
    if latin_words > 5 and non_latin > 10:
        return [{
            "name": "Mixed Script Anomaly",
            "severity": "LOW",
            "category": "Anomaly",
            "explanation": "Mix of Latin and non-Latin scripts may indicate multilingual injection attempt.",
            "matched_text": "[mixed script detected]"
        }]
    return []


# ── Main Detection ────────────────────────────────────────────────────────────

def _scan_for_patterns(text: str) -> List[Dict]:
    """Scan text against all defined injection patterns."""
    findings = []
    text_lower = text.lower()

    for pattern_def in INJECTION_PATTERNS:
        matches = re.findall(
            pattern_def["pattern"],
            text_lower,
            re.IGNORECASE | re.DOTALL
        )
        if matches:
            # Extract actual matched text for display
            raw_match = re.search(
                pattern_def["pattern"], text, re.IGNORECASE | re.DOTALL
            )
            matched_text = raw_match.group(0)[:80] if raw_match else "[pattern matched]"

            findings.append({
                "name": pattern_def["name"],
                "severity": pattern_def["severity"],
                "category": pattern_def["category"],
                "explanation": pattern_def["explanation"],
                "matched_text": matched_text
            })

    return findings


def run_injection_check(
    query: str,
    retrieved_chunks: List[str],
    generated_answer: str
) -> Dict[str, Any]:
    """
    Main entry point for Module 5.

    Scans BOTH the query (direct injection) AND retrieved chunks
    (indirect/RAG injection) for malicious patterns.
    """

    query_findings = _scan_for_patterns(query)
    query_findings += _check_excessive_length(query)
    query_findings += _check_mixed_languages_suspicion(query)


    chunk_findings = []
    for i, chunk in enumerate(retrieved_chunks):
        findings = _scan_for_patterns(chunk)
        if findings:
            chunk_findings.append({
                "chunk_index": i,
                "findings": findings
            })

    all_findings = query_findings + [
        f for cf in chunk_findings for f in cf["findings"]
    ]
    severities = [f["severity"] for f in all_findings]
    risk_level = _risk_level(severities)

    injection_detected = len(all_findings) > 0
    status = "FAIL" if "HIGH" in severities else ("WARN" if injection_detected else "PASS")

    return {
        "module": "Prompt Injection Detection",
        "status": status,
        "risk_level": risk_level,
        "injection_detected": injection_detected,
        "query_findings": query_findings,
        "chunk_findings": chunk_findings,
        "total_findings": len(all_findings),
        "summary": _build_summary(query_findings, chunk_findings, status),
        "recommendation": _build_recommendation(status, query_findings),
        "owasp_reference": "OWASP LLM Top 10 2023 — LLM01: Prompt Injection",
        "framework_mappings": [
            "OWASP LLM Top 10 — LLM01: Prompt Injection (highest risk)",
            "NIST AI RMF — MANAGE 2.2: Risk response via input validation",
            "RBI FREE-AI — Ethics pillar: preventing AI misuse",
            "EU AI Act Article 15 — AI system robustness and cybersecurity",
            "MITRE ATLAS — AML.T0051: Prompt Injection attack technique"
        ]
    }


def _risk_level(severities: List[str]) -> str:
    if "HIGH" in severities:
        return "HIGH"
    elif "MEDIUM" in severities:
        return "MEDIUM"
    elif "LOW" in severities:
        return "LOW"
    return "NONE"


def _build_summary(query_findings, chunk_findings, status) -> str:
    if status == "PASS":
        return "No injection patterns detected. Query appears safe."
    parts = []
    if query_findings:
        cats = list(set(f["category"] for f in query_findings))
        parts.append(f"Query: {', '.join(cats)}")
    if chunk_findings:
        parts.append(f"{len(chunk_findings)} retrieved chunk(s) contain suspicious patterns")
    return "Injection indicators detected — " + " | ".join(parts)


def _build_recommendation(status, query_findings) -> str:
    if status == "PASS":
        return "Query is clean. Safe to forward to LLM."
    high = [f for f in query_findings if f["severity"] == "HIGH"]
    if high:
        return (
            "HIGH RISK: Do NOT forward this query to the LLM. "
            "Block the request and log the attempt. "
            "Notify security team if pattern persists from same source."
        )
    return (
        "Low-to-medium injection risk detected. "
        "Consider sanitising query before forwarding. "
        "Monitor for repeated patterns from the same session."
    )
