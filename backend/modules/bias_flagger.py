import re
from typing import List, Dict, Any
from collections import Counter


DEMOGRAPHIC_TERMS = {
    "gender": {
        "masculine": ["he", "him", "his", "man", "men", "male", "boy", "boys",
                      "husband", "father", "son", "brother", "gentleman", "sir"],
        "feminine": ["she", "her", "hers", "woman", "women", "female", "girl",
                     "girls", "wife", "mother", "daughter", "sister", "madam"],
        "neutral": ["they", "them", "person", "individual", "people", "human"]
    },
    "religion": {
        "terms": ["hindu", "muslim", "christian", "sikh", "buddhist", "jain",
                  "parsi", "jewish", "atheist", "religious", "secular"]
    },
    "region": {
        "terms": ["north", "south", "east", "west", "urban", "rural",
                  "metropolitan", "tier-1", "tier-2", "village", "city"]
    },
    "socioeconomic": {
        "affluent": ["wealthy", "rich", "affluent", "high-income", "premium",
                     "elite", "privileged", "upper-class"],
        "underprivileged": ["poor", "low-income", "underprivileged", "disadvantaged",
                            "below-poverty", "economically weaker", "EWS", "BPL"]
    }
}

# ── Loaded/Charged Word Lists ────────────────────────────────────────────────

POSITIVE_LOADED = ["capable", "intelligent", "hardworking", "trustworthy",
                   "successful", "skilled", "reliable", "honest", "efficient"]

NEGATIVE_LOADED = ["risky", "unreliable", "unskilled", "untrustworthy",
                   "problematic", "difficult", "dangerous", "suspicious", "fraud"]


def _count_demographic_terms(text: str) -> Dict[str, Dict[str, int]]:
    """
    Count occurrences of demographic terms per category.
    Uses word-boundary matching to avoid partial matches
    """
    text_lower = text.lower()
    counts = {}

    for category, subcategories in DEMOGRAPHIC_TERMS.items():
        counts[category] = {}
        if isinstance(subcategories, dict):
            for subcat, terms in subcategories.items():
                subcat_count = 0
                for term in terms:
                    pattern = r'\b' + re.escape(term) + r'\b'
                    subcat_count += len(re.findall(pattern, text_lower))
                counts[category][subcat] = subcat_count
        else:
            for term in subcategories:
                pattern = r'\b' + re.escape(term) + r'\b'
                counts[category][term] = len(re.findall(pattern, text_lower))

    return counts


def _check_gender_imbalance(counts: Dict) -> List[Dict]:
    """
    Check if masculine and feminine terms are used in very unequal proportions.
    A skew ratio > 3:1 is flagged as potential gender bias.
    """
    flags = []
    gender = counts.get("gender", {})
    masc = gender.get("masculine", 0)
    fem = gender.get("feminine", 0)

    total = masc + fem
    if total == 0:
        return flags

    if total > 0 and masc > 0 and fem > 0:
        ratio = max(masc, fem) / min(masc, fem)
        dominant = "masculine" if masc > fem else "feminine"
        if ratio > 3.0:
            flags.append({
                "bias_type": "Gender Representation Imbalance",
                "severity": "MEDIUM",
                "detail": f"{dominant.capitalize()} terms appear {ratio:.1f}x more than the other gender",
                "masculine_count": masc,
                "feminine_count": fem,
                "framework_ref": "EU AI Act Article 10 — non-discrimination"
            })
    elif masc > 0 and fem == 0 and masc >= 3:
        flags.append({
            "bias_type": "Gender Exclusion — Feminine Terms Absent",
            "severity": "MEDIUM",
            "detail": "Only masculine terms used. Content may exclude or ignore women.",
            "masculine_count": masc,
            "feminine_count": 0,
            "framework_ref": "NIST AI RMF — GOVERN 6.1 fairness"
        })
    elif fem > 0 and masc == 0 and fem >= 3:
        flags.append({
            "bias_type": "Gender Exclusion — Masculine Terms Absent",
            "severity": "LOW",
            "detail": "Only feminine terms used.",
            "masculine_count": 0,
            "feminine_count": fem,
            "framework_ref": "NIST AI RMF — GOVERN 6.1 fairness"
        })

    return flags


def _check_socioeconomic_bias(counts: Dict, text: str) -> List[Dict]:
    """
    Check if the text associates negative loaded words with underprivileged groups
    or positive words only with affluent groups — a key fairness concern in
    financial AI systems (credit scoring, loan recommendations).
    """
    flags = []
    text_lower = text.lower()
    socio = counts.get("socioeconomic", {})

    affluent_count = socio.get("affluent", 0)
    underprivileged_count = socio.get("underprivileged", 0)

   
    for term in DEMOGRAPHIC_TERMS["socioeconomic"]["underprivileged"]:
        if term.lower() in text_lower:
            for neg_word in NEGATIVE_LOADED:
                if neg_word in text_lower:
                    flags.append({
                        "bias_type": "Socioeconomic Stereotype",
                        "severity": "HIGH",
                        "detail": f"Negative term '{neg_word}' appears in text with underprivileged group reference '{term}'. Potential harmful association.",
                        "framework_ref": "RBI FREE-AI — Fairness; Equal Credit Opportunity"
                    })
                    break 

    return flags


def _check_religious_balance(counts: Dict) -> List[Dict]:
    """
    Check if content mentions some religious groups but not others,
    which can create biased perceptions in financial contexts.
    """
    flags = []
    religion_counts = counts.get("religion", {})
    mentioned = {k: v for k, v in religion_counts.items() if v > 0}

    if len(mentioned) == 1:
        group = list(mentioned.keys())[0]
        flags.append({
            "bias_type": "Single Religion Mentioned",
            "severity": "LOW",
            "detail": f"Only '{group}' religious terms found. If advice is religion-specific, ensure it's labelled as such.",
            "framework_ref": "NIST AI RMF — Fairness (MAP 5.1)"
        })

    return flags


def run_bias_check(
    query: str,
    retrieved_chunks: List[str],
    generated_answer: str
) -> Dict[str, Any]:
    """
    Main entry point for Module 3.
    
    Runs bias analysis on retrieved chunks combined and on generated answer.
    Chunk analysis catches RETRIEVAL BIAS (knowledge base level).
    Answer analysis catches OUTPUT BIAS (generation level).
    Both must be clean for the pipeline to be considered unbiased.
    """
    combined_chunks = " ".join(retrieved_chunks)

   
    chunk_counts = _count_demographic_terms(combined_chunks)
    chunk_flags = []
    chunk_flags += _check_gender_imbalance(chunk_counts)
    chunk_flags += _check_socioeconomic_bias(chunk_counts, combined_chunks)
    chunk_flags += _check_religious_balance(chunk_counts)

    
    answer_counts = _count_demographic_terms(generated_answer)
    answer_flags = []
    answer_flags += _check_gender_imbalance(answer_counts)
    answer_flags += _check_socioeconomic_bias(answer_counts, generated_answer)
    answer_flags += _check_religious_balance(answer_counts)

    all_flags = chunk_flags + answer_flags
    severities = [f["severity"] for f in all_flags]

    risk_level = _risk_level(severities)
    status = "FAIL" if "HIGH" in severities else ("WARN" if all_flags else "PASS")

    return {
        "module": "Bias Flagging",
        "status": status,
        "risk_level": risk_level,
        "total_flags": len(all_flags),
        "retrieval_bias_flags": chunk_flags,
        "output_bias_flags": answer_flags,
        "demographic_counts": {
            "in_chunks": chunk_counts,
            "in_answer": answer_counts
        },
        "summary": _build_summary(all_flags, status),
        "recommendation": _build_recommendation(status, all_flags),
        "framework_mappings": [
            "RBI FREE-AI — Fairness pillar",
            "EU AI Act Article 10 — non-discrimination requirement",
            "NIST AI RMF — GOVERN 6.1: bias monitored and mitigated",
            "Equal Credit Opportunity Act (ECOA) — US reference",
            "ISO/IEC TR 24027 — Bias in AI systems and AI-aided decision making"
        ],
        "known_limitation": (
            "This is heuristic-based bias detection. For production financial AI, "
            "use statistical fairness metrics (Demographic Parity, Equalized Odds) "
            "via tools like IBM AI Fairness 360 or Microsoft Fairlearn."
        )
    }


def _risk_level(severities: List[str]) -> str:
    if "HIGH" in severities:
        return "HIGH"
    elif "MEDIUM" in severities:
        return "MEDIUM"
    elif "LOW" in severities:
        return "LOW"
    return "NONE"


def _build_summary(flags: List[Dict], status: str) -> str:
    if not flags:
        return "No significant bias indicators detected in retrieved chunks or generated answer."
    flag_types = [f["bias_type"] for f in flags]
    return f"{len(flags)} bias indicator(s) detected: {', '.join(set(flag_types))}"


def _build_recommendation(status: str, flags: List[Dict]) -> str:
    if status == "PASS":
        return "No bias action required for this query."
    high_flags = [f for f in flags if f["severity"] == "HIGH"]
    if high_flags:
        return (
            "HIGH severity bias detected. Review content before deployment. "
            "Consider adding demographic balance guidelines to your retrieval prompt. "
            "For financial AI, consult RBI FREE-AI Fairness guidelines."
        )
    return (
        "Low-to-medium bias indicators found. Monitor patterns across multiple queries. "
        "If pattern persists, review knowledge base for demographic imbalance."
    )
