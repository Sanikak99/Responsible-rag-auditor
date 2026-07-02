import re
from typing import List, Dict, Any, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np


def _split_into_sentences(text: str) -> List[str]:
    """Split text into individual sentences for granular groundedness checking."""
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    return [s.strip() for s in sentences if len(s.strip()) > 10]


def _compute_groundedness_tfidf(
    sentences: List[str],
    chunks: List[str],
    threshold: float
) -> List[Dict]:
    """
    Compute groundedness for all sentences using TF-IDF cosine similarity.

    We fit the TF-IDF vectoriser on chunks + sentences together so both
    share the same vocabulary space — required for valid comparison.
    """
    all_texts = chunks + sentences

  
    vectorizer = TfidfVectorizer(
        stop_words='english',   
        ngram_range=(1, 2),     
        min_df=1                
    )
    tfidf_matrix = vectorizer.fit_transform(all_texts)

    
    chunk_vectors    = tfidf_matrix[:len(chunks)]
    sentence_vectors = tfidf_matrix[len(chunks):]

    results = []
    for i, sentence in enumerate(sentences):
        sent_vec = sentence_vectors[i]
        sims = cosine_similarity(sent_vec, chunk_vectors)[0]
        max_score      = float(np.max(sims))
        best_chunk_idx = int(np.argmax(sims))
        is_grounded    = max_score >= threshold

        results.append({
            "sentence": sentence,
            "groundedness_score": round(max_score, 4),
            "verdict": "GROUNDED" if is_grounded else "HALLUCINATED",
            "best_matching_chunk": best_chunk_idx,
            "threshold_used": threshold,
            "explanation": _explain_score(max_score, threshold)
        })

    return results


def _explain_score(score: float, threshold: float) -> str:
    if score >= 0.6:
        return "Strongly supported — high word overlap with retrieved context."
    elif score >= threshold:
        return "Sufficiently supported by retrieved context."
    elif score >= 0.1:
        return "Weak overlap — possibly paraphrased from model memory."
    else:
        return "No meaningful overlap with retrieved chunks — likely hallucinated."


def run_groundedness_check(
    query: str,
    retrieved_chunks: List[str],
    generated_answer: str,
    threshold: float = 0.15
) -> Dict[str, Any]:
    """
    Main entry point for Module 2.

    NOTE ON THRESHOLD:
    TF-IDF scores are generally lower than neural embedding scores because
    TF-IDF only counts exact word matches, not semantic similarity.
    So we use 0.15 as default (vs 0.35 for neural embeddings).
    A score of 0.15 with TF-IDF still means meaningful word overlap.
    """
    if not retrieved_chunks:
        return {"module": "Groundedness / Hallucination Check",
                "status": "ERROR", "summary": "No retrieved chunks provided."}

    if not generated_answer.strip():
        return {"module": "Groundedness / Hallucination Check",
                "status": "ERROR", "summary": "Generated answer is empty."}

    sentences = _split_into_sentences(generated_answer)
    if not sentences:
        return {"module": "Groundedness / Hallucination Check",
                "status": "ERROR", "summary": "Could not parse sentences from answer."}

    sentence_results  = _compute_groundedness_tfidf(sentences, retrieved_chunks, threshold)
    hallucinated      = sum(1 for s in sentence_results if s["verdict"] == "HALLUCINATED")
    total             = len(sentence_results)
    grounded          = total - hallucinated
    overall_score     = round(grounded / total, 4) if total > 0 else 0.0

    status = "PASS" if hallucinated == 0 else ("PARTIAL" if hallucinated / total <= 0.5 else "FAIL")

    return {
        "module": "Groundedness / Hallucination Check",
        "status": status,
        "overall_groundedness_score": overall_score,
        "score_percent": f"{round(overall_score * 100)}%",
        "threshold": threshold,
        "method": "TF-IDF cosine similarity (production upgrade: sentence-transformers)",
        "total_sentences": total,
        "grounded_sentences": grounded,
        "hallucinated_sentences": hallucinated,
        "sentence_results": sentence_results,
        "summary": (
            f"All {total} sentence(s) grounded." if hallucinated == 0
            else f"{hallucinated}/{total} sentence(s) not supported by retrieved context — possible hallucination."
        ),
        "recommendation": (
            "Answer is fully grounded. Safe to display." if status == "PASS"
            else f"{hallucinated} sentence(s) flagged as potentially hallucinated. Review before displaying."
        ),
        "framework_mappings": [
            "NIST AI RMF — MEASURE 2.5: AI performance monitored",
            "RBI FREE-AI — Reliability pillar",
            "EU AI Act Article 13 — Transparency & traceability",
            "ISO/IEC 42001 — AI output verification"
        ]
    }
