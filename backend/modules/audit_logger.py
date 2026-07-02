"""
Module 4: Audit Trail / Audit Logger
=====================================
Creates and maintains an immutable, queryable log of every audit event.
Every time the auditor runs, a complete record is stored in SQLite.

WHY AUDIT TRAILS MATTER (Interview core concept):
  In regulated industries (banking, healthcare, finance), every AI decision
  must be traceable. If a loan is denied by an AI or a student gets wrong
  information from an AI tutor, regulators can ask:
  - What was the exact query?
  - What documents did the system retrieve?
  - What did the model say?
  - Were any risks flagged at the time?
  - Who or what was responsible?

  Without an audit trail, you CANNOT answer these questions.
  This is called "AI accountability" — one of the 6 pillars of responsible AI.

IMMUTABILITY (Critical concept):
  We INSERT records but NEVER UPDATE or DELETE them.
  This is the "append-only" pattern. Even if an audit has an error,
  we add a CORRECTION record, not modify the original.
  Why? Because if records can be modified, they can be falsified.
  A trustworthy audit trail is one where the past cannot be changed.

  In production: use a WORM (Write Once Read Many) storage system,
  or a blockchain-based ledger for tamper-evident audit trails.
  AWS QLDB (Quantum Ledger Database) is designed exactly for this.

DATABASE CHOICE — Why SQLite?
  - Zero infrastructure: no server needed, just a file
  - Perfect for development and demos
  - ACID compliant (Atomicity, Consistency, Isolation, Durability) —
    guarantees that each write either fully completes or fully fails
  - In production: replace with PostgreSQL + append-only table policy,
    or a dedicated audit log service

FRAMEWORK MAPPINGS:
  - NIST AI RMF — GOVERN 1.7: Processes for audit and accountability
  - RBI FREE-AI — Accountability & Transparency pillars
  - EU AI Act Article 12 — Record-keeping for high-risk AI systems
  - DPDP Act 2023 — Data fiduciaries must maintain processing records
  - ISO 27001 — A.12.4: Logging and monitoring
"""

import sqlite3
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path

# Database file location
# In production this path would come from environment config
DB_PATH = Path(__file__).parent.parent / "audit_log.db"


def _get_connection() -> sqlite3.Connection:
    """
    Get a database connection with WAL mode enabled.
    WAL = Write-Ahead Logging: allows concurrent reads during writes.
    This is important for audit logs which may be read while being written.
    """
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # Returns rows as dict-like objects
    conn.execute("PRAGMA journal_mode=WAL")  # Enable WAL mode
    conn.execute("PRAGMA foreign_keys=ON")   # Enforce referential integrity
    return conn


def initialise_db() -> None:
    """
    Create the audit tables if they don't exist.
    Called once when the FastAPI server starts.
    
    TABLE DESIGN DECISIONS:
    - audit_id: UUID (universally unique — can merge logs from multiple systems)
    - timestamp_utc: Always UTC (never local time — avoids timezone ambiguity)
    - content_hash: SHA-256 of the full audit record — tamper detection
      If someone modifies a row, the hash won't match anymore.
    - raw_results: Full JSON stored as text — preserves complete context
    - risk_score: Computed 0-100 score for quick filtering/querying
    """
    conn = _get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id        TEXT PRIMARY KEY,
            timestamp_utc   TEXT NOT NULL,
            session_id      TEXT,
            query           TEXT NOT NULL,
            retrieved_chunks TEXT NOT NULL,      -- JSON array
            generated_answer TEXT NOT NULL,
            pii_status      TEXT,
            pii_risk_level  TEXT,
            groundedness_score REAL,
            groundedness_status TEXT,
            bias_status     TEXT,
            bias_risk_level TEXT,
            injection_status TEXT,
            injection_risk_level TEXT,
            overall_risk_score INTEGER,
            overall_status  TEXT,
            raw_results     TEXT NOT NULL,       -- Full JSON of all module outputs
            content_hash    TEXT NOT NULL,       -- SHA-256 tamper detection
            model_version   TEXT DEFAULT 'unknown',
            pipeline_name   TEXT DEFAULT 'unknown'
        )
    """)
    conn.commit()
    conn.close()


def _compute_hash(data: Dict) -> str:
    """
    Compute SHA-256 hash of the audit record for tamper detection.

    INTERVIEW EXPLANATION of SHA-256:
    SHA-256 is a cryptographic hash function that converts any input
    into a fixed 64-character string. Two different inputs NEVER produce
    the same hash (collision resistance). If even one character of the
    audit record changes, the hash changes completely. So by storing the
    hash alongside the record, we can later verify the record hasn't
    been tampered with. This is the same mechanism used in blockchain.
    """
    serialised = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()


def _compute_overall_risk_score(results: Dict[str, Any]) -> int:
    """
    Compute a 0-100 overall risk score from all module results.
    Lower = safer. 0 = perfect, 100 = extremely risky.

    SCORING LOGIC:
    - Starts at 0 (clean)
    - PII detected: +30 (CRITICAL: +30, HIGH: +20, MEDIUM: +10)
    - Hallucination: penalty based on % hallucinated sentences × 25
    - Bias detected: HIGH: +20, MEDIUM: +10, LOW: +5
    - Prompt injection: detected: +25

    This weighted scoring is a simplified version of how risk scoring
    works in enterprise AI governance platforms like IBM OpenScale.
    """
    score = 0

    # PII penalty
    pii = results.get("pii", {})
    pii_severity_map = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "NONE": 0}
    score += pii_severity_map.get(pii.get("risk_level", "NONE"), 0)

    # Groundedness penalty
    ground = results.get("groundedness", {})
    hallucinated = ground.get("hallucinated_sentences", 0)
    total = ground.get("total_sentences", 1)
    if total > 0:
        score += int((hallucinated / total) * 25)

    # Bias penalty
    bias = results.get("bias", {})
    bias_severity_map = {"HIGH": 20, "MEDIUM": 10, "LOW": 5, "NONE": 0}
    score += bias_severity_map.get(bias.get("risk_level", "NONE"), 0)

    # Injection penalty
    injection = results.get("prompt_injection", {})
    inj_severity_map = {"HIGH": 25, "MEDIUM": 15, "LOW": 5, "NONE": 0}
    score += inj_severity_map.get(injection.get("risk_level", "NONE"), 0)

    return min(score, 100)  # Cap at 100


def _determine_overall_status(risk_score: int) -> str:
    """
    Map numeric risk score to a traffic-light status.
    Standard in enterprise risk management:
    GREEN (Pass) / AMBER (Warn) / RED (Fail)
    """
    if risk_score <= 15:
        return "PASS"
    elif risk_score <= 40:
        return "WARN"
    else:
        return "FAIL"


def log_audit(
    query: str,
    retrieved_chunks: List[str],
    generated_answer: str,
    module_results: Dict[str, Any],
    session_id: Optional[str] = None,
    model_version: str = "unknown",
    pipeline_name: str = "unknown"
) -> Dict[str, Any]:
    """
    Main entry point for Module 4.
    Creates a complete, tamper-evident audit record and stores it.
    Returns the audit record including its unique ID and hash.
    """
    audit_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    pii = module_results.get("pii", {})
    ground = module_results.get("groundedness", {})
    bias = module_results.get("bias", {})
    injection = module_results.get("prompt_injection", {})

    overall_risk_score = _compute_overall_risk_score(module_results)
    overall_status = _determine_overall_status(overall_risk_score)

    # Build the full record for hashing (before DB insert)
    record_data = {
        "audit_id": audit_id,
        "timestamp_utc": timestamp,
        "query": query,
        "retrieved_chunks": retrieved_chunks,
        "generated_answer": generated_answer,
        "overall_risk_score": overall_risk_score,
        "module_results": module_results
    }
    content_hash = _compute_hash(record_data)

    try:
        conn = _get_connection()
        conn.execute("""
            INSERT INTO audit_log (
                audit_id, timestamp_utc, session_id, query,
                retrieved_chunks, generated_answer,
                pii_status, pii_risk_level,
                groundedness_score, groundedness_status,
                bias_status, bias_risk_level,
                injection_status, injection_risk_level,
                overall_risk_score, overall_status,
                raw_results, content_hash,
                model_version, pipeline_name
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            audit_id,
            timestamp,
            session_id,
            query,
            json.dumps(retrieved_chunks),
            generated_answer,
            pii.get("status"),
            pii.get("risk_level"),
            ground.get("overall_groundedness_score"),
            ground.get("status"),
            bias.get("status"),
            bias.get("risk_level"),
            injection.get("status"),
            injection.get("risk_level"),
            overall_risk_score,
            overall_status,
            json.dumps(module_results, default=str),
            content_hash,
            model_version,
            pipeline_name
        ))
        conn.commit()
        conn.close()
        db_error = None
    except Exception as e:
        db_error = str(e)

    return {
        "module": "Audit Trail",
        "audit_id": audit_id,
        "timestamp_utc": timestamp,
        "overall_risk_score": overall_risk_score,
        "overall_status": overall_status,
        "status": overall_status,
        "content_hash": content_hash,
        "db_error": db_error,
        "summary": (
            f"Audit record {audit_id} saved. "
            f"Overall risk score: {overall_risk_score}/100. "
            f"Status: {overall_status}."
        ),
        "framework_mappings": [
            "NIST AI RMF — GOVERN 1.7: Audit and accountability processes",
            "RBI FREE-AI — Accountability & Transparency pillars",
            "EU AI Act Article 12 — Record-keeping for high-risk AI",
            "DPDP Act 2023 — Data fiduciary processing records",
            "ISO 27001 A.12.4 — Logging and monitoring"
        ]
    }


def get_audit_history(limit: int = 50) -> List[Dict]:
    """Retrieve recent audit records for the dashboard history view."""
    try:
        conn = _get_connection()
        rows = conn.execute("""
            SELECT audit_id, timestamp_utc, query, overall_risk_score,
                   overall_status, pii_status, groundedness_status,
                   bias_status, injection_status, pipeline_name
            FROM audit_log
            ORDER BY timestamp_utc DESC
            LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []


def get_audit_by_id(audit_id: str) -> Optional[Dict]:
    """Retrieve a specific audit record by ID — for drill-down in dashboard."""
    try:
        conn = _get_connection()
        row = conn.execute(
            "SELECT * FROM audit_log WHERE audit_id = ?", (audit_id,)
        ).fetchone()
        conn.close()
        if row:
            result = dict(row)
            result["raw_results"] = json.loads(result["raw_results"])
            result["retrieved_chunks"] = json.loads(result["retrieved_chunks"])
            return result
        return None
    except Exception:
        return None


def clear_audit_history() -> Dict:
    """
    Delete all audit records from the database.

    DESIGN NOTE — Why allow deletion at all?
    In a real regulated system (RBI, banking) audit logs are IMMUTABLE
    and deletion would be prohibited. Logs must be retained for a defined
    period (RBI mandates 5 years for financial records).

    In our tool we allow it for demo/development purposes only.
    In production this endpoint would be:
    - Restricted to admin roles only (RBAC — Role Based Access Control)
    - Replaced with an 'archive' action, not a hard delete
    - Logged itself as a meta-audit event ("who deleted the logs and when")

    This is a great interview talking point — shows you understand the
    difference between dev convenience and production governance requirements.
    """
    try:
        conn = _get_connection()
        result = conn.execute("DELETE FROM audit_log")
        deleted_count = result.rowcount
        conn.commit()
        conn.close()
        return {
            "success": True,
            "deleted_count": deleted_count,
            "message": f"Cleared {deleted_count} audit record(s) successfully."
        }
    except Exception as e:
        return {
            "success": False,
            "deleted_count": 0,
            "message": f"Failed to clear history: {str(e)}"
        }


def delete_audit_by_id(audit_id: str) -> Dict:
    """
    Delete a single audit record by its UUID.

    DESIGN NOTE (Interview talking point):
    Deleting individual records is called 'selective deletion' or
    'targeted purge'. In real governance systems this is even more
    restricted than bulk deletion because:
    - Individual record deletion can be used to hide specific decisions
    - Regulators may require ALL records for a time period, not just some
    - Selective deletion breaks the chain of evidence

    In production this would require:
    - Admin role (RBAC)
    - A written justification logged separately
    - Approval from a second person (4-eyes principle)
    - The deletion event itself logged in a separate tamper-proof log

    For our demo tool we allow it freely — but knowing these constraints
    shows governance maturity in interviews.
    """
    try:
        conn = _get_connection()
        # First check if record exists
        row = conn.execute(
            "SELECT audit_id FROM audit_log WHERE audit_id = ?", (audit_id,)
        ).fetchone()

        if not row:
            conn.close()
            return {
                "success": False,
                "message": f"Record {audit_id} not found."
            }

        conn.execute("DELETE FROM audit_log WHERE audit_id = ?", (audit_id,))
        conn.commit()
        conn.close()
        return {
            "success": True,
            "message": f"Record {audit_id[:8]}... deleted successfully."
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to delete record: {str(e)}"
        }