# Responsible RAG Auditor 🔍

A **pipeline-agnostic AI governance tool** that audits any RAG (Retrieval Augmented Generation) system for safety, privacy, and compliance risks across 5 dimensions — in real time.

Built to demonstrate practical implementation of **NIST AI RMF**, **RBI FREE-AI**, **EU AI Act**, **DPDP Act 2023**, and **OWASP LLM Top 10** principles.

---

## What It Does

Any RAG pipeline produces 3 things: a **query**, **retrieved chunks**, and a **generated answer**.  
You send these 3 things to the auditor. It runs 5 checks and returns a governance report.

```
Your RAG Pipeline (Vidya AI / FinBot / any system)
        ↓  query + retrieved chunks + generated answer
Responsible RAG Auditor
        ↓
5-Module Governance Report + Risk Score (0–100) + Audit Trail
```

---

## 5 Audit Modules

| Module | What It Checks | Framework |
|--------|---------------|-----------|
| 🔒 Prompt Injection Detection | Malicious instructions in query/chunks | OWASP LLM Top 10 — LLM01 |
| 🔍 PII Detection | Emails, Aadhaar, PAN, phone in chunks/answer | DPDP Act 2023, RBI Guidelines |
| 🧠 Groundedness Check | Is each answer sentence supported by retrieved context? | NIST AI RMF — MEASURE 2.5 |
| ⚖️ Bias Flagging | Gender, socioeconomic, religious bias indicators | EU AI Act Article 10, RBI FREE-AI |
| 📋 Audit Trail | Tamper-evident SHA-256 log of every decision | EU AI Act Article 12, ISO 27001 |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, FastAPI, Uvicorn |
| Audit Engine | scikit-learn (TF-IDF), regex, SQLite |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| API Docs | Swagger UI (auto-generated at /docs) |

---

## Project Structure

```
responsible-rag-auditor/
├── backend/
│   ├── main.py                          # FastAPI app — all endpoints
│   ├── requirements.txt                 # Python dependencies
│   └── modules/
│       ├── pii_detector.py              # Module 1 — PII scanning
│       ├── groundedness_checker.py      # Module 2 — Hallucination detection
│       ├── bias_flagger.py              # Module 3 — Bias analysis
│       ├── audit_logger.py              # Module 4 — SQLite audit trail
│       └── prompt_injection_detector.py # Module 5 — Input safety
├── frontend/
│   └── index.html                       # Dashboard (HTML/CSS/JS)
├── run.sh                               # One-command startup script
└── README.md
```

---

## Sample Input / Output

### Input — paste these 3 things into the dashboard

**Query:**
```
What is Newton's second law of motion?
```

**Retrieved Chunk:**
```
Newton's second law of motion states that the force acting on an object
is equal to the mass of the object multiplied by its acceleration.
Mathematically expressed as F = ma, where F is force in Newtons,
m is mass in kilograms, and a is acceleration in metres per second squared.
```

**Generated Answer (deliberately bad — hallucination + PII):**
```
Newton's second law states F=ma. This law was discovered by Einstein in 1905
and is used by NASA for rocket propulsion. Contact us at test@example.com
or call 9876543210 for more information.
```

---

### Output — what the auditor returns

```json
{
  "overall_status": "FAIL",
  "overall_risk_score": 52,
  "modules": {
    "prompt_injection": { "status": "PASS" },
    "pii": {
      "status": "FAIL",
      "risk_level": "HIGH",
      "summary": "Generated answer exposes Email Address, Indian Mobile Number — HIGHEST RISK"
    },
    "groundedness": {
      "status": "FAIL",
      "score_percent": "25%",
      "summary": "3/4 sentences not supported by retrieved context — possible hallucination",
      "sentence_results": [
        { "sentence": "Newton's second law states F=ma.", "verdict": "GROUNDED", "score": 0.82 },
        { "sentence": "This law was discovered by Einstein in 1905.", "verdict": "HALLUCINATED", "score": 0.04 },
        { "sentence": "It is used by NASA for rocket propulsion.", "verdict": "HALLUCINATED", "score": 0.02 },
        { "sentence": "Contact us at test@example.com", "verdict": "HALLUCINATED", "score": 0.00 }
      ]
    },
    "bias": { "status": "PASS" },
    "audit_trail": {
      "audit_id": "55293b1a-ff16-44c3-b4e7-270d18795ab8",
      "content_hash": "b4e7270d18795ab8c3f...",
      "timestamp_utc": "2025-07-03T10:42:31.004Z"
    }
  }
}
```

**What the dashboard flags:**
- 🔴 PII FAIL — email + phone detected in generated answer
- 🔴 Groundedness FAIL — 3/4 sentences hallucinated (Einstein 1905, NASA, contact info)
- ✅ Prompt Injection PASS — no malicious patterns in query
- ✅ Bias PASS — no demographic bias indicators
- 📋 Audit Trail — record saved with SHA-256 hash for tamper detection

---

## How to Run Locally

### Step 1 — Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/responsible-rag-auditor.git
cd responsible-rag-auditor
```

### Step 2 — Install dependencies
```bash
pip install -r backend/requirements.txt
```

### Step 3 — Activate virtual environment
```powershell
# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### Step 4 — Start the server
```powershell
# Windows
cd backend
python -m uvicorn main:app --reload

# Mac/Linux
cd backend
uvicorn main:app --reload
```

### Step 5 — Open the dashboard
````
http://localhost:8000
```
---

## API Usage (Pipeline Integration)

Any RAG pipeline can call the auditor via a single POST request:

```python
import requests

result = requests.post("http://localhost:8000/audit", json={
    "query": "What is Newton's second law?",
    "retrieved_chunks": [
        "Force equals mass times acceleration. F=ma."
    ],
    "generated_answer": "Newton's second law states F=ma.",
    "pipeline_name": "Vidya AI",
    "model_version": "llama-3.3-70b"
})

print(result.json()["overall_risk_score"])   # 0-100
print(result.json()["overall_status"])        # PASS / WARN / FAIL
```

### Sample Response
```json
{
  "audit_id": "55293b1a-ff16-44c3-...",
  "overall_status": "WARN",
  "overall_risk_score": 38,
  "content_hash": "b4e7270d18795ab8...",
  "processing_time_ms": 142.5,
  "modules": {
    "prompt_injection": { "status": "PASS" },
    "pii": { "status": "FAIL", "risk_level": "HIGH" },
    "groundedness": { "status": "FAIL", "score_percent": "25%" },
    "bias": { "status": "PASS" },
    "audit_trail": { "audit_id": "...", "content_hash": "..." }
  }
}
```

---

## Risk Scoring

| Score | Status | Meaning |
|-------|--------|---------|
| 0–15 | ✅ PASS | No significant governance risks |
| 16–40 | ⚠️ WARN | Some concerns, review recommended |
| 41–100 | ❌ FAIL | Critical violations, do not deploy |

---

## Governance Framework Mappings

| Check | NIST AI RMF | RBI FREE-AI | EU AI Act | India Law |
|-------|------------|-------------|-----------|-----------|
| PII Detection | Privacy (MANAGE 2.2) | Ethics | Article 10 | DPDP Act 2023 |
| Groundedness | MEASURE 2.5 | Reliability | Article 13 | — |
| Bias Flagging | GOVERN 6.1 | Fairness | Article 10 | — |
| Audit Trail | GOVERN 1.7 | Accountability | Article 12 | DPDP Act 2023 |
| Injection Detection | MANAGE 2.2 | Ethics | Article 15 | IT Act 2000 |

---

## Author

**Sanika Kamble**  
B.Tech CSE (AI/ML) | PG Diploma in Applied Data Science & AI — IIT Roorkee  
IEEE Published Researcher (STPEC 2025, NIT Goa)

- GitHub: [Sanikak99](https://github.com/Sanikak99)
- LinkedIn: [sanika-kamble](https://linkedin.com/in/sanika-kamble-53375522a)
- Portfolio: [sanika-k99.figweb.site](https://sanika-k99.figweb.site)
- Email: sanikaprasadkamble@gmail.com