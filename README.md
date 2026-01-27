# CodeRisk AI

**CodeRisk AI** is a **probabilistic security scoring framework for AI-generated code**.

It produces an **overall risk score** plus a **risk breakdown** across:
- **OWASP-style categories** (e.g., injection, broken access control, insecure design)
- **CVSS-inspired severity dimensions** (impact, exploitability)
- **Behavioral risk signals** unique to AI-generated code (non-determinism sensitivity, hallucination markers, dependency volatility)

> Goal: help teams **measure and govern** risk in code produced by copilots and LLMs — not just scan it.

---

## Why this exists

Traditional static analysis answers: “Is there a known issue here?”

AI-generated code introduces additional failure modes:
- **Plausible-but-wrong logic** that passes review at a glance
- **Inconsistent behavior** under small prompt or context changes
- **Invented APIs / phantom dependencies**
- **Risky defaults** (weak validation, permissive parsing, unsafe deserialization)

CodeRisk AI is designed to quantify these risks in a way that is:
- **bounded**
- **auditable**
- **repeatable**
- **suitable for governance and security review**

---

## What it outputs

**Example (target output format)**

```json
{
  "overall_score": 7.2,
  "confidence": 0.68,
  "owasp": {
    "A03_injection": 8.1,
    "A01_broken_access_control": 5.4,
    "A06_vulnerable_dependencies": 6.4
  },
  "behavioral": {
    "hallucination_risk": "high",
    "nondeterminism_sensitivity": "medium",
    "dependency_volatility": "medium"
  },
  "findings": [
    {
      "id": "INJECTION.SQL.STRING_CONCAT",
      "severity": "high",
      "evidence": "Detected string concatenation into SQL query",
      "location": { "file": "example.py", "line_start": 42, "line_end": 44 }
    }
  ]
}
