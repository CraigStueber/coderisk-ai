# CodeRisk AI

**CodeRisk AI** is a **probabilistic security scoring framework for AI-generated code**.

It analyzes code produced by copilots and large language models and produces:

- a **composite security risk score**
- a **confidence estimate** describing score stability
- a **breakdown across OWASP Top 10 categories**
- **CVSS-inspired impact and exploitability signals**
- **AI-specific behavioral risk indicators** (e.g., non-determinism sensitivity, unsafe defaults)

> **Goal**: help teams **measure, reason about, and govern** risk in AI-generated code — not just scan it.

---

## Why this exists

Traditional static analysis answers a narrow question:

> "Is there a known vulnerability here?"

AI-generated code introduces additional, systemic risks that are harder to reason about:

- **Plausible-looking logic** that is subtly incorrect
- **Inconsistent behavior** under small prompt or context changes
- **Invented APIs or phantom dependencies**
- **Unsafe defaults** (permissive access, weak validation, unsafe deserialization)
- **Security-critical checks** commented out or partially removed

These risks are often **not binary** and **not deterministic**.

CodeRisk AI is designed to quantify this uncertainty in a way that is:

- **bounded** (scores are always within known limits)
- **explainable** (every score is traceable to findings)
- **auditable** (deterministic analysis first, AI second)
- **repeatable** (designed for governance and review workflows)

---

## What CodeRisk AI does today (v0.1)

### ✔️ Deterministic analysis first

CodeRisk AI currently performs file- and directory-level analysis for **Python code** and detects security issues aligned to the **OWASP Top 10**, including:

#### **A01 – Broken Access Control**

- Missing authentication decorators (Flask/FastAPI)
- Commented-out authorization checks

#### **A03 – Injection**

- SQL query construction via string concatenation

#### **A08 – Software and Data Integrity Failures**

- Unsafe deserialization (e.g., `pickle.loads` on untrusted input)

Each detector produces **structured findings** with:

- stable IDs
- severity
- evidence (file, line, snippet)
- CWE and OWASP references
- confidence estimates

### ✔️ Probabilistic scoring model

Findings are aggregated into:

- **OWASP category scores** (capped at 10)
- a **composite overall risk score**
- a **confidence score** representing stability, not correctness

The scoring model explicitly separates:

- **impact**
- **exploitability**
- **uncertainty**

This avoids the common failure mode of treating vulnerability counts as risk.

### ✔️ Behavioral risk signals (v0.1 stubs)

CodeRisk AI also emits **AI-specific risk signals**, currently stubbed but structurally complete:

- Hallucination markers
- Non-determinism sensitivity
- Dependency volatility

These signals will be expanded as the framework evolves.

---

## Example

```bash
coderisk analyze examples/ --pretty
```

Produces output similar to:

```json
{
  "summary": {
    "overall_score": 10.0,
    "confidence": 0.7,
    "owasp": {
      "A01_access_control": 10.0,
      "A03_injection": 4.8,
      "A08_integrity_failures": 5.04
    }
  },
  "findings": [
    {
      "id": "ACCESS_CONTROL.MISSING.FLASK_AUTH",
      "severity": "medium",
      "category": "A01_access_control",
      "evidence": {
        "file": "examples/broken_access_control.py",
        "line_start": 13,
        "snippet": "@app.route(\"/users/<int:user_id>/delete\")"
      }
    }
  ]
}
```

---

## Design philosophy

CodeRisk AI intentionally follows these principles:

### **Deterministic before probabilistic**

Core analysis and scoring are rule-based and auditable.

### **Confidence ≠ severity**

A severe issue can still have low confidence, and vice versa.

### **AI as an advisor, not an authority**

Language models are not allowed to invent findings or silently modify code.

### **Governance over automation theater**

The output is designed for security review, risk acceptance, and audit trails.

---

## Roadmap (intentional and phased)

### **Phase 1 (current): Python + OWASP Top 10**

- Complete Python detectors for all OWASP Top 10 categories
- Stabilize scoring and output schema
- Establish baseline confidence and uncertainty handling

### **Phase 2: AI-assisted explanation and remediation guidance**

After deterministic analysis is complete, CodeRisk AI will introduce an **optional AI advisory layer**:

#### **AI explains the issue**

- Why it matters
- How it could be exploited
- What assumptions make it risky

#### **AI suggests remediation options**

- Secure patterns
- Framework-specific guidance
- Tradeoffs and caveats

**Critically**:

- The AI **does not generate findings**
- The AI **does not silently change code**
- All advice is grounded in the existing, structured analysis output

This keeps humans firmly in the loop.

### **Phase 3: Multi-language support**

Once the Python OWASP Top 10 baseline is complete, CodeRisk AI will expand to:

#### **JavaScript / TypeScript**

- Node.js, Express, frontend-to-backend boundaries

#### **Java**

- Spring security, serialization, configuration risks

Each language will follow the same model:

- deterministic detectors first
- consistent scoring semantics
- shared governance-friendly output schema

---

## Non-goals

CodeRisk AI is **not** intended to:

- replace expert security review
- auto-patch code without human approval
- claim vulnerability completeness
- act as a generic "AI code fixer"

**It is a measurement and decision-support system.**

---

## Status

This project is under active development and is intended as:

- a **practical security tool**
- a **research artifact**
- and a **reference implementation** for governing AI-generated code
