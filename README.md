# CodeRisk AI

CodeRisk AI is a probabilistic security scoring framework for AI-generated code.

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

AI-generated code introduces systemic risk patterns that don't behave like traditional vulnerabilities:

- **Plausible-looking logic** that is subtly incorrect
- **Inconsistent behavior** under small prompt or context changes
- **Invented APIs or phantom dependencies**
- **Unsafe defaults** (permissive access, weak validation, unsafe deserialization)
- **Security checks** commented out or partially removed

These risks are often **probabilistic, context-dependent, and non-deterministic**.

CodeRisk AI exists to quantify that uncertainty in a way that is:

- **bounded** (scores always live in known ranges)
- **explainable** (every score maps to evidence)
- **auditable** (deterministic analysis first)
- **repeatable** (designed for governance, not demos)

---

## What CodeRisk AI does today

### ✔ Deterministic analysis first

CodeRisk AI performs file- and directory-level analysis for **Python code**, detecting security issues aligned to the **OWASP Top 10**.

Examples include:

#### **A01 – Broken Access Control**

- Missing authentication decorators
- Disabled or commented-out authorization checks

#### **A03 – Injection**

- SQL query construction via string concatenation or interpolation

#### **A08 – Software and Data Integrity Failures**

- Unsafe deserialization (e.g., `pickle.loads` on untrusted input)

#### **A09 – Security Logging & Monitoring Failures**

- Swallowed exceptions
- Fallback behavior without telemetry

Each detector emits **structured findings** with:

- stable rule IDs
- severity and confidence
- evidence (file, line, snippet)
- CWE and OWASP references

### ✔ Probabilistic scoring model

Findings are aggregated into:

- **OWASP category scores** (0–10)
- a **composite overall risk score**
- a **confidence score** representing stability, not correctness

The scoring model explicitly separates:

- **impact**
- **exploitability**
- **uncertainty**

This avoids the common failure mode of treating vulnerability counts as "risk."

### ✔ AI-specific behavioral signals (early scaffolding)

CodeRisk AI also emits **AI-specific risk signals**.  
In v0.1 these are structurally complete but intentionally conservative:

- Hallucination markers
- Non-determinism sensitivity
- Dependency volatility

These signals will mature as the framework evolves, but are already integrated into the output schema to support future governance workflows.

---

## Example

```bash
coderisk analyze examples/ --pretty
```

Produces output similar to:

```json
{
  "summary": {
    "overall_score": 7.0,
    "confidence": 0.7,
    "owasp": {
      "A01_access_control": 6.5,
      "A03_injection": 4.8
    }
  }
}
```

---

## Design philosophy

### **Deterministic before probabilistic**

All findings are rule-based, auditable, and reproducible.

### **Confidence ≠ severity**

A severe issue may still have low confidence, and vice versa.

### **AI as an advisor, not an authority**

Language models never invent findings or silently modify code.

### **Governance over automation theater**

Outputs are designed for review, risk acceptance, and audit trails.

---

## Roadmap

CodeRisk AI is intentionally phased, with each stage adding capability without breaking governance guarantees or weakening auditability.

### **Phase 1 – Python Scan (current)**

**Focus**: establish a trustworthy analytical core.

- Python-only support
- Deterministic OWASP Top 10 detectors
- Stable scoring model and output schema
- Clear separation of findings, scores, and confidence
- Reference corpora:
  - intentionally vulnerable examples
  - hardened "safe" implementations

**Status**:

- ✔ In active development
- ✔ Scoring and schema stabilizing
- ✔ Suitable as a research artifact and CLI tool

### **Phase 2 – LLM-Assisted Explanation (Advisory Only)**

**Focus**: help humans understand why a finding exists — without changing what was found.

In this phase, an optional LLM advisory layer is introduced **after deterministic analysis completes**.

The LLM is used to:

- Explain what the issue is in plain language
- Describe why it matters from a security perspective
- Walk through how it could realistically be exploited
- Clarify assumptions and context that make the issue risky
- Highlight tradeoffs in remediation options

**Critically**:

- The LLM **does not generate findings**
- The LLM **does not change scores**
- The LLM **does not modify code**
- All explanations are grounded in existing structured findings

Think of this phase as:

> "Translate the evidence into human reasoning — without adding new evidence."

This preserves auditability while reducing cognitive load during review.

### **Phase 3 – User Interface**

**Focus**: make risk inspectable, not just machine-readable.

- Local web UI for browsing results
- Visual OWASP breakdowns
- Drill-down from score → category → finding → evidence
- Explicit confidence and uncertainty display

Designed for:

- security reviews
- engineering discussions
- risk acceptance documentation

**No auto-fixing. No magic buttons.**

### **Phase 4 – JavaScript / TypeScript Support**

**Focus**: extend the model without changing its semantics.

- Node.js and Express backends
- Frontend-to-backend boundary risks
- Injection, auth, deserialization, and configuration patterns
- Same scoring model
- Same confidence semantics
- Same output schema

**Key constraint**:  
Multi-language support must feel **boring and consistent**, not flashy.

### **Phase 4a – VS Code Extension**

**Focus**: bring visibility closer to where AI-generated code is written.

- On-save or on-demand analysis
- Inline annotations tied to CodeRisk findings
- OWASP category summaries per file

**Hard constraints**:

- **No background code modification**
- **No autonomous execution**

The extension **observes and reports** — it does not act.

### **Phase 5 – GitHub Action**

**Focus**: governance at the pipeline level.

- Run CodeRisk AI in CI
- Produce structured artifacts (JSON, SARIF-style)
- Fail or warn based on policy thresholds

Support:

- pull request reviews
- risk gating
- audit trails

**This is not security theater CI.**  
It is a measurement checkpoint.

---

## Non-goals

CodeRisk AI is **not** intended to:

- replace expert security review
- auto-patch code without approval
- claim vulnerability completeness
- act as a generic "AI code fixer"

**It is a measurement and decision-support system.**

---

## Status

CodeRisk AI is under active development and intended as:

- a **practical security tool**
- a **research artifact**
- and a **reference implementation** for governing AI-generated code
