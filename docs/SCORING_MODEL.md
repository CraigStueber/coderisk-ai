# CodeRisk AI — Scoring Model (v0.1)

This document defines how **CodeRisk AI** computes risk scores for AI-generated code.

The model is designed to:

- quantify **security risk**, not code quality
- remain **bounded, explainable, and auditable**
- explicitly account for **uncertainty introduced by probabilistic code generation**

---

## Core principles

### 1. Risk ≠ vulnerability count

A higher number of findings does not automatically imply higher risk.

Risk is modeled as a function of:

- **impact**
- **exploitability**
- **uncertainty**

---

### 2. AI-generated code introduces uncertainty by default

Unlike human-written code, AI-generated code:

- may vary across generations
- may include fabricated or partially correct logic
- may appear correct while failing under edge cases

Uncertainty is therefore treated as a **first-class risk factor**, not a footnote.

---

### 3. Scores are probabilistic, not absolute

All scores represent **risk estimates**, not ground truth.

The scoring model produces:

- a **composite risk score**
- a **confidence estimate** describing score stability

---

## Score components

### 1. Finding-level scores

Each detected finding `f` is assigned:

| Component          | Range | Description                          |
| ------------------ | ----- | ------------------------------------ |
| `impact_f`         | 0–10  | Potential damage if exploited.       |
| `exploitability_f` | 0–10  | Ease of exploitation given context.  |
| `confidence_f`     | 0–1   | Confidence in detection correctness. |

**Base finding score:**

```text
base_score_f = (impact_f * exploitability_f) / 10
rule_score_f = base_score_f * confidence_f
```

This ensures:

- weak or ambiguous detections contribute less
- high-confidence findings dominate scoring

---

### 2. OWASP category rollups

Findings are grouped into OWASP-style categories.

For each category `c`:

```text
category_score_c = max(rule_score_f for f in category_c)
```

Notes:

- Each category score represents the **highest-risk finding** in that category
- The maximum-based approach avoids artificial score inflation from multiple findings
- Categories with no findings may be omitted or reported as `0`

---

### 3. CVSS-inspired dimensions

CodeRisk AI reports CVSS-like sub-scores to support governance alignment:

| Dimension                        | Meaning                                  |
| -------------------------------- | ---------------------------------------- |
| `impact`                         | Maximum plausible damage across findings |
| `exploitability`                 | Aggregate ease of exploitation           |
| `prevalence` (optional)          | How widespread the pattern is            |
| `uncertainty_penalty` (optional) | Derived from behavioral signals          |

These values are not strict CVSS scores but preserve familiar semantics.

---

## Behavioral risk signals (AI-specific)

Behavioral signals model **systemic risk introduced by probabilistic generation**, even when no explicit vulnerability is detected.

### 1. Hallucination risk

Signals include:

- non-existent imports or APIs
- inconsistent function signatures
- references to undocumented behavior

**Effect:**

- increases uncertainty
- may elevate category scores tied to integrity and design

---

### 2. Non-determinism sensitivity

Measures how fragile logic is to small changes in:

- prompt phrasing
- context
- generation temperature

Indicators:

- weak input validation
- implicit assumptions
- multiple unguarded execution paths

**Effect:**

- reduces confidence
- increases uncertainty penalty

---

### 3. Dependency volatility

Evaluates:

- unpinned dependencies
- obscure or low-maintenance packages
- risky transitive dependency chains

**Effect:**

- raises impact and exploitability for affected findings
- contributes to uncertainty penalty

---

## Composite risk score

The overall risk score follows a **max-category model**:

```text
overall_score = max(category_scores)
```

Where:

- Each category score represents the highest-risk finding in that category
- The overall score equals the maximum category score
- This avoids artificial inflation from multiple categories with findings
- The final score is always **bounded [0–10]**

**Rationale:**

- Each category score already represents the highest-risk finding in that category
- The overall risk is driven by the worst category, not the sum
- This approach highlights the most critical area requiring attention
- Keeps scoring bounded and interpretable

> Important: absence of findings does **not** imply low risk if uncertainty is high.

---

## Confidence score

### Definition

`confidence` represents **score stability**, not correctness.

It answers:

> “If this code were regenerated or lightly modified, how likely is this risk score to remain similar?”

### Contributors

Confidence is reduced by:

- hallucination markers
- high non-determinism sensitivity
- unstable dependency signals

### Range

0.0 → highly unstable / low confidence
1.0 → highly stable / high confidence

---

## Interpretation guidance

| Scenario                     | Meaning                                  |
| ---------------------------- | ---------------------------------------- |
| High score + high confidence | Clear, actionable security risk          |
| High score + low confidence  | Potentially severe risk with instability |
| Low score + low confidence   | Unknown risk; warrants human review      |
| Low score + high confidence  | Likely low risk in current form          |

---

## Non-goals

This scoring model does **not**:

- claim vulnerability completeness
- replace expert security review
- guarantee exploitability
- attempt automatic remediation

---

## Versioning and evolution

- Scoring rules are versioned independently of the output schema.
- New signals may be added without invalidating prior results.
- Major scoring logic changes require a `ruleset_version` bump.

---

## Research alignment

This scoring model is derived from ongoing research into:

- probabilistic software systems
- AI-assisted development risks
- governance and auditability of AI outputs

The model is designed to support both **practical tooling** and **empirical evaluation**.
