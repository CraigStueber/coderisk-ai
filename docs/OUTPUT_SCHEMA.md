# CodeRisk AI — Output Schema (v0.1)

This document defines the **public output contract** for CodeRisk AI analysis results.

## Design goals

- **Stable contract:** consumers can rely on field names and types.
- **Explainable scoring:** every score must be traceable to evidence.
- **Confidence-aware:** uncertainty is a first-class output.
- **Forward compatible:** additive changes should not break clients.

---

## Top-level object

### `analysis_result` (object)

| Field            | Type   | Required | Description                                                     |
| ---------------- | ------ | -------- | --------------------------------------------------------------- |
| `schema_version` | string | ✅       | Output schema version (e.g., `"0.1"`).                          |
| `analyzer`       | object | ✅       | Information about the analyzer build/version.                   |
| `target`         | object | ✅       | What was analyzed (path, language, file count, etc.).           |
| `summary`        | object | ✅       | Overall risk score, confidence, and rollups.                    |
| `findings`       | array  | ✅       | List of detected issues and their evidence.                     |
| `signals`        | object | ✅       | Behavioral / probabilistic signals (LLM-specific risk factors). |
| `metadata`       | object | ❌       | Optional context (model, prompt style, run id, etc.).           |

---

## `analyzer` (object)

| Field             | Type   | Required | Description                                             |
| ----------------- | ------ | -------- | ------------------------------------------------------- |
| `name`            | string | ✅       | Always `"coderisk-ai"`.                                 |
| `version`         | string | ✅       | Analyzer version (SemVer recommended, e.g., `"0.0.1"`). |
| `ruleset_version` | string | ✅       | Version of scoring rules/detectors (e.g., `"0.1"`).     |
| `timestamp_utc`   | string | ✅       | ISO-8601 timestamp of analysis (UTC).                   |

---

## `target` (object)

| Field        | Type    | Required | Description                                                     |
| ------------ | ------- | -------- | --------------------------------------------------------------- |
| `path`       | string  | ✅       | File or directory analyzed.                                     |
| `language`   | string  | ✅       | Primary language (e.g., `"python"`).                            |
| `file_count` | integer | ✅       | Number of files analyzed.                                       |
| `files`      | array   | ❌       | Optional list of file descriptors (useful for multi-file runs). |

### `target.files[]` (object, optional)

| Field    | Type    | Required | Description                                  |
| -------- | ------- | -------- | -------------------------------------------- |
| `file`   | string  | ✅       | Relative file path.                          |
| `sha256` | string  | ❌       | Hash for reproducibility (optional for now). |
| `lines`  | integer | ❌       | Line count (optional).                       |

---

## `summary` (object)

| Field             | Type   | Required | Description                                               |
| ----------------- | ------ | -------- | --------------------------------------------------------- |
| `overall_score`   | number | ✅       | 0–10 composite risk score (higher = riskier).             |
| `confidence`      | number | ✅       | 0–1 stability/confidence estimate (higher = more stable). |
| `severity_counts` | object | ✅       | Count of findings by severity.                            |
| `owasp`           | object | ✅       | OWASP-category rollup scores (0–10 each).                 |
| `cvss_like`       | object | ✅       | CVSS-inspired sub-scores (0–10 each).                     |

### `summary.severity_counts` (object)

| Field      | Type    | Required | Description                      |
| ---------- | ------- | -------- | -------------------------------- |
| `critical` | integer | ✅       | Count of critical findings.      |
| `high`     | integer | ✅       | Count of high findings.          |
| `medium`   | integer | ✅       | Count of medium findings.        |
| `low`      | integer | ✅       | Count of low findings.           |
| `info`     | integer | ✅       | Count of informational findings. |

### `summary.owasp` (object)

Key/value map where keys are OWASP-style identifiers and values are 0–10 scores.

**Recommended key set (expand over time):**

- `A01_broken_access_control`
- `A02_cryptographic_failures`
- `A03_injection`
- `A04_insecure_design`
- `A05_security_misconfiguration`
- `A06_vulnerable_and_outdated_components`
- `A07_identification_and_authentication_failures`
- `A08_software_and_data_integrity_failures`
- `A09_security_logging_and_monitoring_failures`
- `A10_ssrf`

> v0.x note: you can start with 3–4 categories implemented; unused categories may be omitted or set to `0`.

### `summary.cvss_like` (object)

| Field                 | Type   | Required | Description                                                           |
| --------------------- | ------ | -------- | --------------------------------------------------------------------- |
| `impact`              | number | ✅       | 0–10 estimated impact if exploited.                                   |
| `exploitability`      | number | ✅       | 0–10 ease of exploitation.                                            |
| `prevalence`          | number | ❌       | 0–10 how common this pattern is in the codebase (optional).           |
| `uncertainty_penalty` | number | ❌       | 0–10 penalty derived from instability/uncertainty (optional for now). |

---

## `findings` (array)

### `findings[]` (object)

| Field                | Type   | Required | Description                                                 |
| -------------------- | ------ | -------- | ----------------------------------------------------------- |
| `id`                 | string | ✅       | Stable detector id (e.g., `"INJECTION.SQL.STRING_CONCAT"`). |
| `title`              | string | ✅       | Human-readable short title.                                 |
| `description`        | string | ✅       | What was detected and why it matters.                       |
| `category`           | string | ✅       | High-level category (e.g., `"A03_injection"`).              |
| `severity`           | string | ✅       | One of: `critical`, `high`, `medium`, `low`, `info`.        |
| `score_contribution` | number | ✅       | 0–10 contribution toward overall score (bounded).           |
| `confidence`         | number | ✅       | 0–1 confidence for this specific finding.                   |
| `evidence`           | object | ✅       | Evidence and location details.                              |
| `references`         | array  | ❌       | Optional references (CWE, OWASP, docs).                     |

### `findings[].evidence` (object)

| Field         | Type    | Required | Description                                     |
| ------------- | ------- | -------- | ----------------------------------------------- |
| `file`        | string  | ✅       | File path.                                      |
| `line_start`  | integer | ✅       | Start line number (1-indexed).                  |
| `line_end`    | integer | ✅       | End line number (1-indexed).                    |
| `snippet`     | string  | ❌       | Small code excerpt (keep short).                |
| `explanation` | string  | ✅       | Plain-English explanation tied to this snippet. |

### `findings[].references[]` (object, optional)

| Field   | Type   | Required | Description                        |
| ------- | ------ | -------- | ---------------------------------- |
| `type`  | string | ✅       | e.g., `"CWE"`, `"OWASP"`, `"URL"`. |
| `value` | string | ✅       | e.g., `"CWE-89"` or a URL.         |

---

## `signals` (object)

Behavioral/probabilistic indicators common in AI-generated code. This is where CodeRisk AI differentiates.

| Field                        | Type   | Required | Description                                                            |
| ---------------------------- | ------ | -------- | ---------------------------------------------------------------------- |
| `hallucination_markers`      | object | ✅       | Signals suggesting invented APIs, inconsistent imports, phantom calls. |
| `nondeterminism_sensitivity` | object | ✅       | Stability risk under small changes (prompt/context variations).        |
| `dependency_volatility`      | object | ✅       | Risk from unpinned/obscure/transitive dependencies.                    |
| `notes`                      | array  | ❌       | Optional freeform notes for explainability.                            |

### `signals.hallucination_markers` (object)

| Field        | Type   | Required | Description                                   |
| ------------ | ------ | -------- | --------------------------------------------- |
| `level`      | string | ✅       | `low` / `medium` / `high`.                    |
| `indicators` | array  | ✅       | List of detected hallucination-like patterns. |

### `signals.nondeterminism_sensitivity` (object)

| Field       | Type   | Required | Description                  |
| ----------- | ------ | -------- | ---------------------------- |
| `level`     | string | ✅       | `low` / `medium` / `high`.   |
| `rationale` | string | ✅       | Why this level was assigned. |

### `signals.dependency_volatility` (object)

| Field                   | Type    | Required | Description                       |
| ----------------------- | ------- | -------- | --------------------------------- |
| `level`                 | string  | ✅       | `low` / `medium` / `high`.        |
| `unpinned_dependencies` | integer | ❌       | Count (optional).                 |
| `suspicious_packages`   | array   | ❌       | Package names flagged (optional). |

---

## `metadata` (object, optional)

Use this for context that should not affect scoring unless explicitly configured.

Suggested fields:

- `source_model` (string) — e.g., `"copilot"`, `"gpt-4.1"`, `"claude"`
- `prompt_style` (string) — e.g., `"freeform"`, `"structured"`
- `prompt_hash` (string) — reproducibility without storing prompt
- `run_id` (string) — traceability
- `tags` (array[string]) — user-provided labels

---

## Example output (v0.1)

```json
{
  "schema_version": "0.1",
  "analyzer": {
    "name": "coderisk-ai",
    "version": "0.0.1",
    "ruleset_version": "0.1",
    "timestamp_utc": "2026-01-27T19:10:00Z"
  },
  "target": {
    "path": "examples/injection_example.py",
    "language": "python",
    "file_count": 1
  },
  "summary": {
    "overall_score": 7.2,
    "confidence": 0.68,
    "severity_counts": {
      "critical": 0,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    },
    "owasp": {
      "A03_injection": 8.1,
      "A06_vulnerable_and_outdated_components": 6.4,
      "A04_insecure_design": 5.2
    },
    "cvss_like": {
      "impact": 7.8,
      "exploitability": 6.9
    }
  },
  "signals": {
    "hallucination_markers": {
      "level": "medium",
      "indicators": ["inconsistent_import_usage"]
    },
    "nondeterminism_sensitivity": {
      "level": "medium",
      "rationale": "multiple alternative code paths detected with weak validation boundaries"
    },
    "dependency_volatility": {
      "level": "low"
    }
  },
  "findings": [
    {
      "id": "INJECTION.SQL.STRING_CONCAT",
      "title": "SQL injection via string concatenation",
      "description": "User input appears concatenated into an SQL query without parameterization.",
      "category": "A03_injection",
      "severity": "high",
      "score_contribution": 3.2,
      "confidence": 0.86,
      "evidence": {
        "file": "examples/injection_example.py",
        "line_start": 12,
        "line_end": 14,
        "snippet": "query = \"SELECT * FROM users WHERE name='\" + name + \"'\"",
        "explanation": "String concatenation of user-controlled input can allow attackers to modify the query."
      },
      "references": [
        { "type": "CWE", "value": "CWE-89" },
        { "type": "OWASP", "value": "A03:2021 Injection" }
      ]
    }
  ]
}
```
