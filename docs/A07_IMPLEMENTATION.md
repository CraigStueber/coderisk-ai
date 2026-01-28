# OWASP A07 – Identification & Authentication Failures Implementation

## Overview

This document describes the implementation of OWASP A07 detection rules for CodeRisk AI.

**Implementation Date:** January 28, 2026  
**Status:** ✅ Complete  
**Rules Implemented:** 2

---

## Rules Implemented

### Rule 1: AUTH.CUSTOM.PASSWORD_CHECK

**Intent:** Detect homegrown password validation or authentication logic

**Examples Detected:**

- `if password == stored_password`
- `if len(password) < 8` (in auth context)
- `if password.isdigit()` (in auth context)
- Manual password validation without vetted frameworks

**Risk Characteristics:**

- **OWASP Category:** A07 - Identification and Authentication Failures
- **Severity:** Medium to High (context-dependent)
- **Confidence:** 0.50 - 0.75
  - Higher confidence (0.75) in authentication/login context
  - Lower confidence (0.50) for general password validation

**CWE References:**

- CWE-287: Improper Authentication
- CWE-257: Storing Passwords in a Recoverable Format

**Scoring:**

- Impact: 7.0 - 8.5
- Exploitability: 6.0 - 7.5
- Base Score: 4.2 - 6.375
- Rule Score: 3.15 - 4.78 (after confidence adjustment)

**Detection Heuristics:**

- Checks for password variable comparisons in conditionals
- Detects manual password attribute checks (len, isdigit, etc.)
- Considers authentication context for severity adjustment
- Excludes established auth libraries (bcrypt, passlib, Django auth, etc.)

**Exploit Scenario:**

> "An attacker could exploit weaknesses in custom authentication logic to bypass authentication checks, perform timing attacks to enumerate valid credentials, or leverage missing security controls like rate limiting and account lockout."

**Recommended Fix:**

> "Replace custom password validation with a vetted authentication library such as bcrypt via passlib, Django's authentication system, Flask-Login, or similar frameworks that implement security best practices."

---

### Rule 2: AUTH.PLAINTEXT.PASSWORD_COMPARE

**Intent:** Detect direct comparison of plaintext passwords

**Examples Detected:**

- `password == "admin123"` (hardcoded)
- `input_pw == user.password` (attribute comparison)
- `request.form["password"] == os.getenv("PASSWORD")` (env variable)
- `password == config["admin_password"]` (config comparison)

**Risk Characteristics:**

- **OWASP Category:** A07 - Identification and Authentication Failures
- **Severity:** High
- **Confidence:** 0.70 - 0.85
  - Highest confidence (0.85) for hardcoded comparisons
  - High confidence (0.80) in authentication context
  - Medium-high (0.70-0.75) for env/config comparisons

**CWE References:**

- CWE-256: Plaintext Storage of a Password
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-798: Use of Hard-coded Credentials

**Scoring:**

- Impact: 8.5 - 9.5 (varies by comparison type)
- Exploitability: 8.0 - 9.0
- Base Score: 6.8 - 8.55
- Rule Score: 5.44 - 7.27 (after confidence adjustment)

**Contextual Severity Escalation:**

- **Hardcoded:** Impact 9.5, Exploitability 9.0
- **Environment/Config:** Impact 8.5, Exploitability 8.0
- **Variable/Attribute:** Impact 9.0, Exploitability 8.5

**Detection Heuristics:**

- Pattern matching for direct password comparisons
- Variable name analysis (password, passwd, pwd, secret, auth)
- Context awareness (authentication flow detection)
- Excludes established auth libraries
- Filters out obvious non-password comparisons (status, role, type, etc.)

**Exploit Scenario:**

> "An attacker with access to the codebase, configuration files, memory dumps, or logs could extract plaintext passwords and compromise user accounts. Additionally, timing attacks may be feasible against non-constant-time string comparisons, allowing attackers to enumerate valid credentials character by character."

**Recommended Fix:**

> "Never compare passwords in plaintext. Use a secure password hashing library (e.g., bcrypt, scrypt, or Argon2 via passlib) to hash passwords with salt and verify them using constant-time comparison. For configuration-based auth, store hashed passwords instead of plaintext."

---

## Implementation Details

### File Structure

```
src/coderisk_ai/detectors/python/
├── identification_authentication_failures.py  # Main detector
└── __init__.py                                 # Export detector

examples/
├── identification_authentication_failures_test.py  # Comprehensive test suite
└── ai_generated_auth_failures.py                   # Real-world examples

validate_a07_detector.py                        # Schema validation script
```

### Detection Algorithm

1. **Prioritization:** Plaintext comparison is checked first (higher severity)
2. **Context Analysis:** Detects authentication/login context within ±10 lines
3. **Library Exclusion:** Skips lines using established auth frameworks
4. **False Positive Reduction:** Filters obvious non-password comparisons
5. **Confidence Scoring:** Adjusts based on context and variable naming

### Schema Compliance

All findings follow the CodeRisk AI schema:

```json
{
  "rule_id": "AUTH.CUSTOM.PASSWORD_CHECK | AUTH.PLAINTEXT.PASSWORD_COMPARE",
  "rule_score": "<0-10>",
  "confidence": "<0-1>",
  "exploit_scenario": "<concrete narrative>",
  "recommended_fix": "<actionable guidance>",
  "instances": [
    {
      "file": "<path>",
      "line_start": "<line>",
      "line_end": "<line>",
      "snippet": "<code>",
      "explanation": "<context>"
    }
  ],
  "references": [
    { "type": "CWE", "value": "CWE-XXX" },
    {
      "type": "OWASP",
      "value": "A07:2021 Identification and Authentication Failures"
    }
  ]
}
```

### Integration

- **CLI Integration:** ✅ Complete
  - Added to `cli.py` analyzer pipeline
  - Included in OWASP scoring rollup
- **Module Export:** ✅ Complete
  - Exported via `__init__.py`
  - Function: `detect_identification_authentication_failures(source, file_path)`

---

## Test Results

### Validation Summary

**Test File:** `examples/identification_authentication_failures_test.py`

- ✅ 2 A07 finding groups detected
- ✅ 19 total instances across both rules
- ✅ Schema validation passed
- ✅ Both expected rules detected

**Detection Breakdown:**

| Rule ID                         | Instances | Severity | Confidence | Rule Score |
| ------------------------------- | --------- | -------- | ---------- | ---------- |
| AUTH.PLAINTEXT.PASSWORD_COMPARE | 12        | High     | 0.85       | 6.12       |
| AUTH.CUSTOM.PASSWORD_CHECK      | 7         | Medium   | 0.75       | 4.46       |

**A07 OWASP Score:** 6.12 (max of rule scores)

### Real-World Test

**Test File:** `examples/ai_generated_auth_failures.py`

- Overall Score: 6.12
- A07 Score: 6.12
- Both authentication issues detected successfully

---

## Design Decisions

### Why Heuristic-Based?

- AI-generated code often uses predictable patterns
- Variable naming conventions are consistent
- Pattern matching is fast and deterministic
- No AST parsing needed for initial implementation

### Confidence Scoring Philosophy

- **Prefer false positives with reduced confidence** over silent misses
- Uncertainty is explicitly preserved in confidence scores
- Context (auth flow) increases confidence
- Variable naming patterns inform confidence

### Severity Assignment

- Plaintext comparison → **High** (clear security violation)
- Custom password checks → **Medium-High** (potential weakness)
- Context escalates severity (auth flow → higher impact)

### False Positive Management

- Exclude established auth libraries explicitly
- Filter obvious non-password comparisons
- Provide detailed explanations for analyst review
- Conservative confidence scores signal uncertainty

---

## Limitations & Future Work

### Known Limitations

1. **Heuristic-based:** May miss obfuscated patterns
2. **No AST analysis:** Limited to line-based pattern matching
3. **Context window:** ±10 lines may miss distant relationships
4. **Variable naming:** Relies on conventional naming patterns

### Future Enhancements

1. **AST-based analysis** for more accurate detection
2. **Data flow tracking** to trace password origins
3. **Inter-procedural analysis** for multi-function auth flows
4. **ML-based confidence scoring** using historical data
5. **Framework-specific rules** (Django, Flask, FastAPI)

---

## Usage Examples

### Analyze a single file:

```bash
python -m coderisk_ai.cli analyze examples/ai_generated_auth_failures.py --pretty
```

### Validate detector:

```bash
python validate_a07_detector.py
```

### Check A07 score:

```bash
python -m coderisk_ai.cli analyze <file> | jq '.summary.owasp.A07_identification_authentication_failures'
```

---

## References

- **OWASP Top 10 2021:** A07:2021 – Identification and Authentication Failures
- **CWE-287:** Improper Authentication
- **CWE-256:** Plaintext Storage of a Password
- **CWE-319:** Cleartext Transmission of Sensitive Information
- **CWE-798:** Use of Hard-coded Credentials

---

## Maintenance Notes

- **Last Updated:** January 28, 2026
- **Schema Version:** 0.1
- **Ruleset Version:** 0.1
- **Python Version:** 3.11+

**Compatibility:** This implementation follows the CodeRisk AI schema and integrates seamlessly with existing detectors (A01, A02, A03, A05, A08).
