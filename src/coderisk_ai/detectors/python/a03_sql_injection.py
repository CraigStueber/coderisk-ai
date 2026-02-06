from __future__ import annotations

import re
from typing import Any

from .detector_utils import deduplicate_findings


_SQL_LINE_HINT = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)

# SQL structure patterns for stronger detection (v0.2)
_SQL_SELECT_PATTERN = re.compile(r"\bSELECT\b.*\bFROM\b", re.IGNORECASE)
_SQL_INSERT_PATTERN = re.compile(r"\bINSERT\b.*\bINTO\b", re.IGNORECASE)
_SQL_UPDATE_PATTERN = re.compile(r"\bUPDATE\b.*\bSET\b", re.IGNORECASE)
_SQL_DELETE_PATTERN = re.compile(r"\bDELETE\b.*\bFROM\b", re.IGNORECASE)

# Logging/printing detection to avoid false positives
_LOGGING_PATTERN = re.compile(r"\b(logger\.|logging\.|print\()", re.IGNORECASE)

# Heuristic patterns (v0.2):
# 1) "SELECT ..." + user_input
# 2) f"SELECT ... {var} ..."
_CONCAT_PATTERN = re.compile(r'(["\']\s*\+\s*\w+|\w+\s*\+\s*["\'])')
_FSTRING_PATTERN = re.compile(r'(^|[^A-Za-z0-9_])f(["\'])', re.IGNORECASE)

# Safe evidence patterns (v0.3):
# Placeholder construction from constants
_PLACEHOLDER_PATTERN = re.compile(
    r'["\']\s*\.\s*join\s*\(\s*\[\s*["\'](%s|\?)["\'\s]*\]\s*\*',
    re.IGNORECASE
)

# Parameterized execute patterns
_PARAMETERIZED_EXECUTE = re.compile(
    r'\.(execute|executemany)\s*\([^,)]+,\s*\w+\s*\)',
    re.IGNORECASE
)

# Allowlist evidence (table/column from fixed set or dict keys)
_ALLOWLIST_PATTERN = re.compile(
    r'\b(table|column|field|sort|order)\w*\s+in\s+\[|'
    r'\b(table|column|field)\w*\s*=\s*\w+\.get\(|'
    r'ALLOWED_(?:TABLES|COLUMNS|FIELDS)',
    re.IGNORECASE
)


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "info"


def _detect_safe_evidence(lines: list[str], line_idx: int, window: int = 5) -> tuple[bool, str]:
    """
    Detect safe evidence in SQL construction that suggests parameterization or allowlisting.
    
    Returns: (has_safe_evidence, evidence_type)
    """
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    
    context = '\n'.join(lines[start:end])
    
    # Check for placeholder pattern
    if _PLACEHOLDER_PATTERN.search(context):
        # Also check for parameterized execute nearby
        if _PARAMETERIZED_EXECUTE.search(context):
            return True, "placeholders+parameterized"
    
    # Check for parameterized execute with the query variable
    if _PARAMETERIZED_EXECUTE.search(context):
        return True, "parameterized"
    
    # Check for allowlist evidence
    if _ALLOWLIST_PATTERN.search(context):
        return True, "allowlist"
    
    return False, ""


def detect_sql_injection(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    SQL injection heuristic detector (v0.2).
    - Looks for SQL structure patterns + string interpolation
    - Filters out logging/printing statements
    - Returns schema-shaped finding dicts.
    """
    findings: list[dict[str, Any]] = []
    lines = source.splitlines()

    for idx, line in enumerate(lines, start=1):
        # Skip if clearly logging/printing
        if _LOGGING_PATTERN.search(line):
            continue
        
        # Check if line has SQL structure
        has_sql_structure = bool(
            _SQL_SELECT_PATTERN.search(line) or
            _SQL_INSERT_PATTERN.search(line) or
            _SQL_UPDATE_PATTERN.search(line) or
            _SQL_DELETE_PATTERN.search(line)
        )
        
        if not has_sql_structure:
            continue

        has_concat = bool(_CONCAT_PATTERN.search(line))
        has_fstring = bool(_FSTRING_PATTERN.search(line)) and "{" in line and "}" in line

        if not (has_concat or has_fstring):
            continue

        # Check for safe evidence (v0.3)
        has_safe_evidence, evidence_type = _detect_safe_evidence(lines, idx - 1)

        # v0.1 scoring: simple, explainable defaults
        impact_f = 8.0
        exploitability_f = 8.0
        confidence_f = 0.75 if has_concat else 0.65
        
        # Downgrade if safe evidence detected
        if has_safe_evidence:
            # Downgrade severity by one level
            impact_f = 6.0  # medium instead of high
            confidence_f -= 0.35  # significantly lower confidence
            if confidence_f < 0.3:
                confidence_f = 0.3

        base_score_f = (impact_f * exploitability_f) / 10.0
        rule_score_f = round(base_score_f * confidence_f, 2)

        severity = _severity_from_score(base_score_f)
        
        # Adjust severity display for safe evidence
        if not has_safe_evidence:
            severity = _severity_from_score(base_score_f + 1.0)  # nudge into high for unsafe detector

        snippet = line.strip()
        
        if has_safe_evidence:
            explanation = (
                "Detected SQL query construction using "
                + ("string concatenation." if has_concat else "f-string interpolation.")
                + f" However, safe evidence detected ({evidence_type}): "
                + "query appears to use parameterized execution or identifier allowlisting. "
                + "Review to confirm proper parameterization."
            )
            title = "Dynamic SQL detected; appears parameterized/allowlisted (review)"
        else:
            explanation = (
                "Detected likely SQL query construction using "
                + ("string concatenation." if has_concat else "f-string interpolation.")
                + " If user-controlled input is inserted into SQL without parameterization, it can enable SQL injection."
            )
            title = "Potential SQL injection via dynamic query construction"

        findings.append(
            {
                "id": "INJECTION.SQL.STRING_INTERPOLATION" if has_fstring else "INJECTION.SQL.STRING_CONCAT",
                "title": title,
                "description": "SQL keywords were found on a line that also appears to dynamically insert variables into the query.",
                "category": "A03_injection",
                "severity": severity,
                "rule_score": rule_score_f,
                "confidence": confidence_f,
                "exploit_scenario": "Attacker injects malicious SQL through user input to read, modify, or delete database contents.",
                "recommended_fix": "Use parameterized queries or ORM methods to safely handle user input in SQL statements.",
                "evidence": {
                    "file": file_path,
                    "line_start": idx,
                    "line_end": idx,
                    "snippet": snippet[:240],
                    "explanation": explanation,
                },
                "references": [
                    {"type": "CWE", "value": "CWE-89"},
                    {"type": "OWASP", "value": "A03:2021 Injection"},
                ],
            }
        )

    return deduplicate_findings(findings)
