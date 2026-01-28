from __future__ import annotations

import re
from typing import Any


_SQL_LINE_HINT = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)

# Heuristic patterns (v0.1):
# 1) "SELECT ..." + user_input
# 2) f"SELECT ... {var} ..."
_CONCAT_PATTERN = re.compile(r'(["\']\s*\+\s*\w+|\w+\s*\+\s*["\'])')
_FSTRING_PATTERN = re.compile(r'(^|[^A-Za-z0-9_])f(["\'])', re.IGNORECASE)


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


def detect_sql_injection(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    Very narrow SQL injection heuristic detector (v0.1).
    - Looks for SQL keywords + string concatenation OR SQL keywords + f-string interpolation.
    - Returns schema-shaped finding dicts.
    """
    findings: list[dict[str, Any]] = []
    lines = source.splitlines()

    for idx, line in enumerate(lines, start=1):
        if not _SQL_LINE_HINT.search(line):
            continue

        has_concat = bool(_CONCAT_PATTERN.search(line))
        has_fstring = bool(_FSTRING_PATTERN.search(line)) and "{" in line and "}" in line

        if not (has_concat or has_fstring):
            continue

        # v0.1 scoring: simple, explainable defaults
        impact_f = 8.0
        exploitability_f = 8.0
        confidence_f = 0.75 if has_concat else 0.65

        base_score_f = (impact_f * exploitability_f) / 10.0  # 6.4
        score_contribution_f = round(base_score_f * confidence_f, 2)

        severity = _severity_from_score(base_score_f + 1.0)  # nudge into high for this detector

        snippet = line.strip()
        explanation = (
            "Detected likely SQL query construction using "
            + ("string concatenation." if has_concat else "f-string interpolation.")
            + " If user-controlled input is inserted into SQL without parameterization, it can enable SQL injection."
        )

        findings.append(
            {
                "id": "INJECTION.SQL.STRING_INTERPOLATION" if has_fstring else "INJECTION.SQL.STRING_CONCAT",
                "title": "Potential SQL injection via dynamic query construction",
                "description": "SQL keywords were found on a line that also appears to dynamically insert variables into the query.",
                "category": "A03_injection",
                "severity": severity,
                "score_contribution": score_contribution_f,
                "confidence": confidence_f,
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

    return findings
