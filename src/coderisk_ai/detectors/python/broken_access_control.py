from __future__ import annotations

import re
from typing import Any


# v0.1: Heuristic-based patterns for broken access control detection
# Focus on Flask and FastAPI route handlers missing authentication

# Flask route decorators
_FLASK_ROUTE = re.compile(r"@(app|bp|blueprint)\.route\s*\(", re.IGNORECASE)
# FastAPI route decorators
_FASTAPI_ROUTE = re.compile(r"@app\.(get|post|put|delete|patch|options|head)\s*\(", re.IGNORECASE)

# Common authentication decorators (Flask, Flask-Login, Flask-JWT, custom)
_AUTH_DECORATOR = re.compile(
    r"@(login_required|jwt_required|requires_auth|requires_roles?|admin_required|auth_required|authenticated)",
    re.IGNORECASE,
)

# FastAPI dependencies pattern
_FASTAPI_DEPENDENCIES = re.compile(r"dependencies\s*=\s*\[", re.IGNORECASE)
_FASTAPI_DEPENDS = re.compile(r"Depends\s*\(", re.IGNORECASE)

# Commented-out authorization checks
_COMMENTED_AUTH = re.compile(
    r"^\s*#.*\b(if\s+not\s+\w+\.is_(admin|authorized|authenticated)|"
    r"authorize\s*\(|check_permission\s*\(|requires_role\s*\(|"
    r"verify_access|check_access|has_permission)",
    re.IGNORECASE,
)


def _severity_from_score(score: float) -> str:
    """Map base score to severity level."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "info"


def _make_finding(
    *,
    finding_id: str,
    title: str,
    description: str,
    file_path: str,
    line_no: int,
    snippet: str,
    explanation: str,
    impact_f: float,
    exploitability_f: float,
    confidence_f: float,
) -> dict[str, Any]:
    """Create a structured finding dict following CodeRisk AI schema."""
    base_score_f = (impact_f * exploitability_f) / 10.0
    score_contribution_f = round(base_score_f * confidence_f, 2)
    severity = _severity_from_score(base_score_f)

    return {
        "id": finding_id,
        "title": title,
        "description": description,
        "category": "A01_access_control",
        "severity": severity,
        "score_contribution": score_contribution_f,
        "confidence": confidence_f,
        "evidence": {
            "file": file_path,
            "line_start": line_no,
            "line_end": line_no,
            "snippet": snippet[:240],
            "explanation": explanation,
        },
        "references": [
            {"type": "CWE", "value": "CWE-284"},
            {"type": "OWASP", "value": "A01:2021 Broken Access Control"},
        ],
    }


def _check_nearby_auth(lines: list[str], route_idx: int, window: int = 5) -> bool:
    """
    Check if there's an auth decorator within 'window' lines above the route.
    Also check the function signature line for Depends(...).
    """
    # Check decorators above
    start = max(0, route_idx - window)
    for i in range(start, route_idx):
        if _AUTH_DECORATOR.search(lines[i]):
            return True

    # Check route decorator line and next few lines for FastAPI dependencies
    end = min(len(lines), route_idx + window)
    for i in range(route_idx, end):
        line = lines[i]
        # Check for dependencies=[...] in decorator
        if _FASTAPI_DEPENDENCIES.search(line):
            return True
        # Check for def handler(..., user: User = Depends(get_current_user)):
        if line.strip().startswith("def ") and _FASTAPI_DEPENDS.search(line):
            return True
        # Stop checking after we hit the function definition
        if line.strip().startswith("def "):
            break

    return False


def detect_broken_access_control(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    Detect broken access control patterns in Python web frameworks.

    v0.1 scope:
    - Flask routes without auth decorators
    - FastAPI routes without dependencies or Depends() in signature
    - Commented-out authorization checks

    Returns:
        List of finding dicts matching CodeRisk AI schema
    """
    findings: list[dict[str, Any]] = []
    lines = source.splitlines()

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            # Check for commented-out auth
            if _COMMENTED_AUTH.search(line):
                findings.append(
                    _make_finding(
                        finding_id="ACCESS_CONTROL.COMMENTED_AUTH",
                        title="Commented-out authorization check",
                        description="An authorization or access control check appears to be commented out, potentially leaving the code path unprotected.",
                        file_path=file_path,
                        line_no=idx,
                        snippet=stripped,
                        explanation=(
                            "Detected a commented line containing authorization keywords like 'is_admin', "
                            "'authorize(', 'check_permission(', or similar. This suggests access control "
                            "may have been disabled or bypassed. Review whether this was intentional."
                        ),
                        impact_f=8.0,
                        exploitability_f=7.0,
                        confidence_f=0.75,
                    )
                )
            continue

        # Detect Flask routes
        if _FLASK_ROUTE.search(line):
            # Check for auth decorators nearby
            if not _check_nearby_auth(lines, idx - 1):  # idx-1 for 0-indexed lines list
                findings.append(
                    _make_finding(
                        finding_id="ACCESS_CONTROL.MISSING.FLASK_AUTH",
                        title="Flask route without authentication",
                        description="A Flask route was detected without any visible authentication decorator (e.g., @login_required, @jwt_required).",
                        file_path=file_path,
                        line_no=idx,
                        snippet=stripped,
                        explanation=(
                            "This Flask route handler does not have an authentication decorator like "
                            "@login_required, @jwt_required, @requires_auth, or similar within a few lines above it. "
                            "If this endpoint handles sensitive operations, it may be accessible without authentication. "
                            "Consider adding appropriate access control checks."
                        ),
                        impact_f=8.0,
                        exploitability_f=7.5,
                        confidence_f=0.70,
                    )
                )

        # Detect FastAPI routes
        elif _FASTAPI_ROUTE.search(line):
            # Check for dependencies or Depends in signature
            if not _check_nearby_auth(lines, idx - 1):
                findings.append(
                    _make_finding(
                        finding_id="ACCESS_CONTROL.MISSING.FASTAPI_AUTH",
                        title="FastAPI route without authentication",
                        description="A FastAPI route was detected without visible authentication dependencies or Depends() in the function signature.",
                        file_path=file_path,
                        line_no=idx,
                        snippet=stripped,
                        explanation=(
                            "This FastAPI route handler does not appear to use 'dependencies=[Depends(...)]' "
                            "in the decorator or 'Depends(get_current_user)' (or similar) in the function signature. "
                            "If this endpoint handles sensitive data or operations, it may be accessible without authentication. "
                            "Consider adding appropriate dependency injection for authentication."
                        ),
                        impact_f=8.0,
                        exploitability_f=7.5,
                        confidence_f=0.70,
                    )
                )

    return findings
