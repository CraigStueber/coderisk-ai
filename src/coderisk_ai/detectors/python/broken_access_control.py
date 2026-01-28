from __future__ import annotations

import re
from typing import Any

from .detector_utils import deduplicate_findings


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
    exploit_scenario: str,
    recommended_fix: str,
) -> dict[str, Any]:
    """Create a structured finding dict following CodeRisk AI schema.
    
    Scoring semantics (v0.1):
    - rule_score: canonical base score for this rule instance (impact * exploitability * confidence)
    - score_contribution: post-weight score for aggregation (currently == rule_score for v0.1)
    - Future (v0.2+): score_contribution may apply additional context/weighting multipliers
    """
    base_score_f = (impact_f * exploitability_f) / 10.0
    rule_score_f = round(base_score_f * confidence_f, 2)
    severity = _severity_from_score(base_score_f)

    return {
        "id": finding_id,
        "title": title,
        "description": description,
        "category": "A01_access_control",
        "severity": severity,
        "rule_score": rule_score_f,
        "confidence": confidence_f,
        "exploit_scenario": exploit_scenario,
        "recommended_fix": recommended_fix,
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


# Public/auth endpoint allowlist for ACCESS_CONTROL.MISSING.FLASK_AUTH
# These routes are typically public by design and should not require auth decorators
_PUBLIC_ROUTE_PATTERNS = [
    '/login', '/signin', '/sign_in', '/logout', '/signout', '/sign_out',
    '/auth', '/auth/', '/oauth', '/oauth/', '/register', '/signup', '/sign_up',
    '/health', '/healthz', '/ready', '/readyz', '/live', '/liveness',
    '/metrics', '/status', '/ping',
]


def _extract_route_path(line: str) -> str | None:
    """Extract route path from Flask @app.route() decorator.
    Returns None if path cannot be extracted."""
    match = re.search(r"@(?:app|bp|blueprint)\.route\s*\(\s*['\"]([^'\"]+)['\"]"  , line, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _is_public_route(route_path: str) -> bool:
    """Check if route path matches public endpoint allowlist.
    Rationale: login/auth/health endpoints should not require auth decorators.
    """
    if not route_path:
        return False
    
    route_lower = route_path.lower()
    for pattern in _PUBLIC_ROUTE_PATTERNS:
        # Exact match or prefix match for patterns ending with '/'
        if route_lower == pattern or (pattern.endswith('/') and route_lower.startswith(pattern)):
            return True
    return False


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
            # Check for commented-out auth (may be benign like documentation/examples)
            if _COMMENTED_AUTH.search(line):
                findings.append(
                    _make_finding(
                        finding_id="ACCESS_CONTROL.AUTH_CHECK_COMMENTED_OUT",
                        title="Commented-out authorization check detected",
                        description="An authorization check appears to be commented out (may be benign like documentation/examples, but often indicates disabled enforcement).",
                        file_path=file_path,
                        line_no=idx,
                        snippet=stripped,
                        explanation=(
                            "Detected a commented line containing authorization keywords like 'is_admin', "
                            "'authorize(', 'check_permission(', or similar. While this may be benign "
                            "(documentation, commented example code), it often indicates that access control "
                            "enforcement has been temporarily or permanently disabled. Review the context to "
                            "determine if this represents an actual security risk."
                        ),
                        impact_f=8.0,
                        exploitability_f=7.0,
                        confidence_f=0.60,
                        exploit_scenario="Attacker accesses protected resources by exploiting disabled authorization checks.",
                        recommended_fix="Remove commented code or restore authorization checks to enforce access control.",
                    )
                )
            continue

        # Detect Flask routes
        if _FLASK_ROUTE.search(line):
            # Extract route path and check if it's a public endpoint
            route_path = _extract_route_path(line)
            if route_path and _is_public_route(route_path):
                # Skip public/auth endpoints - these are expected to be unauthenticated
                continue
            
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
                        exploit_scenario="Attacker directly accesses sensitive endpoints without authentication credentials.",
                        recommended_fix="Add authentication decorator such as @login_required or @jwt_required to the route.",
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
                        exploit_scenario="Attacker directly accesses sensitive API endpoints without authentication.",
                        recommended_fix="Add dependencies parameter to route decorator or use Depends() in function signature for authentication.",
                    )
                )

    return deduplicate_findings(findings)
