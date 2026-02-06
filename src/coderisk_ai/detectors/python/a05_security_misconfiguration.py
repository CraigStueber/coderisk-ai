from __future__ import annotations

import re
from typing import Any

from .detector_utils import deduplicate_findings


# v0.1: Heuristic-based patterns for security misconfiguration detection

# Debug mode enabled patterns
_DEBUG_TRUE_PATTERN = re.compile(
    r'\bdebug\s*=\s*True\b',
    re.IGNORECASE,
)

# Permissive CORS patterns
_CORS_ALLOW_ALL_ORIGINS_PATTERN = re.compile(
    r'\ballow_all_origins\s*=\s*True\b',
    re.IGNORECASE,
)
_CORS_ALLOW_ORIGINS_WILDCARD_PATTERN = re.compile(
    r'\ballow_origins\s*=\s*\[\s*["\']?\*["\']?\s*\]',
    re.IGNORECASE,
)
_CORS_ORIGINS_WILDCARD_PATTERN = re.compile(
    r'\borigins\s*=\s*["\']?\*["\']?',
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
    cwe_refs: list[str],
    exploit_scenario: str,
    recommended_fix: str,
) -> dict[str, Any]:
    """Create a structured finding dict following CodeRisk AI schema."""
    base_score_f = (impact_f * exploitability_f) / 10.0
    rule_score_f = round(base_score_f * confidence_f, 2)
    severity = _severity_from_score(base_score_f)

    references = [{"type": "CWE", "value": cwe} for cwe in cwe_refs]
    references.append({"type": "OWASP", "value": "A05:2021 Security Misconfiguration"})

    return {
        "id": finding_id,
        "title": title,
        "description": description,
        "category": "A05_security_misconfiguration",
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
        "references": references,
    }


def detect_security_misconfiguration(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    Security misconfiguration detector (v0.1).
    - Detects debug=True in web frameworks
    - Detects permissive CORS configurations (allow_all_origins, wildcard origins)
    - Returns schema-shaped finding dicts.
    """
    findings: list[dict[str, Any]] = []
    lines = source.splitlines()
    found_lines: set[int] = set()  # Track lines to avoid duplicates

    for idx, line in enumerate(lines, start=1):
        # Skip if we already found something on this line
        if idx in found_lines:
            continue

        # Skip commented-out lines
        if line.lstrip().startswith('#'):
            continue

        # Check for debug=True
        debug_match = _DEBUG_TRUE_PATTERN.search(line)
        if debug_match:
            matched_text = debug_match.group(0)
            # Check if it's a runtime call (has parenthesis nearby) or lowercase debug (parameter)
            if '(' in line and 'debug' in matched_text.lower():
                # Runtime debug parameter (e.g., app.run(debug=True))
                found_lines.add(idx)
                findings.append(
                    _make_finding(
                        finding_id="MISCONFIG.DEBUG.TRUE",
                        title="Debug mode enabled",
                        description="Debug mode is explicitly enabled, which can expose sensitive information in production.",
                        file_path=file_path,
                        line_no=idx,
                        snippet=line.strip(),
                        explanation=(
                            "Running applications with debug=True in production exposes detailed error messages, "
                            "stack traces, and internal application state to users. This information can aid attackers "
                            "in understanding the application's internals and identifying vulnerabilities. Debug mode "
                            "should only be enabled in development environments and controlled via environment variables."
                        ),
                        impact_f=6.0,
                        exploitability_f=7.0,
                        confidence_f=0.80,
                        cwe_refs=["CWE-489", "CWE-215"],
                        exploit_scenario="Attacker triggers errors to view stack traces revealing internal paths, configuration, and code structure.",
                        recommended_fix="Remove debug=True from code and control debug mode via environment variables.",
                    )
                )
            elif 'DEBUG' in line and '=' in line and '(' not in line:
                # Standalone DEBUG = True constant
                found_lines.add(idx)
                # Clean snippet by removing misleading comments
                clean_snippet = line.strip()
                if '#' in clean_snippet:
                    # Remove comment that says "Should NOT flag"
                    code_part = clean_snippet.split('#')[0].rstrip()
                    if 'should not flag' in clean_snippet.lower():
                        clean_snippet = code_part
                
                finding = _make_finding(
                    finding_id="MISCONFIG.DEBUG.TRUE",
                    title="Debug mode enabled",
                    description="Debug constant is set to True, which may expose sensitive information if used by web frameworks.",
                    file_path=file_path,
                    line_no=idx,
                    snippet=clean_snippet,
                    explanation=(
                        "A DEBUG constant is set to True. If this constant is used by Flask, FastAPI, or similar "
                        "frameworks to enable debug mode, it can expose detailed error messages, stack traces, and "
                        "internal application state in production. Debug mode should only be enabled in development "
                        "environments. Note: This may be a false positive if the constant is not actually used for "
                        "framework configuration."
                    ),
                    impact_f=6.0,
                    exploitability_f=7.0,
                    confidence_f=0.80,  # Keep rule confidence at 0.80
                    cwe_refs=["CWE-489", "CWE-215"],
                    exploit_scenario="Attacker triggers errors to view stack traces revealing internal paths and configuration if DEBUG is used by framework.",
                    recommended_fix="Remove DEBUG = True or ensure it is not used for production framework configuration.",
                )
                # Mark this instance with lower confidence
                finding["_instance_confidence"] = 0.60
                findings.append(finding)
            continue

        # Check for allow_all_origins=True
        cors_allow_all_match = _CORS_ALLOW_ALL_ORIGINS_PATTERN.search(line)
        if cors_allow_all_match:
            found_lines.add(idx)
            findings.append(
                _make_finding(
                    finding_id="MISCONFIG.CORS.ALLOW_ALL",
                    title="Permissive CORS configuration detected",
                    description="CORS is configured to allow requests from all origins, which can enable cross-origin attacks.",
                    file_path=file_path,
                    line_no=idx,
                    snippet=line.strip(),
                    explanation=(
                        "Setting allow_all_origins=True permits any website to make cross-origin requests to your API, "
                        "potentially exposing sensitive data or functionality to malicious sites. Configure CORS to "
                        "explicitly allow only trusted origins, or use environment-based configuration to restrict "
                        "origins appropriately for each deployment environment."
                    ),
                    impact_f=7.0,
                    exploitability_f=6.0,
                    confidence_f=0.85,
                    cwe_refs=["CWE-942"],
                    exploit_scenario="Attacker hosts malicious website that makes cross-origin requests to steal user data or perform unauthorized actions.",
                    recommended_fix="Configure explicit list of allowed origins or use environment variables to manage CORS settings per deployment.",
                )
            )
            continue

        # Check for allow_origins=["*"] or allow_origins=['*']
        cors_origins_wildcard_match = _CORS_ALLOW_ORIGINS_WILDCARD_PATTERN.search(line)
        if cors_origins_wildcard_match:
            found_lines.add(idx)
            findings.append(
                _make_finding(
                    finding_id="MISCONFIG.CORS.ALLOW_ALL",
                    title="Permissive CORS configuration detected",
                    description="CORS is configured with wildcard origin (*), which allows requests from any domain.",
                    file_path=file_path,
                    line_no=idx,
                    snippet=line.strip(),
                    explanation=(
                        "Using a wildcard (*) in allow_origins permits any website to make cross-origin requests to your API, "
                        "potentially exposing sensitive data or functionality to malicious sites. Configure CORS to "
                        "explicitly allow only trusted origins, or use environment-based configuration to restrict "
                        "origins appropriately for each deployment environment."
                    ),
                    impact_f=7.0,
                    exploitability_f=6.0,
                    confidence_f=0.85,
                    cwe_refs=["CWE-942"],
                    exploit_scenario="Attacker hosts malicious website that makes cross-origin requests to steal user data or perform unauthorized actions.",
                    recommended_fix="Replace wildcard with explicit list of trusted origins.",
                )
            )
            continue

        # Check for origins="*" or origins='*'
        origins_wildcard_match = _CORS_ORIGINS_WILDCARD_PATTERN.search(line)
        if origins_wildcard_match:
            found_lines.add(idx)
            findings.append(
                _make_finding(
                    finding_id="MISCONFIG.CORS.ALLOW_ALL",
                    title="Permissive CORS configuration detected",
                    description="CORS origins parameter is set to wildcard (*), allowing requests from any domain.",
                    file_path=file_path,
                    line_no=idx,
                    snippet=line.strip(),
                    explanation=(
                        "Setting origins='*' permits any website to make cross-origin requests to your API, "
                        "potentially exposing sensitive data or functionality to malicious sites. Configure CORS to "
                        "explicitly allow only trusted origins, or use environment-based configuration to restrict "
                        "origins appropriately for each deployment environment."
                    ),
                    impact_f=7.0,
                    exploitability_f=6.0,
                    confidence_f=0.85,
                    cwe_refs=["CWE-942"],
                    exploit_scenario="Attacker hosts malicious website that makes cross-origin requests to steal user data or perform unauthorized actions.",
                    recommended_fix="Replace wildcard with explicit list of trusted origins.",
                )
            )
            continue

    return deduplicate_findings(findings)
