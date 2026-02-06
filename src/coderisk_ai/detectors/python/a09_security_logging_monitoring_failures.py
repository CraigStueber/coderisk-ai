from __future__ import annotations

import re
from typing import Any

from .detector_utils import deduplicate_findings


# v0.2: Enhanced A09 detection with severity escalation, telemetry detection, and best-effort handling

# Exception handler patterns
_EXCEPT_PATTERN = re.compile(
    r'^\s*except\s*(?:\(([^)]+)\)|([a-zA-Z_]\w*))?:',
    re.IGNORECASE,
)

# Pattern for raise statements
_RAISE_PATTERN = re.compile(r'^\s*raise\b', re.IGNORECASE)

# Empty body indicators
_PASS_PATTERN = re.compile(r'^\s*(pass|\.\.\.)\s*$', re.IGNORECASE)
_RETURN_PATTERN = re.compile(r'^\s*return\s*$', re.IGNORECASE)
_CONTINUE_PATTERN = re.compile(r'^\s*continue\s*$', re.IGNORECASE)

# Security-critical keywords for severity escalation
# Note: Using word boundaries to avoid substring matches
_SECURITY_CRITICAL_KEYWORDS = [
    'auth', 'authentication', 'login', 'jwt', 'token', 'session',
    'decrypt', 'decryption', 'crypto', 'cipher', 'signature', 'sign', 'verify',
    'permission', 'authorize', 'authorization', 'access', 'role', 'policy',
    'csrf', 'xss', 'sql', 'injection',
    'secret', 'credential', 'private', 'apikey', 'api_key', 'signing', 'encryption', 'kms'
]

# Compound phrases with "key" that are security-critical
_SECURITY_KEY_PHRASES = [
    'secret key', 'private key', 'api key', 'api_key', 'apikey',
    'signing key', 'encryption key', 'kms key'
]

# Best-effort / optional subsystem indicators
_BEST_EFFORT_KEYWORDS = [
    'best effort', 'optional', 'cache', 'telemetry', 'non-critical', 
    'fallback', 'ignore', 'expected', 'ok to fail'
]

# Optional exception types (less critical)
_OPTIONAL_EXCEPTION_TYPES = [
    'CacheError', 'TimeoutError', 'RequestException'
]

# Fallback indicators (suggests intentional fallback rather than silent swallow)
_FALLBACK_PATTERN = re.compile(
    r'\b(requests\.|http\.|backup|fallback|default|cache|optional|alternative|retry|secondary)\b',
    re.IGNORECASE
)

# Telemetry detection patterns (expanded)
_TELEMETRY_PATTERN = re.compile(
    r'\b(logger\.|logging\.|log\.|print\(|'
    r'capture_exception|capture_message|'
    r'metrics\.|statsd\.|increment|counter|histogram|trace|span)',
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


def _escalate_severity(severity: str, reason: str) -> str:
    """
    Escalate severity by one level based on security-critical context.
    Low → Medium, Medium → High, High stays High.
    Returns the escalated severity.
    """
    if severity == "low":
        return "medium"
    elif severity == "medium":
        return "high"
    # High stays high; no critical for now
    return severity


def detect_security_critical_context(
    lines: list[str],
    except_idx: int,
    body_start_idx: int,
    body_end_idx: int,
    exception_types: str,
) -> tuple[bool, str]:
    """
    Detect if exception handler is in security-critical context.
    
    Checks:
    - Exception type names
    - Function name
    - Code tokens in handler body
    - Comments near handler
    
    Uses word boundaries to avoid false positives from generic terms.
    
    Returns (is_critical, reason) where reason explains why.
    """
    # Check exception type
    exception_types_lower = exception_types.lower()
    for keyword in _SECURITY_CRITICAL_KEYWORDS:
        if re.search(r'\b' + re.escape(keyword) + r'\b', exception_types_lower):
            return (True, f"keyword: {keyword}")
    
    # Check function name (look back for def statement)
    for idx in range(max(0, except_idx - 10), except_idx):
        line_lower = lines[idx].lower()
        if 'def ' in line_lower:
            for keyword in _SECURITY_CRITICAL_KEYWORDS:
                if re.search(r'\b' + re.escape(keyword) + r'\b', line_lower):
                    return (True, f"keyword: {keyword}")
            # Check for key phrases
            for phrase in _SECURITY_KEY_PHRASES:
                if phrase in line_lower:
                    return (True, f"keyword: {phrase}")
            break
    
    # Check body and surrounding lines
    start = max(0, except_idx - 3)
    end = min(len(lines), body_end_idx + 3)
    context = '\n'.join(lines[start:end]).lower()
    
    for keyword in _SECURITY_CRITICAL_KEYWORDS:
        if re.search(r'\b' + re.escape(keyword) + r'\b', context):
            return (True, f"keyword: {keyword}")
    
    # Check for key phrases (compound terms with "key")
    for phrase in _SECURITY_KEY_PHRASES:
        if phrase in context:
            return (True, f"keyword: {phrase}")
    
    return (False, "")


def detect_best_effort_context(
    lines: list[str],
    except_idx: int,
    body_start_idx: int,
    body_end_idx: int,
    exception_types: str,
) -> tuple[bool, str]:
    """
    Detect if exception handler is explicitly marked as best-effort/optional.
    
    Checks:
    - Comments in handler or nearby
    - Exception type names (CacheError, TimeoutError, etc.)
    
    Returns (is_best_effort, reason).
    """
    # Check comments in body and near except
    start = max(0, except_idx - 2)
    end = min(len(lines), body_end_idx + 1)
    
    for idx in range(start, end):
        line_lower = lines[idx].lower()
        if '#' in line_lower:
            comment = line_lower[line_lower.index('#'):].lower()
            for phrase in _BEST_EFFORT_KEYWORDS:
                if phrase in comment:
                    return (True, f"comment: {phrase}")
    
    # Check exception type
    for exc_type in _OPTIONAL_EXCEPTION_TYPES:
        if exc_type.lower() in exception_types.lower():
            return (True, f"exception type: {exc_type}")
    
    return (False, "")


def detect_telemetry(body_lines: list[str]) -> bool:
    """
    Detect if telemetry/logging exists in exception handler body.
    
    Looks for:
    - logger.* calls
    - logging.* calls
    - print() calls
    - Sentry capture_* calls
    - Metrics/tracing calls
    
    Returns True if telemetry detected.
    """
    for line in body_lines:
        if _TELEMETRY_PATTERN.search(line):
            return True
    return False


def detect_fallback_behavior(body_lines: list[str]) -> tuple[bool, str]:
    """
    Detect if exception handler implements a fallback behavior.
    
    Checks for:
    - External calls (backup endpoints, secondary services)
    - Cache/default value returns
    - Retry/alternative path logic
    - Explicit fallback patterns
    
    Returns (has_fallback, fallback_type).
    """
    body_text = '\n'.join(body_lines)
    
    # Check for fallback patterns
    if _FALLBACK_PATTERN.search(body_text):
        # Determine type of fallback
        if re.search(r'\b(backup|secondary|alternative|retry)\b', body_text, re.IGNORECASE):
            return True, "backup/retry"
        if re.search(r'\b(cache|default|fallback)\b', body_text, re.IGNORECASE):
            return True, "cache/default"
    
    # Check for return statements with values (potential default returns)
    if re.search(r'\breturn\s+\w+', body_text, re.IGNORECASE):
        # Only if it's not just "return None" or "return False"
        if not re.search(r'\breturn\s+(None|False|True)\s*$', body_text, re.IGNORECASE):
            return True, "default_value"
    
    return False, ""


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
    security_critical: bool = False,
    security_critical_reason: str = "",
    best_effort: bool = False,
    best_effort_reason: str = "",
    telemetry_detected: bool = False,
) -> dict[str, Any]:
    """Create a structured finding dict following CodeRisk AI schema."""
    base_score_f = (impact_f * exploitability_f) / 10.0
    rule_score_f = round(base_score_f * confidence_f, 2)
    severity = _severity_from_score(base_score_f)
    
    # Apply severity escalation if security-critical
    original_severity = severity
    if security_critical:
        severity = _escalate_severity(severity, security_critical_reason)

    references = [{"type": "CWE", "value": cwe} for cwe in cwe_refs]
    references.append({"type": "OWASP", "value": "A09:2021 Security Logging and Monitoring Failures"})

    finding = {
        "id": finding_id,
        "title": title,
        "description": description,
        "category": "A09_security_logging_monitoring_failures",
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
    
    # Store per-instance severity for aggregation
    finding["_instance_severity"] = severity
    
    # Add optional metadata fields
    if security_critical:
        finding["security_critical"] = True
        finding["security_critical_reason"] = security_critical_reason
    
    if best_effort:
        finding["best_effort"] = True
        finding["best_effort_reason"] = best_effort_reason
    
    if telemetry_detected:
        finding["telemetry_detected"] = True
    
    return finding


def _get_indentation(line: str) -> int:
    """Get the indentation level (number of leading spaces)."""
    return len(line) - len(line.lstrip())


def detect_security_logging_monitoring_failures(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    Detect security logging and monitoring failures (v0.2).
    
    Rules:
    - A09.EXCEPT.EMPTY_PASS: Empty exception handlers (pass, ..., return, continue only)
    - A09.EXCEPT.SWALLOWED: Exceptions caught but not logged or rethrown
    
    Features:
    - Severity escalation for security-critical contexts
    - Best-effort detection to reduce false positives
    - Telemetry detection (logging/metrics)
    - Actionable recommended fixes
    
    Returns schema-shaped finding dicts.
    """
    findings: list[dict[str, Any]] = []
    lines = source.splitlines()
    found_lines: set[int] = set()
    
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        
        # Skip if already found something on this line
        if idx in found_lines:
            idx += 1
            continue
        
        # Check for except statement
        except_match = _EXCEPT_PATTERN.match(line)
        if except_match:
            except_line_no = idx + 1  # 1-based line number
            except_indent = _get_indentation(line)
            
            # Extract exception type(s) if present
            exception_types = except_match.group(1) or except_match.group(2) or "all exceptions"
            
            # Find the body of the except block (lines with greater indentation)
            body_lines = []
            body_start_idx = idx + 1
            body_end_idx = idx
            
            for body_idx in range(idx + 1, len(lines)):
                body_line = lines[body_idx]
                
                # Skip empty lines
                if not body_line.strip():
                    continue
                
                body_indent = _get_indentation(body_line)
                
                # If indentation is less than or equal to except, we've left the block
                if body_indent <= except_indent:
                    break
                
                # This line is part of the body
                body_lines.append(body_line)
                body_end_idx = body_idx
            
            # Analyze the body
            if body_lines:
                # Detect context before analyzing
                security_critical, sec_reason = detect_security_critical_context(
                    lines, idx, body_start_idx, body_end_idx, exception_types
                )
                best_effort, best_reason = detect_best_effort_context(
                    lines, idx, body_start_idx, body_end_idx, exception_types
                )
                has_telemetry = detect_telemetry(body_lines)
                has_fallback, fallback_type = detect_fallback_behavior(body_lines)
                
                # Check for empty handler (RULE 1: A09.EXCEPT.EMPTY_PASS)
                is_empty = True
                for body_line in body_lines:
                    stripped = body_line.strip()
                    # Ignore comments and whitespace
                    if not stripped or stripped.startswith('#'):
                        continue
                    # Check if it's pass, ..., return, or continue
                    if not (_PASS_PATTERN.match(body_line) or 
                           _RETURN_PATTERN.match(body_line) or 
                           _CONTINUE_PATTERN.match(body_line)):
                        is_empty = False
                        break
                
                if is_empty:
                    found_lines.add(idx)
                    
                    # Build snippet showing except and body
                    snippet_lines = [line] + body_lines[:3]  # Show up to 3 body lines
                    snippet = '\n'.join(snippet_lines)
                    
                    # Adjust impact and confidence based on context
                    impact = 6.5
                    exploitability = 6.0
                    confidence = 0.85
                    
                    # Best-effort reduces severity unless security-critical
                    if best_effort and not security_critical:
                        impact = 5.0
                        confidence = 0.70
                    
                    # Build explanation
                    explanation_parts = [
                        f"Exception handler for '{exception_types}' contains only '{body_lines[0].strip()}' "
                        "without any logging, error handling, or re-raising. This silently swallows errors "
                        "and makes debugging and security monitoring impossible."
                    ]
                    
                    if security_critical:
                        explanation_parts.append(f" Security-critical context detected ({sec_reason}).")
                    
                    if best_effort:
                        explanation_parts.append(f" Best-effort context detected ({best_reason}), but telemetry is still recommended.")
                    
                    # Choose appropriate recommended fix
                    if security_critical:
                        recommended_fix = (
                            "Log the exception using structured logging (e.g., logger.exception(...)) and include "
                            "request/user correlation IDs where available. In security-critical contexts, consider "
                            "re-raising the exception or implementing explicit fallback logic with audit trail."
                        )
                    else:
                        recommended_fix = (
                            "Log the exception using structured logging (e.g., logger.exception(...)) to maintain "
                            "visibility into failure paths. If suppression is intentional for best-effort operations, "
                            "record a warning-level event and continue with a clearly defined fallback."
                        )
                    
                    findings.append(
                        _make_finding(
                            finding_id="A09.EXCEPT.EMPTY_PASS",
                            title="Empty exception handler detected",
                            description="An exception handler does not log, rethrow, or otherwise handle the error.",
                            file_path=file_path,
                            line_no=except_line_no,
                            snippet=snippet.strip(),
                            explanation=''.join(explanation_parts),
                            impact_f=impact,
                            exploitability_f=exploitability,
                            confidence_f=confidence,
                            cwe_refs=["CWE-778", "CWE-391"],
                            exploit_scenario=(
                                "Attackers can trigger errors that are silently ignored, allowing them to probe "
                                "for vulnerabilities, bypass security checks, or cause silent data corruption without detection."
                            ),
                            recommended_fix=recommended_fix,
                            security_critical=security_critical,
                            security_critical_reason=sec_reason,
                            best_effort=best_effort,
                            best_effort_reason=best_reason,
                            telemetry_detected=has_telemetry,
                        )
                    )
                    idx = body_end_idx + 1
                    continue
                
                # Check for swallowed exception (RULE 2: A09.EXCEPT.SWALLOWED)
                # Not empty, but no logging or raising
                has_logging = False
                has_raise = False
                has_other_logic = False
                
                body_text = '\n'.join(body_lines)
                
                for body_line in body_lines:
                    stripped = body_line.strip()
                    if not stripped or stripped.startswith('#'):
                        continue
                    
                    # Check for logging
                    if _TELEMETRY_PATTERN.search(body_line):
                        has_logging = True
                    
                    # Check for raise
                    if _RAISE_PATTERN.match(body_line):
                        has_raise = True
                    
                    # Check for other logic (not just pass/return/continue)
                    if not (_PASS_PATTERN.match(body_line) or stripped.startswith('#')):
                        has_other_logic = True
                
                # Swallowed if: has other logic, but no logging or raise
                if has_other_logic and not has_logging and not has_raise:
                    found_lines.add(idx)
                    
                    # Detect fallback behavior
                    has_fallback, fallback_type = detect_fallback_behavior(body_lines)
                    
                    # Adjust impact and confidence based on context
                    impact = 7.0
                    exploitability = 6.5
                    confidence = 0.75
                    
                    # Determine rule variant and messaging
                    if has_fallback:
                        # Fallback-without-telemetry: medium severity, acknowledge intentional fallback
                        impact = 5.5
                        confidence = 0.65
                        rule_id = "A09.EXCEPT.FALLBACK_NO_TELEMETRY"
                        title = "Fallback on exception without telemetry"
                        description = (
                            "Exception handler implements fallback logic but lacks telemetry. "
                            "While fallback may be intentional, lack of logging reduces visibility into failure patterns."
                        )
                    else:
                        # Silent swallow: higher severity
                        rule_id = "A09.EXCEPT.SWALLOWED"
                        title = "Swallowed exception detected"
                        description = (
                            "Exceptions are caught without logging or monitoring and without rethrowing, "
                            "which can hide failures."
                        )
                    
                    # Apply adjustments
                    if best_effort and not security_critical and not has_fallback:
                        # Best-effort without telemetry: still report but lower severity
                        impact = 5.5
                        confidence = 0.65
                    
                    # Build explanation
                    explanation_parts = [
                        f"Exception handler for '{exception_types}' "
                    ]
                    
                    if has_fallback:
                        explanation_parts.append(
                            f"implements a {fallback_type} fallback but does not log "
                            "the exception or emit metrics. While fallback behavior may be intentional, "
                            "lack of telemetry makes it difficult to track failure rates and patterns."
                        )
                    else:
                        explanation_parts.append(
                            "executes logic but does not log "
                            "the exception or rethrow it. This hides failures from monitoring systems and "
                            "makes it difficult to detect security incidents or operational issues."
                        )
                    
                    if security_critical:
                        explanation_parts.append(f" Security-critical context detected ({sec_reason}).")
                    
                    if best_effort and not has_fallback:
                        explanation_parts.append(
                            f" Best-effort context detected ({best_reason}), but telemetry is still "
                            "recommended for visibility into failure rates."
                        )
                    
                    # Build snippet
                    snippet_lines = [line] + body_lines[:5]  # Show up to 5 body lines
                    snippet = '\n'.join(snippet_lines)
                    
                    # Choose appropriate recommended fix
                    if has_fallback:
                        recommended_fix = (
                            "Add logging (logger.warning or logger.exception) to record when fallback paths "
                            "are taken. Include metrics/counters to track fallback frequency and help identify "
                            "patterns. Include sufficient context (correlation IDs, resource names) for troubleshooting."
                        )
                    elif security_critical:
                        recommended_fix = (
                            "Emit telemetry (counter/trace) for failure paths and include context such as "
                            "request IDs, user identifiers, or resource names. Log at error level using "
                            "structured logging (e.g., logger.error(...)) and re-raise the exception unless "
                            "there is explicit safe fallback logic with documented rationale."
                        )
                    elif best_effort:
                        recommended_fix = (
                            "If suppression is intentional for best-effort operations, record a warning-level "
                            "event (e.g., logger.warning(...)) to maintain visibility into failure rates and "
                            "patterns. Include sufficient context to understand impact and troubleshoot if needed."
                        )
                    else:
                        recommended_fix = (
                            "Log the exception using structured logging (e.g., logger.exception(...)) to capture "
                            "stack traces and context. Emit telemetry (counter/trace) for failure paths, and "
                            "re-raise unless explicitly safe to suppress with documented fallback behavior."
                        )
                    
                    findings.append(
                        _make_finding(
                            finding_id=rule_id,
                            title=title,
                            description=description,
                            file_path=file_path,
                            line_no=except_line_no,
                            snippet=snippet.strip(),
                            explanation=''.join(explanation_parts),
                            impact_f=impact,
                            exploitability_f=exploitability,
                            confidence_f=confidence,
                            cwe_refs=["CWE-778", "CWE-391"],
                            exploit_scenario=(
                                "Attackers can trigger exceptions in critical paths (authentication, authorization, "
                                "data validation) that are silently handled without logging, allowing them to bypass "
                                "security controls or cause data integrity issues without detection." if not has_fallback else
                                "Repeated fallback executions without visibility can hide systemic issues, performance "
                                "degradation, or targeted attacks. Lack of telemetry prevents correlation analysis and "
                                "incident response."
                            ),
                            recommended_fix=recommended_fix,
                            security_critical=security_critical,
                            security_critical_reason=sec_reason,
                            best_effort=best_effort,
                            best_effort_reason=best_reason,
                            telemetry_detected=has_telemetry,
                        )
                    )
                    idx = body_end_idx + 1
                    continue
        
        idx += 1
    
    return deduplicate_findings(findings)
