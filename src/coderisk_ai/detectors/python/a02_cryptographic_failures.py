from __future__ import annotations

import re
from typing import Any

from .detector_utils import deduplicate_findings


# v0.1: Heuristic-based patterns for cryptographic failures detection

# Hardcoded secrets: variable names that suggest secrets
_SECRET_VAR_PATTERN = re.compile(
    r'\b(secret|password|api_key|apikey|api_secret|access_token|auth_token|private_key|auth_key|session_key|encryption_key)\s*=\s*["\']([^"\']{8,})["\']',
    re.IGNORECASE,
)

# Weak hashing algorithms
_WEAK_HASH_PATTERN = re.compile(
    r'\bhashlib\.(md5|sha1)\s*\(',
    re.IGNORECASE,
)

# Security-sensitive context for hashing (password, auth, tokens, etc.)
_SECURITY_CONTEXT_PATTERN = re.compile(
    r'\b(password|pwd|auth|token|secret|key|session|signature)\b',
    re.IGNORECASE,
)

# Insecure randomness in token-like contexts
_RANDOM_MODULE_PATTERN = re.compile(
    r'\brandom\.(random|randint|choice)\s*\(',
    re.IGNORECASE,
)
_TOKEN_VAR_PATTERN = re.compile(
    r'\b(token|secret|key|session|auth|api_key|password)\b',
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
    references.append({"type": "OWASP", "value": "A02:2021 Cryptographic Failures"})

    return {
        "id": finding_id,
        "title": title,
        "description": description,
        "category": "A02_cryptographic_failures",
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


def detect_cryptographic_failures(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    Narrow cryptographic failures detector (v0.1).
    - Detects hardcoded secrets in variable assignments
    - Detects weak hashing algorithms (MD5, SHA1)
    - Detects insecure randomness in token-like contexts
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

        # Check for hardcoded secrets
        secret_match = _SECRET_VAR_PATTERN.search(line)
        if secret_match:
            found_lines.add(idx)
            findings.append(
                _make_finding(
                    finding_id="CRYPTO.HARDCODED.SECRET",
                    title="Hardcoded secret detected",
                    description="A variable name suggests it contains sensitive data, and a hardcoded string value is assigned to it.",
                    file_path=file_path,
                    line_no=idx,
                    snippet=line.strip(),
                    explanation=(
                        "Hardcoded secrets in source code can be easily extracted by attackers "
                        "who gain access to the codebase. Secrets should be stored in environment "
                        "variables, secure vaults, or configuration management systems."
                    ),
                    impact_f=9.0,
                    exploitability_f=8.0,
                    confidence_f=0.80,
                    cwe_refs=["CWE-798", "CWE-259"],
                    exploit_scenario="Attacker with repository access extracts hardcoded credentials to compromise the system.",
                    recommended_fix="Store secrets in environment variables or a secure vault service and reference them at runtime.",
                )
            )
            continue

        # Check for weak hashing algorithms
        weak_hash_match = _WEAK_HASH_PATTERN.search(line)
        if weak_hash_match:
            found_lines.add(idx)
            algorithm = weak_hash_match.group(1).lower()  # md5 or sha1
            
            # Check if this is in a security-sensitive context
            # Look at the line and surrounding variable/function names
            in_security_context = _SECURITY_CONTEXT_PATTERN.search(line)
            
            # If security context detected, use high severity; otherwise medium
            if in_security_context:
                impact_f = 9.0  # High severity for security-sensitive usage
                explanation = (
                    "This weak hashing algorithm is used in a security-sensitive context (password, auth, token, etc.). "
                    "For password hashing, use bcrypt, scrypt, or Argon2. For general cryptographic hashing, "
                    "use SHA-256 or stronger algorithms from the SHA-2/SHA-3 families."
                )
                exploit_scenario = "Attacker performs offline cracking or credential compromise using weak hash algorithm."
                recommended_fix = "Use bcrypt, scrypt, or Argon2 for password hashing; SHA-256+ for general cryptographic needs."
            else:
                impact_f = 6.5  # Medium severity for general usage
                explanation = (
                    "This weak hashing algorithm is used for general purposes. While not immediately exploitable, "
                    "it may allow collisions that undermine integrity checks or cache keys. Use SHA-256 or stronger "
                    "algorithms from the SHA-2/SHA-3 families."
                )
                exploit_scenario = "May allow collisions that undermine integrity checks or cache keys."
                recommended_fix = "Replace with SHA-256 or stronger from SHA-2/SHA-3 families."
            
            finding = _make_finding(
                finding_id="CRYPTO.WEAK.HASH",
                title="Weak hashing algorithm detected",
                description="Usage of cryptographically weak hashing algorithm.",
                file_path=file_path,
                line_no=idx,
                snippet=line.strip(),
                explanation=explanation,
                impact_f=impact_f,
                exploitability_f=8.0,
                confidence_f=0.85,
                cwe_refs=["CWE-327", "CWE-328"],
                exploit_scenario=exploit_scenario,
                recommended_fix=recommended_fix,
            )
            # Store algorithm for per-instance metadata
            finding["_algorithm"] = algorithm
            findings.append(finding)
            continue

        # Check for insecure randomness in token-like contexts
        random_match = _RANDOM_MODULE_PATTERN.search(line)
        if random_match and _TOKEN_VAR_PATTERN.search(line):
            found_lines.add(idx)
            random_func = random_match.group(1)
            findings.append(
                _make_finding(
                    finding_id="CRYPTO.INSECURE.RANDOM",
                    title="Insecure randomness for security-sensitive operation",
                    description=f"Use of random.{random_func}() in a context that appears to involve security tokens or secrets.",
                    file_path=file_path,
                    line_no=idx,
                    snippet=line.strip(),
                    explanation=(
                        f"The random.{random_func}() function is not cryptographically secure and should not be "
                        "used for generating security tokens, passwords, or other security-sensitive values. "
                        "Use the 'secrets' module instead (e.g., secrets.token_hex(), secrets.token_urlsafe(), "
                        "secrets.randbelow()) or os.urandom() for cryptographically strong random values."
                    ),
                    impact_f=8.0,
                    exploitability_f=7.0,
                    exploit_scenario="Attacker predicts weak random values to forge tokens or bypass authentication mechanisms.",
                    recommended_fix="Replace random module usage with secrets module functions like secrets.token_hex() or secrets.token_urlsafe().",
                    confidence_f=0.70,
                    cwe_refs=["CWE-338"],
                )
            )
            continue

    return deduplicate_findings(findings)
