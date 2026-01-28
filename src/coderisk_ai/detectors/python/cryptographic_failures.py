from __future__ import annotations

import re
from typing import Any


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
) -> dict[str, Any]:
    """Create a structured finding dict following CodeRisk AI schema."""
    base_score_f = (impact_f * exploitability_f) / 10.0
    score_contribution_f = round(base_score_f * confidence_f, 2)
    severity = _severity_from_score(base_score_f)

    references = [{"type": "CWE", "value": cwe} for cwe in cwe_refs]
    references.append({"type": "OWASP", "value": "A02:2021 Cryptographic Failures"})

    return {
        "id": finding_id,
        "title": title,
        "description": description,
        "category": "A02_cryptographic_failures",
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
                    impact_f=8.0,
                    exploitability_f=7.0,
                    confidence_f=0.80,
                    cwe_refs=["CWE-798", "CWE-259"],
                )
            )
            continue

        # Check for weak hashing algorithms
        weak_hash_match = _WEAK_HASH_PATTERN.search(line)
        if weak_hash_match:
            found_lines.add(idx)
            algorithm = weak_hash_match.group(1).upper()
            findings.append(
                _make_finding(
                    finding_id="CRYPTO.WEAK.HASH",
                    title=f"Weak hashing algorithm detected: {algorithm}",
                    description=f"Usage of cryptographically weak {algorithm} hashing algorithm.",
                    file_path=file_path,
                    line_no=idx,
                    snippet=line.strip(),
                    explanation=(
                        f"{algorithm} is considered cryptographically weak and should not be used for "
                        "security-sensitive operations. For password hashing, use bcrypt, scrypt, or Argon2. "
                        "For general cryptographic hashing, use SHA-256 or stronger algorithms from the SHA-2/SHA-3 families."
                    ),
                    impact_f=7.0,
                    exploitability_f=6.0,
                    confidence_f=0.85,
                    cwe_refs=["CWE-327", "CWE-328"],
                )
            )
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
                    impact_f=6.0,
                    exploitability_f=5.0,
                    confidence_f=0.70,
                    cwe_refs=["CWE-338"],
                )
            )
            continue

    return findings
