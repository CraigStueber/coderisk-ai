from __future__ import annotations

import re
from typing import Any

from .detector_utils import deduplicate_findings


# v0.1: Heuristic-based patterns for identification and authentication failures detection

# Password-related variable names
_PASSWORD_VAR_PATTERN = re.compile(
    r'\b(password|passwd|pwd|passphrase|pass|secret|credential|auth)\b',
    re.IGNORECASE,
)

# Authentication/login context indicators
_AUTH_CONTEXT_PATTERN = re.compile(
    r'\b(login|authenticate|auth|signin|sign_in|verify_user|check_user|check_password|verify_password|verify_credentials)\b',
    re.IGNORECASE,
)

# Registration/signup context indicators (for password policy)
_SIGNUP_CONTEXT_PATTERN = re.compile(
    r'\b(register|signup|sign_up|create_user|create_account|set_password|validate_password|password_strength|password_policy|new_user|registration)\b',
    re.IGNORECASE,
)

# Stored credential indicators (suggests auth verification, not policy)
_STORED_CREDENTIAL_PATTERN = re.compile(
    r'\b(stored_password|password_hash|user\.password|verify|check_password|bcrypt|argon2|passlib|compare_digest|hash|salt|hashed)\b',
    re.IGNORECASE,
)

# Established auth library indicators (to exclude from detection)
_ESTABLISHED_AUTH_LIBS = re.compile(
    r'\b(bcrypt|passlib|hashlib\.pbkdf2_hmac|check_password_hash|verify_password|'
    r'django\.contrib\.auth|flask_login|flask_jwt|jwt\.encode|jwt\.decode|'
    r'argon2|scrypt|werkzeug\.security)\b',
    re.IGNORECASE,
)

# Direct password comparison patterns (==, !=)
_PLAINTEXT_COMPARE_PATTERN = re.compile(
    # Password variable compared to string literal
    r'\b(password|passwd|pwd|pass|secret|credential|auth_token|api_key)\w*\s*(==|!=)\s*["\'][\w@!#$%^&*()_+\-=\[\]{};\':",.<>/?]{2,}["\']|'
    # Password variable compared to another variable
    r'\b(password|passwd|pwd|pass|secret|credential|auth_token|api_key)\w*\s*(==|!=)\s*\w+|'
    # Variable compared to password attribute
    r'\w+\s*(==|!=)\s*\w*\.?(password|passwd|pwd|pass|secret|credential)',
    re.IGNORECASE,
)

# Environment variable or config password comparison
_ENV_CONFIG_COMPARE = re.compile(
    r'\b\w+\s*(==|!=)\s*(os\.getenv|os\.environ|config|settings|env)\s*[\[\(]["\']([Pp]assword|[Pp][Ww][Dd]|[Ss]ecret|[Aa][Uu][Tt][Hh])',
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
    """Create a structured finding dict following CodeRisk AI schema.
    
    Scoring semantics (v0.1):
    - rule_score: canonical base score for this rule instance (impact * exploitability * confidence)
    - Used in max_category model: overall_score = max(category_scores)
    """
    base_score_f = (impact_f * exploitability_f) / 10.0
    rule_score_f = round(base_score_f * confidence_f, 2)
    severity = _severity_from_score(base_score_f)

    references = [{"type": "CWE", "value": cwe} for cwe in cwe_refs]
    references.append({"type": "OWASP", "value": "A07:2021 Identification and Authentication Failures"})

    return {
        "id": finding_id,
        "title": title,
        "description": description,
        "category": "A07_identification_authentication_failures",
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


def _is_in_auth_context(lines: list[str], line_idx: int, window: int = 10) -> bool:
    """
    Check if the line is within an authentication/login context.
    Looks at function names and nearby code within a window.
    """
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    
    for i in range(start, end):
        if _AUTH_CONTEXT_PATTERN.search(lines[i]):
            return True
    return False


def _uses_established_auth_lib(lines: list[str], line_idx: int, window: int = 15) -> bool:
    """
    Check if established auth libraries are used nearby.
    This helps reduce false positives for legitimate auth code.
    """
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    
    for i in range(start, end):
        if _ESTABLISHED_AUTH_LIBS.search(lines[i]):
            return True
    return False


def _is_in_signup_context(lines: list[str], line_idx: int, window: int = 15) -> bool:
    """
    Check if the line is within a registration/signup context.
    Looks at function names and nearby code within a window.
    """
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    
    for i in range(start, end):
        if _SIGNUP_CONTEXT_PATTERN.search(lines[i]):
            return True
    return False


def _has_stored_credential_indicators(lines: list[str], line_idx: int, window: int = 10) -> bool:
    """
    Check if there are stored credential indicators nearby.
    This suggests auth verification rather than password policy.
    """
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    
    for i in range(start, end):
        if _STORED_CREDENTIAL_PATTERN.search(lines[i]):
            return True
    return False


def _is_password_policy_check(line: str, lines: list[str], line_idx: int) -> tuple[bool, float, str]:
    """
    Detect password policy/strength validation (typically at signup/registration).
    Returns: (is_policy_check, confidence, explanation)
    """
    # Skip if using established auth libraries
    if _ESTABLISHED_AUTH_LIBS.search(line):
        return False, 0.0, ""
    
    # Check for manual password validation patterns (length, upper/lower/digit checks)
    manual_check_pattern = re.compile(
        r'\b(len\s*\(\s*\w*password\w*\s*\)|'
        r'password\w*\.(?:upper|lower|isdigit|isalpha|isupper|islower)|'
        r'any\s*\(.*[cC]\.(isupper|islower|isdigit).*password|'
        r'any\s*\(.*password.*[cC]\.(isupper|islower|isdigit)|'
        r'all\s*\(.*password)',
        re.IGNORECASE
    )
    
    if manual_check_pattern.search(line):
        # Check context to determine if this is password policy or auth verification
        in_signup = _is_in_signup_context(lines, line_idx)
        has_stored_cred = _has_stored_credential_indicators(lines, line_idx)
        in_auth = _is_in_auth_context(lines, line_idx)
        
        # If in signup context and no stored credentials, likely password policy
        if in_signup and not has_stored_cred:
            confidence = 0.60
            explanation = (
                "Password policy validation detected (length, character type checks). "
                "This appears to be password strength validation at registration. "
                "Ensure this is paired with proper password hashing and does not replace secure authentication."
            )
            return True, confidence, explanation
        
        # If NOT in auth context and no stored credentials, likely password policy
        if not in_auth and not has_stored_cred:
            confidence = 0.55
            explanation = (
                "Password validation detected. This appears to be password strength checking. "
                "Verify this is used for policy enforcement at registration and not for authentication."
            )
            return True, confidence, explanation
    
    return False, 0.0, ""


def _is_custom_auth_verification(line: str, lines: list[str], line_idx: int) -> tuple[bool, float, str]:
    """
    Detect custom authentication/verification logic.
    Returns: (is_custom_auth, confidence, explanation)
    """
    # Skip if using established auth libraries
    if _ESTABLISHED_AUTH_LIBS.search(line):
        return False, 0.0, ""
    
    # Check for direct password comparison in conditionals
    if re.search(r'\bif\b.*\b(password|passwd|pwd|pass)\w*\s*(==|!=)', line, re.IGNORECASE):
        # Higher confidence if in auth context or has stored credentials
        in_auth = _is_in_auth_context(lines, line_idx)
        has_stored_cred = _has_stored_credential_indicators(lines, line_idx)
        
        if in_auth or has_stored_cred:
            confidence = 0.75
            explanation = (
                "Custom password comparison detected in authentication context. "
                "This pattern suggests homegrown authentication rather than using vetted frameworks."
            )
            return True, confidence, explanation
    
    # Check for manual password validation in auth context
    manual_check_pattern = re.compile(
        r'\b(len\s*\(\s*\w*password\w*\s*\)|'
        r'password\w*\.(?:upper|lower|isdigit|isalpha)|'
        r'any\s*\(.*password|'
        r'all\s*\(.*password)',
        re.IGNORECASE
    )
    
    if manual_check_pattern.search(line):
        in_auth = _is_in_auth_context(lines, line_idx)
        has_stored_cred = _has_stored_credential_indicators(lines, line_idx)
        
        # Only flag as custom auth if in auth context or has stored credentials
        if in_auth or has_stored_cred:
            confidence = 0.70
            explanation = (
                "Manual password validation in authentication context. "
                "Custom password checks may bypass security best practices."
            )
            return True, confidence, explanation
    
    return False, 0.0, ""


def _is_plaintext_password_compare(line: str, lines: list[str], line_idx: int) -> tuple[bool, float, str, str]:
    """
    Detect plaintext password comparison.
    Returns: (is_plaintext, confidence, explanation, comparison_type)
    """
    # Skip if using established auth libraries (they handle comparison internally)
    if _ESTABLISHED_AUTH_LIBS.search(line):
        return False, 0.0, "", ""
    
    # Skip obvious non-password comparisons (status, role, type, etc.)
    # But only skip if the line doesn't also contain password-related comparisons
    non_password_pattern = re.compile(
        r'\b(status|role|type|email|user_type|account_type|level|permission)\s*(==|!=)',
        re.IGNORECASE
    )
    # Only apply this filter if there's no password-related comparison in the line
    if non_password_pattern.search(line) and not _PASSWORD_VAR_PATTERN.search(line):
        return False, 0.0, "", ""
    
    # Check for direct comparison to hardcoded password
    hardcoded_match = re.search(
        r'(\w+)\s*(==|!=)\s*["\']([^"\']{2,})["\']',
        line
    )
    if hardcoded_match:
        var_name = hardcoded_match.group(1)
        password_value = hardcoded_match.group(3)
        
        # Check if variable name suggests password (require password-related name)
        if _PASSWORD_VAR_PATTERN.search(var_name):
            confidence = 0.85
            explanation = (
                "Direct comparison of password to hardcoded plaintext string. "
                "This exposes credentials in source code and bypasses secure hashing."
            )
            return True, confidence, explanation, "hardcoded"
    
    # Check for password variable comparison (password == stored_password)
    if _PLAINTEXT_COMPARE_PATTERN.search(line):
        # Check context to boost confidence
        in_auth = _is_in_auth_context(lines, line_idx)
        has_password_var = _PASSWORD_VAR_PATTERN.search(line)
        
        if in_auth and has_password_var:
            confidence = 0.80
            explanation = (
                "Plaintext password comparison in authentication context. "
                "Passwords should be hashed with a strong algorithm (e.g., bcrypt) and compared using "
                "constant-time comparison to prevent timing attacks."
            )
            return True, confidence, explanation, "variable"
        elif has_password_var:
            confidence = 0.70
            explanation = (
                "Potential plaintext password comparison. "
                "Ensure passwords are hashed before comparison."
            )
            return True, confidence, explanation, "variable"
    
    # Check for environment/config password comparison
    if _ENV_CONFIG_COMPARE.search(line):
        confidence = 0.75
        explanation = (
            "Plaintext password comparison against environment variable or configuration value. "
            "While storing secrets in environment variables is better than hardcoding, "
            "direct comparison bypasses proper hashing and constant-time comparison."
        )
        return True, confidence, explanation, "env_config"
    
    # Additional check: comparison with user model attributes
    user_attr_match = re.search(
        r'(\w+)\s*(==|!=)\s*(\w+)\.(password|passwd|pwd|pass)',
        line,
        re.IGNORECASE
    )
    if user_attr_match:
        confidence = 0.75
        explanation = (
            "Direct comparison with password attribute from user object. "
            "This suggests plaintext password storage or comparison. Use a secure password "
            "hashing library with salt and verify using constant-time comparison."
        )
        return True, confidence, explanation, "attribute"
    
    return False, 0.0, "", ""


def detect_identification_authentication_failures(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    Identification and authentication failures detector (v0.1).
    - Detects custom password checking logic (AUTH.CUSTOM.PASSWORD_CHECK)
    - Detects plaintext password comparison (AUTH.PLAINTEXT.PASSWORD_COMPARE)
    - Returns schema-shaped finding dicts.
    
    Precedence handling (v0.1):
    - AUTH.PLAINTEXT.PASSWORD_COMPARE takes precedence over AUTH.CUSTOM.PASSWORD_CHECK
    - Same line ranges are not duplicated across both rules
    - Rationale: plaintext comparison is the more specific/severe issue
    """
    findings: list[dict[str, Any]] = []
    lines = source.splitlines()
    found_lines: set[int] = set()  # Track lines to avoid duplicates
    
    # Track line ranges covered by higher-precedence rules (for overlap suppression)
    # Key: (line_start, line_end), Value: rule_id that claimed it
    covered_ranges: dict[tuple[int, int], str] = {}

    for idx, line in enumerate(lines, start=1):
        # Skip if we already found something on this line
        if idx in found_lines:
            continue

        # Skip commented-out lines
        stripped = line.lstrip()
        if stripped.startswith('#'):
            continue
        
        # Skip blank lines
        if not stripped:
            continue

        # Check for plaintext password comparison FIRST (higher severity)
        # This takes precedence over custom password checks
        is_plaintext, plaintext_confidence, plaintext_explanation, compare_type = (
            _is_plaintext_password_compare(line, lines, idx - 1)
        )
        
        if is_plaintext:
            found_lines.add(idx)
            # Mark this line range as covered by AUTH.PLAINTEXT.PASSWORD_COMPARE (precedence)
            covered_ranges[(idx, idx)] = "AUTH.PLAINTEXT.PASSWORD_COMPARE"
            
            # Adjust severity based on comparison type
            if compare_type == "hardcoded":
                impact_f = 9.5
                exploitability_f = 9.0
                severity_note = "with hardcoded credentials"
            elif compare_type == "env_config":
                impact_f = 8.5
                exploitability_f = 8.0
                severity_note = "with configuration values"
            else:
                impact_f = 9.0
                exploitability_f = 8.5
                severity_note = ""
            
            title = f"Plaintext password comparison detected{' ' + severity_note if severity_note else ''}"
            
            findings.append(
                _make_finding(
                    finding_id="AUTH.PLAINTEXT.PASSWORD_COMPARE",
                    title=title,
                    description=(
                        "Direct plaintext comparison of passwords detected. Passwords should never be "
                        "compared directly in plaintext. This practice exposes credentials to various "
                        "attack vectors including memory dumps, log files, and timing attacks."
                    ),
                    file_path=file_path,
                    line_no=idx,
                    snippet=line.strip(),
                    explanation=plaintext_explanation,
                    impact_f=impact_f,
                    exploitability_f=exploitability_f,
                    confidence_f=plaintext_confidence,
                    cwe_refs=["CWE-256", "CWE-319", "CWE-798"],
                    exploit_scenario=(
                        "An attacker with access to the codebase, configuration files, memory dumps, or logs "
                        "could extract plaintext passwords and compromise user accounts. Additionally, "
                        "timing attacks may be feasible against non-constant-time string comparisons, "
                        "allowing attackers to enumerate valid credentials character by character."
                    ),
                    recommended_fix=(
                        "Never compare passwords in plaintext. Use a secure password hashing library "
                        "(e.g., bcrypt, scrypt, or Argon2 via passlib) to hash passwords with salt and "
                        "verify them using constant-time comparison. For configuration-based auth, "
                        "store hashed passwords instead of plaintext."
                    ),
                )
            )
            continue  # Skip custom password check for this line

        # Check for password policy validation FIRST (lower severity, info-level)
        # This takes precedence over custom auth to avoid double-firing
        is_policy, policy_confidence, policy_explanation = _is_password_policy_check(
            line, lines, idx - 1  # idx is 1-based, list is 0-based
        )
        
        if is_policy:
            found_lines.add(idx)
            
            # Skip if already covered by higher-precedence rule (plaintext)
            _is_overlapped = False
            for (range_start, range_end), claiming_rule in covered_ranges.items():
                if range_start <= idx <= range_end:
                    _is_overlapped = True
                    break
            
            if _is_overlapped:
                continue
            
            # Mark this line as covered by password policy check
            covered_ranges[(idx, idx)] = "AUTH.PASSWORD_POLICY.CHECK"
            
            # Info-level severity for password policy checks
            impact_f = 3.0
            exploitability_f = 2.0
            
            findings.append(
                _make_finding(
                    finding_id="AUTH.PASSWORD_POLICY.CHECK",
                    title="Password policy validation detected",
                    description=(
                        "Password strength validation detected (length, character type requirements). "
                        "This is typically used at signup/registration to enforce strong passwords. "
                        "Ensure this is paired with proper password hashing (bcrypt, argon2) and secure "
                        "verification, and is not used as a substitute for proper authentication."
                    ),
                    file_path=file_path,
                    line_no=idx,
                    snippet=line.strip(),
                    explanation=policy_explanation,
                    impact_f=impact_f,
                    exploitability_f=exploitability_f,
                    confidence_f=policy_confidence,
                    cwe_refs=["CWE-521"],
                    exploit_scenario=(
                        "If password policy checks are used in place of proper authentication "
                        "or are bypassed, attackers may be able to register accounts with weak "
                        "passwords susceptible to brute-force or dictionary attacks."
                    ),
                    recommended_fix=(
                        "Ensure password policy validation is used at registration/password change only, "
                        "paired with secure password hashing (bcrypt, argon2, scrypt via passlib). "
                        "Never use policy checks for authentication; use proper verify methods instead."
                    ),
                )
            )
            continue
        
        # Check for custom auth verification (only if not already detected as plaintext or policy)
        is_custom_auth, custom_confidence, custom_explanation = _is_custom_auth_verification(
            line, lines, idx - 1
        )
        
        if is_custom_auth:
            found_lines.add(idx)
            
            # Skip if already covered by higher-precedence rule
            _is_overlapped = False
            for (range_start, range_end), claiming_rule in covered_ranges.items():
                if range_start <= idx <= range_end:
                    _is_overlapped = True
                    break
            
            if _is_overlapped:
                continue
            
            # Mark as covered by custom auth verification
            covered_ranges[(idx, idx)] = "AUTH.CUSTOM.AUTH_VERIFICATION"
            
            # Medium-high severity for custom auth verification
            impact_f = 8.5
            exploitability_f = 7.5
            
            findings.append(
                _make_finding(
                    finding_id="AUTH.CUSTOM.AUTH_VERIFICATION",
                    title="Custom authentication verification logic detected",
                    description=(
                        "Homegrown password verification or authentication logic detected. "
                        "Custom authentication implementations often lack security best practices "
                        "such as proper hashing, salting, and constant-time comparison."
                    ),
                    file_path=file_path,
                    line_no=idx,
                    snippet=line.strip(),
                    explanation=custom_explanation,
                    impact_f=impact_f,
                    exploitability_f=exploitability_f,
                    confidence_f=custom_confidence,
                    cwe_refs=["CWE-287", "CWE-328"],
                    exploit_scenario=(
                        "An attacker could exploit weaknesses in custom authentication logic to bypass "
                        "authentication checks, perform timing attacks to enumerate valid credentials, "
                        "or leverage missing security controls like rate limiting and account lockout."
                    ),
                    recommended_fix=(
                        "Replace custom authentication logic with vetted libraries such as "
                        "bcrypt or argon2 via passlib, Django's authentication system, Flask-Login, "
                        "or similar frameworks that implement security best practices including "
                        "proper hashing, salting, and constant-time comparison."
                    ),
                )
            )
            continue

    return deduplicate_findings(findings)
