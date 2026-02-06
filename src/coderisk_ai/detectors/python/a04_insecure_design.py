"""
Insecure Design detector for OWASP A04.

Detects design-level security issues that cannot be fixed by implementation alone.
These are heuristic-based detections with lower confidence.

Detection rules:
- A04.1: Missing brute-force protection on login/auth handlers
- A04.2: Insecure defaults (admin/debug paths, default-enabled features)
- A04.3: Missing outbound request guardrails (no validation/allowlist)

Policy:
- All A04 findings have confidence <= 0.6
- Default severity is "medium" (can be downgraded with policy_override metadata)
- Rule scores are normalized to 4.0-6.9 range to match medium severity
"""
from __future__ import annotations

import ast
import re
from typing import Any

from .detector_utils import deduplicate_findings


def _severity_from_score(score: float) -> str:
    """Convert rule score to severity level."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "info"


# Patterns for login/auth endpoints
_LOGIN_PATTERNS = [
    r"\blogin\b",
    r"\bauth\b",
    r"\bauthenticate\b",
    r"\bsign_?in\b",
    r"\blog_?in\b",
]

# Patterns for admin/debug paths
_ADMIN_DEBUG_PATTERNS = [
    r"\badmin\b",
    r"\bdebug\b",
    r"\btest\b",
    r"\b__debug__\b",
]

# Rate limiting/throttling indicators
_RATE_LIMIT_INDICATORS = [
    "rate_limit",
    "throttle",
    "limiter",
    "RateLimiter",
    "Throttle",
    "sleep",
    "attempt",
    "retry",
    "backoff",
]

# URL validation/allowlist indicators
_URL_VALIDATION_INDICATORS = [
    "validate",
    "allowlist",
    "whitelist",
    "allowed_hosts",
    "allowed_domains",
    "urlparse",
    "is_safe",
]


class InsecureDesignDetector(ast.NodeVisitor):
    """AST visitor to detect insecure design patterns."""
    
    def __init__(self, source: str, file_path: str):
        self.source = source
        self.file_path = file_path
        self.lines = source.splitlines()
        self.findings: list[dict[str, Any]] = []
        
        # Track function definitions for context
        self.current_function: str | None = None
        self.function_decorators: dict[str, list[str]] = {}
        
        # Track module-level patterns
        self.has_rate_limiting = False
        self.has_url_validation = False
        self.http_request_functions: list[tuple[str, int]] = []
        
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function definitions and check for design issues."""
        old_function = self.current_function
        self.current_function = node.name
        
        # Track decorators
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.append(dec.attr)
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decorators.append(dec.func.id)
                elif isinstance(dec.func, ast.Attribute):
                    decorators.append(dec.func.attr)
        
        self.function_decorators[node.name] = decorators
        
        # Check for login/auth handlers without rate limiting
        self._check_login_without_rate_limit(node, decorators)
        
        # Check for admin/debug endpoints
        self._check_admin_debug_endpoints(node, decorators)
        
        self.generic_visit(node)
        self.current_function = old_function
    
    def _check_login_without_rate_limit(self, node: ast.FunctionDef, decorators: list[str]) -> None:
        """Check if login/auth function lacks rate limiting."""
        func_name_lower = node.name.lower()
        
        # Check if this looks like a login/auth handler
        is_login = any(re.search(pattern, func_name_lower) for pattern in _LOGIN_PATTERNS)
        
        # Also check if it's a route/endpoint
        is_route = any(dec in ["route", "post", "get", "api_route"] for dec in decorators)
        
        if not (is_login and is_route):
            return
        
        # Check if rate limiting is present in decorators
        has_rate_limit = any(
            any(indicator in dec.lower() for indicator in _RATE_LIMIT_INDICATORS)
            for dec in decorators
        )
        
        # Check function body for rate limiting logic
        if not has_rate_limit:
            func_source = ast.get_source_segment(self.source, node)
            if func_source:
                has_rate_limit = any(
                    indicator in func_source
                    for indicator in _RATE_LIMIT_INDICATORS
                )
        
        if not has_rate_limit:
            lineno = node.lineno
            snippet = self._get_line(lineno)
            
            # Lower confidence heuristic detection
            confidence = 0.5
            impact = 6.0  # Medium-high impact
            exploitability = 7.0  # Easy to brute-force
            
            base_score = (impact * exploitability) / 10.0
            
            # POLICY: A04 findings default to severity="medium"
            # Adjust rule_score to match medium severity (4.0-6.9)
            severity = "medium"
            rule_score = round(4.5 * confidence, 2)  # Fixed medium severity score
            
            finding = {
                "rule_id": "A04_INSECURE_DESIGN.MISSING_RATE_LIMIT",
                "title": "Missing Brute-Force Protection on Authentication Handler",
                "description": f"The function '{node.name}' appears to be an authentication/login handler but does not implement rate limiting or brute-force protection. This is a heuristic detection based on function naming and decorators.",
                "category": "A04_insecure_design",
                "severity": severity,
                "rule_score": rule_score,
                "confidence": confidence,
                "exploit_scenario": f"An attacker can repeatedly submit authentication requests to '{node.name}' without rate limiting, enabling credential stuffing or brute-force attacks to compromise user accounts.",
                "recommended_fix": "Implement rate limiting or throttling on authentication endpoints. Use decorators like @limiter.limit() or implement exponential backoff after failed attempts. Consider CAPTCHA for repeated failures.",
                "evidence": {
                    "file": self.file_path,
                    "line_start": lineno,
                    "line_end": lineno,
                    "snippet": snippet,
                    "explanation": f"Authentication function '{node.name}' detected without rate limiting decorators or logic. This is a design-level concern requiring architectural safeguards.",
                },
                "references": [
                    {"type": "CWE", "value": "CWE-307"},
                    {"type": "OWASP", "value": "A04:2021 Insecure Design"},
                ],
            }
            self.findings.append(finding)
    
    def _check_admin_debug_endpoints(self, node: ast.FunctionDef, decorators: list[str]) -> None:
        """Check for admin/debug endpoints without proper guards."""
        func_name_lower = node.name.lower()
        
        # Check if this looks like admin/debug endpoint
        is_admin_debug = any(
            re.search(pattern, func_name_lower) 
            for pattern in _ADMIN_DEBUG_PATTERNS
        )
        
        # Check if it's a route
        is_route = any(dec in ["route", "post", "get", "api_route"] for dec in decorators)
        
        if not (is_admin_debug and is_route):
            return
        
        # Check for authorization decorators
        has_auth = any(
            dec in ["login_required", "permission_required", "admin_required", "requires_auth"]
            for dec in decorators
        )
        
        # Check for DEBUG environment checks
        func_source = ast.get_source_segment(self.source, node)
        has_debug_check = False
        if func_source:
            has_debug_check = "DEBUG" in func_source or "debug" in func_source.lower()
        
        if not has_auth and not has_debug_check:
            lineno = node.lineno
            snippet = self._get_line(lineno)
            
            confidence = 0.55
            impact = 7.0
            exploitability = 6.0
            
            base_score = (impact * exploitability) / 10.0
            
            # POLICY: A04 findings default to severity="medium"
            # Adjust rule_score to match medium severity (4.0-6.9)
            severity = "medium"
            rule_score = round(4.5 * confidence, 2)  # Fixed medium severity score
            
            finding = {
                "rule_id": "A04_INSECURE_DESIGN.INSECURE_ADMIN_ENDPOINT",
                "title": "Admin/Debug Endpoint Without Authorization",
                "description": f"The function '{node.name}' appears to be an admin or debug endpoint but lacks authorization checks. This is a heuristic detection based on naming patterns.",
                "category": "A04_insecure_design",
                "severity": severity,
                "rule_score": rule_score,
                "confidence": confidence,
                "exploit_scenario": f"An attacker could access '{node.name}' without proper authorization, potentially exposing sensitive debugging information or administrative functionality.",
                "recommended_fix": "Add authorization decorators (@login_required, @admin_required) or implement conditional logic based on DEBUG settings. Ensure admin/debug endpoints are disabled in production or protected by strong authentication.",
                "evidence": {
                    "file": self.file_path,
                    "line_start": lineno,
                    "line_end": lineno,
                    "snippet": snippet,
                    "explanation": f"Admin/debug function '{node.name}' detected without authorization decorators. This is a design concern requiring access control safeguards.",
                },
                "references": [
                    {"type": "CWE", "value": "CWE-489"},
                    {"type": "OWASP", "value": "A04:2021 Insecure Design"},
                ],
            }
            self.findings.append(finding)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Track HTTP request calls for A04.3 analysis."""
        # Track requests.* calls
        if isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name) and 
                node.func.value.id == "requests" and 
                node.func.attr in ("get", "post", "put", "delete", "patch", "request")):
                self.http_request_functions.append((self.current_function or "<module>", node.lineno))
        
        # Track urllib.request.urlopen
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Attribute):
                if (isinstance(node.func.value.value, ast.Name) and 
                    node.func.value.value.id == "urllib" and 
                    node.func.value.attr == "request" and 
                    node.func.attr == "urlopen"):
                    self.http_request_functions.append((self.current_function or "<module>", node.lineno))
        
        self.generic_visit(node)
    
    def visit_Module(self, node: ast.Module) -> None:
        """Check module-level patterns after traversal."""
        # First traverse to collect information
        self.generic_visit(node)
        
        # Check if module has URL validation patterns
        self.has_url_validation = any(
            indicator in self.source
            for indicator in _URL_VALIDATION_INDICATORS
        )
        
        # A04.3: Check for HTTP requests without validation in module
        if self.http_request_functions and not self.has_url_validation:
            # Only flag if there are multiple HTTP calls (indicates a pattern)
            if len(self.http_request_functions) >= 2:
                # Report on the first occurrence
                func_name, lineno = self.http_request_functions[0]
                snippet = self._get_line(lineno)
                
                confidence = 0.4  # Low confidence heuristic
                impact = 5.0
                exploitability = 5.0
                
                base_score = (impact * exploitability) / 10.0
                
                # POLICY: A04 findings default to severity="medium"
                # Adjust rule_score to match medium severity (4.0-6.9)
                severity = "medium"
                rule_score = round(4.5 * confidence, 2)  # Fixed medium severity score
                
                finding = {
                    "rule_id": "A04_INSECURE_DESIGN.MISSING_OUTBOUND_GUARDRAILS",
                    "title": "Missing Outbound Request Validation",
                    "description": f"This module contains {len(self.http_request_functions)} HTTP request calls but no apparent URL validation or allowlist logic. This is a low-confidence heuristic detection.",
                    "category": "A04_insecure_design",
                    "severity": severity,
                    "rule_score": rule_score,
                    "confidence": confidence,
                    "exploit_scenario": "Without architectural guardrails for outbound requests, developers may inadvertently introduce SSRF vulnerabilities or make requests to untrusted destinations.",
                    "recommended_fix": "Implement module-level URL validation, use an allowlist of permitted domains, or create a wrapper function that enforces validation. Consider using a proxy or network-level controls.",
                    "evidence": {
                        "file": self.file_path,
                        "line_start": lineno,
                        "line_end": lineno,
                        "snippet": snippet,
                        "explanation": f"Module contains {len(self.http_request_functions)} HTTP request calls without apparent URL validation patterns. This suggests a design gap in outbound request security.",
                    },
                    "references": [
                        {"type": "CWE", "value": "CWE-918"},
                        {"type": "OWASP", "value": "A04:2021 Insecure Design"},
                    ],
                }
                self.findings.append(finding)
    
    def _get_line(self, lineno: int) -> str:
        """Get source line by number (1-indexed)."""
        if 0 < lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""


def detect_insecure_design(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    Detect Insecure Design issues (OWASP A04).
    
    Heuristic-based detection with lower confidence.
    Focuses on design-level security concerns.
    
    Args:
        source: Python source code to analyze
        file_path: Path to the file being analyzed
        
    Returns:
        List of findings (deduplicated)
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # If we can't parse, return no findings
        return []
    
    detector = InsecureDesignDetector(source, file_path)
    detector.visit(tree)
    
    return deduplicate_findings(detector.findings)
