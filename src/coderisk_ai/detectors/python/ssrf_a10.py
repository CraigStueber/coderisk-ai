"""
Server-Side Request Forgery (SSRF) detector for OWASP A10.

Detects potential SSRF vulnerabilities when URLs passed to HTTP request functions
(requests.get/post/request, urllib.request.urlopen) are constructed from user-controlled input.

Taint sources:
- input() calls
- sys.argv access
- os.environ access
- Flask request parameters (request.args, request.form, request.json, request.values)
- FastAPI query/path parameters

SSRF sinks:
- requests.get/post/put/delete/patch/request/head
- urllib.request.urlopen
- urllib.request.Request

Implementation uses AST traversal with basic taint tracking.
"""
from __future__ import annotations

import ast
from typing import Any

from .detector_utils import deduplicate_findings


# Safe function names that indicate URL validation/sanitization
SAFE_FN_NAMES = {
    "validate_url",
    "sanitize_url",
    "allowlist_url",
    "is_allowed_host",
    "is_safe_url",
    "normalize_url",
}


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


class SSRFDetector(ast.NodeVisitor):
    """AST visitor to detect SSRF vulnerabilities with taint tracking."""
    
    def __init__(self, source: str, file_path: str):
        self.source = source
        self.file_path = file_path
        self.lines = source.splitlines()
        self.findings: list[dict[str, Any]] = []
        
        # Tainted variables (set of variable names that contain user input)
        self.tainted_vars: set[str] = set()
        # Track the original source for each tainted variable
        self.tainted_vars_sources: dict[str, str] = {}
        
        # Track if we've seen certain imports
        self.has_requests = False
        self.has_urllib = False
        self.has_flask_request = False
        self.has_fastapi = False
    
    def visit_Import(self, node: ast.Import) -> None:
        """Track imports of requests, urllib, flask, fastapi."""
        for alias in node.names:
            if alias.name == "requests":
                self.has_requests = True
            elif alias.name.startswith("urllib"):
                self.has_urllib = True
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from imports."""
        if node.module:
            if node.module.startswith("flask"):
                for alias in node.names:
                    if alias.name == "request":
                        self.has_flask_request = True
            elif node.module.startswith("fastapi"):
                self.has_fastapi = True
        self.generic_visit(node)
    
    def _is_taint_source(self, node: ast.AST) -> tuple[bool, str]:
        """Check if a node represents a taint source. Returns (is_tainted, source_name)."""
        # input() call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return True, "input()"
        
        # sys.argv access
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                if (isinstance(node.value.value, ast.Name) and 
                    node.value.value.id == "sys" and 
                    node.value.attr == "argv"):
                    return True, "sys.argv"
        
        # os.environ access
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                if (isinstance(node.value.value, ast.Name) and 
                    node.value.value.id == "os" and 
                    node.value.attr == "environ"):
                    return True, "os.environ"
        
        # os.getenv() call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if (isinstance(node.func.value, ast.Name) and 
                    node.func.value.id == "os" and 
                    node.func.attr == "getenv"):
                    return True, "os.getenv()"
        
        # Flask request.args, request.form, request.json, request.values, request.get_json()
        if isinstance(node, ast.Attribute):
            if (isinstance(node.value, ast.Name) and 
                node.value.id == "request" and 
                node.attr in ("args", "form", "json", "values", "data", "params")):
                return True, f"request.{node.attr}"
        
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if (isinstance(node.func.value, ast.Name) and 
                    node.func.value.id == "request" and 
                    node.func.attr in ("get_json", "get_data")):
                    return True, f"request.{node.func.attr}()"
        
        # Subscript on request.args/form/json/values
        if isinstance(node, ast.Subscript):
            is_source, source_name = self._is_taint_source(node.value)
            if is_source:
                return True, source_name
        
        # Call with .get() on request attributes
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "get":
                    is_source, source_name = self._is_taint_source(node.func.value)
                    if is_source:
                        return True, source_name
        
        return False, ""
    
    def _is_tainted(self, node: ast.AST) -> tuple[bool, str]:
        """
        Check if a node is tainted (contains user input).
        Returns (is_tainted, explanation).
        """
        # Direct taint source
        is_source, source_name = self._is_taint_source(node)
        if is_source:
            return True, source_name
        
        # Tainted variable reference
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            # Try to get the original source if we tracked it
            var_source = self.tainted_vars_sources.get(node.id, node.id)
            return True, f"{var_source} (via variable '{node.id}')"
        
        # Subscript on tainted variable (e.g., data["webhook_url"])
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                var_source = self.tainted_vars_sources.get(node.value.id, node.value.id)
                return True, f"{var_source} (via variable '{node.value.id}')"
        
        # Attribute on tainted variable (e.g., payload.url)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                var_source = self.tainted_vars_sources.get(node.value.id, node.value.id)
                return True, f"{var_source} (via variable '{node.value.id}')"
        
        # String concatenation with tainted value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_tainted, left_exp = self._is_tainted(node.left)
            right_tainted, right_exp = self._is_tainted(node.right)
            if left_tainted or right_tainted:
                source = left_exp if left_tainted else right_exp
                return True, f"{source} (string concatenation)"
        
        # f-string with tainted value
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    tainted, exp = self._is_tainted(value.value)
                    if tainted:
                        return True, f"{exp} (f-string interpolation)"
        
        # .format() call on string
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                # Check if any format arguments are tainted
                for arg in node.args:
                    tainted, exp = self._is_tainted(arg)
                    if tainted:
                        return True, f"{exp} (.format() method)"
                for keyword in node.keywords:
                    tainted, exp = self._is_tainted(keyword.value)
                    if tainted:
                        return True, f"{exp} (.format() method)"
        
        return False, ""
    
    def _is_constant_string(self, node: ast.AST) -> bool:
        """Check if a node is a constant string literal (safe URL)."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        # Python 3.7 compatibility
        if isinstance(node, ast.Str):
            return True
        return False
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments from taint sources."""
        # Check if RHS is a call to a safe validation/sanitization function
        is_safe_call = False
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name):
                if node.value.func.id in SAFE_FN_NAMES:
                    is_safe_call = True
        
        if is_safe_call:
            # Safe function call - remove from tainted vars if present
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.discard(target.id)
                    self.tainted_vars_sources.pop(target.id, None)
        else:
            # Check if assignment is from tainted source
            is_tainted, taint_source = self._is_tainted(node.value)
            
            if is_tainted:
                # Mark all assigned variables as tainted
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
                        # Track the original source for better explanations
                        self.tainted_vars_sources[target.id] = taint_source
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Detect SSRF sinks with tainted arguments."""
        sink_function = None
        url_arg = None
        
        # Check for requests.get/post/put/delete/patch/request/head
        if isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name) and 
                node.func.value.id == "requests" and 
                node.func.attr in ("get", "post", "put", "delete", "patch", "request", "head", "options")):
                sink_function = f"requests.{node.func.attr}"
                # For requests.request, URL is second arg (args[1]); for others, it's first (args[0])
                if node.func.attr == "request":
                    if len(node.args) >= 2:
                        url_arg = node.args[1]
                else:
                    if node.args:
                        url_arg = node.args[0]
        
        # Check for urllib.request.urlopen
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Attribute):
                if (isinstance(node.func.value.value, ast.Name) and 
                    node.func.value.value.id == "urllib" and 
                    node.func.value.attr == "request" and 
                    node.func.attr == "urlopen"):
                    sink_function = "urllib.request.urlopen"
                    if node.args:
                        url_arg = node.args[0]
        
        # Check if URL argument is tainted
        if sink_function and url_arg:
            # Skip if it's a constant string (safe)
            if self._is_constant_string(url_arg):
                self.generic_visit(node)
                return
            
            is_tainted, taint_explanation = self._is_tainted(url_arg)
            
            if is_tainted:
                lineno = node.lineno
                snippet = self._get_line(lineno)
                
                # Calculate risk score - adjusted for High severity
                # SSRF is a serious vulnerability that can access internal services,
                # cloud metadata, and bypass network segmentation
                # Target: rule_score >= 7.0 for High severity
                impact = 9.1  # High impact: can access internal/cloud resources
                exploitability = 9.1  # High exploitability: easy to exploit if URL is controllable
                
                # Adjust confidence based on taint source clarity
                if any(direct in taint_explanation for direct in ["input()", "sys.argv", "os.environ", "os.getenv()"]):
                    confidence = 0.85  # Direct user input sources
                elif "request." in taint_explanation:
                    confidence = 0.85  # Web framework parameters
                else:
                    confidence = 0.75  # Derived/propagated taint
                
                base_score = (impact * exploitability) / 10.0
                rule_score = round(base_score * confidence, 2)
                severity = _severity_from_score(rule_score)
                
                # Build detailed explanation
                explanation = f"Call to {sink_function} with URL derived from {taint_explanation}."
                
                finding = {
                    "rule_id": "A10_SSRF.HTTP_REQUEST_TAINTED_URL",
                    "id": f"A10_SSRF.HTTP_REQUEST_TAINTED_URL:{self.file_path}:{lineno}",
                    "title": f"Server-Side Request Forgery via {sink_function}" ,
                    "description": f"The function {sink_function} is called with a URL derived from {taint_explanation}. This allows an attacker to make the server send requests to arbitrary destinations.",
                    "category": "A10_ssrf",
                    "severity": severity,
                    "rule_score": rule_score,
                    "confidence": confidence,
                    "exploit_scenario": f"An attacker can control the URL passed to {sink_function} via {taint_explanation}. This enables accessing internal services (cloud metadata at 169.254.169.254, internal APIs, databases), port scanning internal networks, or exfiltrating data via DNS/HTTP callbacks.",
                    "recommended_fix": "Validate and sanitize URLs before making requests. Use an allowlist of permitted domains/schemes. Avoid directly using user input in URL construction. Consider using a proxy or firewall to restrict outbound requests.",
                    "evidence": {
                        "file": self.file_path,
                        "line_start": lineno,
                        "line_end": lineno,
                        "snippet": snippet,
                        "explanation": explanation,
                    },
                    "references": [
                        {"type": "CWE", "value": "CWE-918"},
                        {"type": "OWASP", "value": "A10:2021 Server-Side Request Forgery"},
                    ],
                }
                self.findings.append(finding)
        
        self.generic_visit(node)
    
    def _get_line(self, lineno: int) -> str:
        """Get source line by number (1-indexed)."""
        if 0 < lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""


def detect_ssrf(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    Detect Server-Side Request Forgery (SSRF) vulnerabilities.
    
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
    
    detector = SSRFDetector(source, file_path)
    detector.visit(tree)
    
    return deduplicate_findings(detector.findings)
