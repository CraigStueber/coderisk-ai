from __future__ import annotations

import re
from typing import Any

# TOML parsing: prefer tomllib (Python 3.11+) else tomli
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore

from .detector_utils import deduplicate_findings


# v0.1: Heuristic-based patterns for vulnerable and outdated components detection

# Known deprecated packages with their recommended alternatives
# Keep this list small and justified for v0.1
DEPRECATED_PACKAGES = {
    "pycrypto": {
        "reason": "Deprecated and unmaintained; contains security vulnerabilities",
        "alternative": "pycryptodome or cryptography",
        "confidence": 0.90,
        "security_critical": True,  # Cryptographic library
    },
    "oauth2": {
        "reason": "Largely unmaintained; superseded by more robust libraries",
        "alternative": "oauthlib or authlib",
        "confidence": 0.85,
        "security_critical": True,  # OAuth/authentication
    },
    "nose": {
        "reason": "Officially deprecated and no longer maintained",
        "alternative": "pytest",
        "confidence": 0.90,
        "security_critical": False,  # Testing framework
    },
    "django-rest-swagger": {
        "reason": "Deprecated in favor of drf-spectacular",
        "alternative": "drf-spectacular or drf-yasg",
        "confidence": 0.85,
        "security_critical": False,  # Documentation tool
    },
    "python-jose": {
        "reason": "Limited maintenance; potential security concerns",
        "alternative": "python-jose[cryptography] or PyJWT",
        "confidence": 0.75,
        "security_critical": True,  # JWT/auth library
    },
}

# Regex patterns for parsing dependency specifications

# Requirements.txt style: package_name[extras]==version or package_name>=1.0
_REQ_LINE_PATTERN = re.compile(
    r'^\s*([a-zA-Z0-9][\w\-\.]*)'  # package name
    r'(?:\[[^\]]+\])?'  # optional extras [crypto,tests]
    r'\s*([<>=!~]+.*)?$',  # optional version specifier
    re.IGNORECASE,
)

# PyProject.toml dependency line: package_name = "version_spec" or package_name = {version = "..."}
_PYPROJECT_DEP_PATTERN = re.compile(
    r'^\s*([a-zA-Z0-9][\w\-\.]*)\s*=\s*["\']([^"\']*)["\']',  # package = "version"
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


def _is_security_critical_package(package_name: str) -> bool:
    """
    Heuristic check if a package name suggests security-critical functionality.
    Used for severity calibration (v0.1 heuristic only).
    
    Returns True if package name contains security-related keywords:
    crypto, crypt, jwt, oauth, auth, jose, ssl, tls, security, identity, signing, encryption
    """
    name_lower = package_name.lower()
    security_keywords = [
        "crypto", "crypt", "jwt", "oauth", "auth", "jose",
        "ssl", "tls", "security", "identity", "sign", "encrypt"
    ]
    return any(keyword in name_lower for keyword in security_keywords)


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
    references.append({"type": "OWASP", "value": "A06:2021 Vulnerable and Outdated Components"})

    return {
        "id": finding_id,
        "title": title,
        "description": description,
        "category": "A06_vulnerable_outdated_components",
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


def _is_pinned_version(version_spec: str | None) -> bool:
    """Check if a version specifier represents a pinned (exact) version."""
    if not version_spec:
        return False
    
    version_spec = version_spec.strip()
    
    # Empty or wildcard is unpinned
    if not version_spec or version_spec == "*":
        return False
    
    # Exact version with == is pinned
    if version_spec.startswith("=="):
        return True
    
    # Loose specifiers are unpinned
    if any(op in version_spec for op in [">=", ">", "~=", "!=", "<", "*"]):
        return False
    
    # If no operator, it might be a bare version (depends on context, but treat as unpinned for safety)
    return False


def _is_loose_version_spec(version_spec: str | None) -> bool:
    """Check if a version specifier is loose/unbounded (allows many versions)."""
    if not version_spec:
        return True  # No version is loose
    
    version_spec = version_spec.strip()
    
    # Wildcard or empty
    if not version_spec or version_spec == "*":
        return True
    
    # Loose operators
    if any(op in version_spec for op in [">=", ">", "~=", "<="]):
        return True
    
    return False


def _check_pyproject_version(version_spec: str) -> tuple[bool, str]:
    """
    Check if a pyproject.toml version spec is pinned.
    Returns (is_pinned, looseness_description).
    
    Poetry uses bare versions like "1.21.0" as exact pins (no ^ or ~ prefix).
    """
    version_spec = version_spec.strip()
    
    # Empty or wildcard
    if not version_spec or version_spec == "*":
        return (False, "wildcard (*) allows any version")
    
    # Caret version (^1.2.3) - allows compatible updates
    if version_spec.startswith("^"):
        return (False, "caret (^) allows compatible updates")
    
    # Tilde version (~1.2.3 or ~=1.2.3) - allows patch updates
    if version_spec.startswith("~"):
        return (False, "tilde (~) allows patch-level updates")
    
    # Exact version with == operator (PEP 440 style)
    if version_spec.startswith("=="):
        return (True, "")
    
    # Check for loose operators before checking bare version
    if any(op in version_spec for op in [">=", ">", "<", "<=", "!=", "~="]):
        return (False, "loose operator allows multiple versions")
    
    # Bare version like "1.2.3" or "1.2.3rc1" - Poetry treats as exact pin
    # Match: digits, dots, and optional pre-release suffixes (rc, alpha, beta, dev, post)
    bare_version_pattern = r'^\d+(\.\d+)*([a-zA-Z]+\d*)?$'
    if re.match(bare_version_pattern, version_spec):
        return (True, "")
    
    # Default: treat as unpinned if uncertain
    return (False, "version constraint not strictly pinned")


def _parse_pyproject_toml(source: str, file_path: str) -> list[tuple[str, str, int]]:
    """
    Parse pyproject.toml and extract dependencies with line numbers.
    Returns list of (package_name, version_spec, line_number) tuples.
    Supports both PEP 621 and Poetry formats.
    """
    if tomllib is None:
        # TOML library not available, fail closed
        return []
    
    try:
        data = tomllib.loads(source)
    except Exception:
        # TOML parse error, fail closed
        return []
    
    dependencies: list[tuple[str, str, int]] = []
    lines = source.splitlines()
    
    # Helper to find line number for a package in source
    def find_line_number(package_name: str, section_name: str) -> int:
        """Find approximate line number where package is defined."""
        # Look for the package name after the section header
        in_section = False
        section_pattern = re.escape(section_name)
        for idx, line in enumerate(lines, start=1):
            if re.search(rf'\[{section_pattern}\]', line):
                in_section = True
            elif in_section:
                if line.strip().startswith("["):
                    # Entered new section
                    break
                if package_name.lower() in line.lower():
                    return idx
        return 1  # Fallback
    
    # PEP 621 format: [project] dependencies
    if "project" in data:
        project = data["project"]
        
        # [project] dependencies = ["pkg>=1.0", "pkg2==2.0", ...]
        if "dependencies" in project and isinstance(project["dependencies"], list):
            for dep_str in project["dependencies"]:
                if not isinstance(dep_str, str):
                    continue
                # Parse requirement string: "package[extras]>=1.0,<2.0"
                match = _REQ_LINE_PATTERN.match(dep_str)
                if match:
                    pkg_name = match.group(1).lower().strip()
                    version_spec = match.group(2) or ""
                    line_no = find_line_number(pkg_name, "project")
                    dependencies.append((pkg_name, version_spec, line_no))
        
        # [project.optional-dependencies] section
        if "optional-dependencies" in project and isinstance(project["optional-dependencies"], dict):
            for group_name, deps in project["optional-dependencies"].items():
                if not isinstance(deps, list):
                    continue
                for dep_str in deps:
                    if not isinstance(dep_str, str):
                        continue
                    match = _REQ_LINE_PATTERN.match(dep_str)
                    if match:
                        pkg_name = match.group(1).lower().strip()
                        version_spec = match.group(2) or ""
                        line_no = find_line_number(pkg_name, f"project.optional-dependencies.{group_name}")
                        dependencies.append((pkg_name, version_spec, line_no))
    
    # Poetry format: [tool.poetry.dependencies]
    if "tool" in data and "poetry" in data["tool"]:
        poetry = data["tool"]["poetry"]
        
        # [tool.poetry.dependencies]
        if "dependencies" in poetry and isinstance(poetry["dependencies"], dict):
            for pkg_name, version_data in poetry["dependencies"].items():
                pkg_lower = pkg_name.lower()
                # Ignore python version constraint
                if pkg_lower == "python":
                    continue
                
                # Extract version spec
                version_spec = ""
                if isinstance(version_data, str):
                    version_spec = version_data
                elif isinstance(version_data, dict) and "version" in version_data:
                    version_spec = version_data["version"]
                
                line_no = find_line_number(pkg_lower, "tool.poetry.dependencies")
                dependencies.append((pkg_lower, version_spec, line_no))
        
        # [tool.poetry.group.<name>.dependencies]
        if "group" in poetry and isinstance(poetry["group"], dict):
            for group_name, group_data in poetry["group"].items():
                if not isinstance(group_data, dict) or "dependencies" not in group_data:
                    continue
                if not isinstance(group_data["dependencies"], dict):
                    continue
                    
                for pkg_name, version_data in group_data["dependencies"].items():
                    pkg_lower = pkg_name.lower()
                    if pkg_lower == "python":
                        continue
                    
                    version_spec = ""
                    if isinstance(version_data, str):
                        version_spec = version_data
                    elif isinstance(version_data, dict) and "version" in version_data:
                        version_spec = version_data["version"]
                    
                    line_no = find_line_number(pkg_lower, f"tool.poetry.group.{group_name}.dependencies")
                    dependencies.append((pkg_lower, version_spec, line_no))
        
        # [tool.poetry.dev-dependencies] (legacy Poetry format)
        if "dev-dependencies" in poetry and isinstance(poetry["dev-dependencies"], dict):
            for pkg_name, version_data in poetry["dev-dependencies"].items():
                pkg_lower = pkg_name.lower()
                if pkg_lower == "python":
                    continue
                
                version_spec = ""
                if isinstance(version_data, str):
                    version_spec = version_data
                elif isinstance(version_data, dict) and "version" in version_data:
                    version_spec = version_data["version"]
                
                line_no = find_line_number(pkg_lower, "tool.poetry.dev-dependencies")
                dependencies.append((pkg_lower, version_spec, line_no))
    
    return dependencies


def detect_vulnerable_outdated_components(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    Detect vulnerable and outdated components (v0.1).
    
    Rules:
    - A06.DEPENDENCIES.UNPINNED: Detects unpinned or loosely versioned dependencies
    - A06.DEPENDENCIES.DEPRECATED: Detects known deprecated packages
    
    Supports:
    - requirements.txt style files
    - pyproject.toml (PEP 621 and Poetry formats)
    
    Returns schema-shaped finding dicts.
    """
    findings: list[dict[str, Any]] = []
    lines = source.splitlines()
    found_lines: set[int] = set()  # Track lines to avoid duplicates
    
    # Detect file type from path
    file_lower = file_path.lower()
    is_requirements = any(name in file_lower for name in ["requirements", "constraints"])
    is_pyproject = "pyproject" in file_lower
    
    # Handle pyproject.toml with proper TOML parsing
    if is_pyproject:
        # Use TOML parser to extract dependencies
        pyproject_deps = _parse_pyproject_toml(source, file_path)
        
        for package_name, version_spec, line_no in pyproject_deps:
            if line_no in found_lines:
                continue
            
            # Check for deprecated package
            if package_name in DEPRECATED_PACKAGES:
                found_lines.add(line_no)
                dep_info = DEPRECATED_PACKAGES[package_name]
                
                # Create snippet from line
                snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else package_name
                
                finding = _make_finding(
                    finding_id="A06.DEPENDENCIES.DEPRECATED",
                    title="Deprecated dependencies detected",
                    description="One or more dependencies are deprecated or unmaintained.",
                    file_path=file_path,
                    line_no=line_no,
                    snippet=snippet[:240],
                    explanation=(
                        f"{dep_info['reason']}. "
                        f"Consider migrating to {dep_info['alternative']}."
                    ),
                    impact_f=7.5,
                    exploitability_f=6.5,
                    confidence_f=dep_info["confidence"],
                    cwe_refs=["CWE-1104"],
                    exploit_scenario=(
                        "Using deprecated packages may expose the application to unpatched "
                        "vulnerabilities, as they no longer receive security updates."
                    ),
                    recommended_fix=(
                        f"Replace '{package_name}' with {dep_info['alternative']}. "
                        "Prefer actively maintained libraries with a strong security track record."
                    ),
                )
                finding["_package_name"] = package_name
                finding["_security_critical"] = dep_info.get("security_critical", _is_security_critical_package(package_name))
                findings.append(finding)
                continue
            
            # Check for unpinned version
            is_pinned, loose_desc = _check_pyproject_version(version_spec)
            if not is_pinned:
                found_lines.add(line_no)
                
                # Create snippet from line
                snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else f"{package_name} = \"{version_spec}\""
                
                findings.append(
                    _make_finding(
                        finding_id="A06.DEPENDENCIES.UNPINNED",
                        title="Unpinned dependencies detected",
                        description="One or more dependencies have loose or missing version constraints.",
                        file_path=file_path,
                        line_no=line_no,
                        snippet=snippet[:240],
                        explanation=(
                            f"The version specifier '{version_spec}' {loose_desc}. "
                            "This can lead to inconsistent builds and unexpected behavior when "
                            "newer versions introduce breaking changes or vulnerabilities. "
                            "Use exact version pinning and lock files for reproducible builds."
                        ),
                        impact_f=5.5,
                        exploitability_f=5.0,
                        confidence_f=0.80,
                        cwe_refs=["CWE-1104"],
                        exploit_scenario=(
                            "Unpinned dependencies can introduce vulnerabilities or breaking changes "
                            "when automatic updates pull in compromised or incompatible versions."
                        ),
                        recommended_fix=(
                            f"Pin '{package_name}' to an exact version (e.g., '{package_name} = \"==1.2.3\"') "
                            "and maintain a lockfile to ensure reproducible builds across environments. "
                            "Use your dependency manager's lock mechanism to prevent version drift."
                        ),
                    )
                )
        
        # Post-process DEPRECATED findings for pyproject.toml to adjust severity
        deduplicated = deduplicate_findings(findings)
        for finding in deduplicated:
            if finding.get("rule_id") == "A06.DEPENDENCIES.DEPRECATED":
                has_security_critical = False
                for instance in finding.get("instances", []):
                    snippet = instance.get("snippet", "")
                    if _is_security_critical_package(snippet):
                        has_security_critical = True
                        break
                if has_security_critical and finding.get("severity") == "medium":
                    finding["severity"] = "high"
        return deduplicated
    
    # Handle requirements.txt style files (original logic)
    if is_requirements:
        for idx, line in enumerate(lines, start=1):
            # Skip if we already found something on this line
            if idx in found_lines:
                continue
            
            # Skip empty lines and comments
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            
            # Skip editable installs, VCS URLs, local paths
            if stripped.startswith("-e") or stripped.startswith("git+") or stripped.startswith("http"):
                continue
            if "/" in stripped or "\\" in stripped:
                continue
            
            # Parse requirements.txt line
            match = _REQ_LINE_PATTERN.match(line)
            if match:
                package_name = match.group(1).lower().strip()
                version_spec = match.group(2)
                
                # Check for deprecated package
                if package_name in DEPRECATED_PACKAGES:
                    found_lines.add(idx)
                    dep_info = DEPRECATED_PACKAGES[package_name]
                    
                    # Store package name in finding for severity adjustment later
                    finding = _make_finding(
                        finding_id="A06.DEPENDENCIES.DEPRECATED",
                        title="Deprecated dependencies detected",  # Generic title
                        description="One or more dependencies are deprecated or unmaintained.",
                        file_path=file_path,
                        line_no=idx,
                        snippet=line.strip(),
                        explanation=(
                            f"{dep_info['reason']}. "
                            f"Consider migrating to {dep_info['alternative']}."
                        ),
                        impact_f=7.5,
                        exploitability_f=6.5,
                        confidence_f=dep_info["confidence"],
                        cwe_refs=["CWE-1104"],
                        exploit_scenario=(
                            "Using deprecated packages may expose the application to unpatched "
                            "vulnerabilities, as they no longer receive security updates."
                        ),
                        recommended_fix=(
                            f"Replace '{package_name}' with {dep_info['alternative']}. "
                            "Prefer actively maintained libraries with a strong security track record."
                        ),
                    )
                    finding["_package_name"] = package_name
                    finding["_security_critical"] = dep_info.get("security_critical", _is_security_critical_package(package_name))
                    findings.append(finding)
                    continue
                
                # Check for unpinned version
                if not _is_pinned_version(version_spec):
                    found_lines.add(idx)
                    
                    # Determine confidence based on looseness
                    if _is_loose_version_spec(version_spec):
                        confidence = 0.85
                        loose_desc = "very loose or unbounded"
                    else:
                        confidence = 0.75
                        loose_desc = "not strictly pinned"
                    
                    version_display = version_spec if version_spec else "(no version specified)"
                    
                    findings.append(
                        _make_finding(
                            finding_id="A06.DEPENDENCIES.UNPINNED",
                            title="Unpinned dependencies detected",  # Generic title
                            description="One or more dependencies have loose or missing version constraints.",
                            file_path=file_path,
                            line_no=idx,
                            snippet=line.strip(),
                            explanation=(
                                f"The version specifier '{version_display}' is {loose_desc}. "
                                "This can lead to inconsistent builds and unexpected behavior when "
                                "newer versions introduce breaking changes or vulnerabilities. "
                                "Use exact version pinning (==X.Y.Z) and lock files for reproducible builds."
                            ),
                            impact_f=5.5,
                            exploitability_f=5.0,
                            confidence_f=confidence,
                            cwe_refs=["CWE-1104"],
                            exploit_scenario=(
                                "Unpinned dependencies can introduce vulnerabilities or breaking changes "
                                "when automatic updates pull in compromised or incompatible versions."
                            ),
                            recommended_fix=(
                                f"Pin '{package_name}' to an exact version (e.g., '{package_name}==1.2.3') "
                                "and maintain a lockfile to ensure reproducible builds across environments. "
                                "Use your dependency manager's lock mechanism to prevent version drift."
                            ),
                        )
                    )
    
    # Deduplicate findings first
    deduplicated = deduplicate_findings(findings)
    
    # Post-process DEPRECATED findings to adjust severity based on security-critical packages
    # v0.1 heuristic: If ANY deprecated dependency is security-critical -> severity="high"
    for finding in deduplicated:
        if finding.get("rule_id") == "A06.DEPENDENCIES.DEPRECATED":
            # Check if any instance is security-critical
            has_security_critical = False
            for instance in finding.get("instances", []):
                # Extract package name from snippet to check if it's security-critical
                snippet = instance.get("snippet", "")
                # Simple heuristic: check if explanation mentions security-critical packages
                # or if the snippet contains security-related keywords
                if _is_security_critical_package(snippet):
                    has_security_critical = True
                    break
            
            # Adjust severity if security-critical (keep rule_score unchanged)
            if has_security_critical and finding.get("severity") == "medium":
                finding["severity"] = "high"
    
    return deduplicated
