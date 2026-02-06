"""
Helper utilities for CodeRisk AI detectors.
Provides finding deduplication and formatting utilities.
"""
from __future__ import annotations

import hashlib
from typing import Any


# Severity levels for aggregation (lower index = lower severity)
_SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]


def _max_severity(severities: list[str]) -> str:
    """
    Return the maximum severity from a list of severity strings.
    
    Args:
        severities: List of severity strings (info, low, medium, high, critical)
        
    Returns:
        The highest severity level
    """
    if not severities:
        return "info"
    
    max_level = 0
    for sev in severities:
        sev_lower = sev.lower()
        if sev_lower in _SEVERITY_LEVELS:
            level = _SEVERITY_LEVELS.index(sev_lower)
            if level > max_level:
                max_level = level
    
    return _SEVERITY_LEVELS[max_level]


def _normalize_path(file_path: str) -> str:
    """Normalize file path for consistent hashing."""
    # Replace backslashes, remove leading ./ or absolute prefixes
    normalized = file_path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    # Remove drive letters (Windows)
    if len(normalized) > 2 and normalized[1] == ":":
        normalized = normalized[2:].lstrip("/")
    return normalized


def _generate_finding_id(rule_id: str, file_path: str, snippet: str, 
                         line_start: int, ruleset_version: str = "0.1",
                         sink_info: str = "", taint_source_info: str = "") -> str:
    """Generate deterministic hash-based finding ID.
    
    Args:
        rule_id: The rule identifier
        file_path: File path (will be normalized)
        snippet: Code snippet
        line_start: Starting line number
        ruleset_version: Analyzer ruleset version
        sink_info: Optional sink information
        taint_source_info: Optional taint source information
        
    Returns:
        Finding ID in format "fnd_<12hex>"
    """
    normalized_path = _normalize_path(file_path)
    
    # Build hash input from components
    hash_input = "|".join([
        rule_id,
        normalized_path,
        str(line_start),
        snippet[:200],  # Limit snippet length for stability
        sink_info,
        taint_source_info,
        ruleset_version,
    ])
    
    # Generate SHA256 hash and take first 12 hex chars
    hash_digest = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[:12]
    return f"fnd_{hash_digest}"


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Deduplicate findings by grouping instances of the same rule in the same file.
    
    Converts multiple findings with same rule_id+file into a single finding with instances array.
    
    Args:
        findings: List of raw findings (each with single evidence)
        
    Returns:
        List of deduplicated findings (each with instances array)
    """
    # Group by (rule_id, file)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    
    for finding in findings:
        # Use rule_id if present, otherwise fall back to id
        # If neither exists, skip this finding (malformed)
        rule_id = finding.get("rule_id") or finding.get("id")
        if not rule_id:
            continue  # Skip malformed findings
        file_path = finding["evidence"]["file"]
        key = (rule_id, file_path)
        
        if key not in groups:
            groups[key] = []
        groups[key].append(finding)
    
    # Build deduplicated findings
    deduplicated = []
    for (rule_id, file_path), group in groups.items():
        # Use the first finding as template
        first = group[0]
        
        # Collect all instances and metadata
        instances = []
        algorithms = set()  # Track unique algorithms for title enhancement
        instance_confidences = []
        instance_severities = []  # Track per-instance severities for aggregation
        all_sink_functions = set()  # Track unique sink functions
        all_taint_sources = []  # Track all taint sources (will deduplicate by path)
        
        for f in group:
            ev = f["evidence"]
            instance = {
                "file": ev["file"],
                "line_start": ev["line_start"],
                "line_end": ev["line_end"],
                "snippet": ev["snippet"],
                "explanation": ev["explanation"],
            }
            # Add per-instance algorithm if present (for weak hash detection)
            if "_algorithm" in f:
                instance["algorithm"] = f["_algorithm"]
                algorithms.add(f["_algorithm"])
            # Add per-instance confidence if different from rule confidence
            if "_instance_confidence" in f:
                instance["confidence"] = f["_instance_confidence"]
                instance_confidences.append(f["_instance_confidence"])
            else:
                instance_confidences.append(f["confidence"])
            # Track per-instance severity for aggregation
            if "_instance_severity" in f:
                instance_severities.append(f["_instance_severity"])
            else:
                instance_severities.append(f["severity"])
            
            # Track per-instance sink if present
            if "sink" in f:
                instance["sink"] = f["sink"]
                if "function" in f["sink"]:
                    all_sink_functions.add(f["sink"]["function"])
            
            # Track per-instance taint_sources if present
            if "taint_sources" in f:
                instance["taint_sources"] = f["taint_sources"]
                all_taint_sources.extend(f["taint_sources"])
            
            instances.append(instance)
        
        # Calculate finding-level confidence as max of instance confidences
        # Rationale: Finding confidence reflects the strongest supported instance
        finding_confidence = max(instance_confidences) if instance_confidences else first["confidence"]
        
        # Calculate finding-level severity as max of instance severities
        # Rationale: Finding severity reflects the most severe instance
        finding_severity = _max_severity(instance_severities) if instance_severities else first["severity"]
        
        # Enhance title with algorithm list if multiple algorithms detected
        title = first["title"]
        if algorithms and len(algorithms) > 1:
            algo_list = ", ".join(sorted(algorithms)).upper()
            if "algorithm detected" in title.lower():
                title = title.replace("detected", f"detected ({algo_list})")
        
        # Build deduplicated finding
        # Generate deterministic hash-based ID
        sink_info = first.get("sink", {}).get("function", "")
        taint_source_info = ""
        if "taint_sources" in first and first["taint_sources"]:
            taint_source_info = first["taint_sources"][0].get("type", "")
        
        finding_id = _generate_finding_id(
            rule_id=rule_id,
            file_path=file_path,
            snippet=instances[0]["snippet"],
            line_start=instances[0]["line_start"],
            ruleset_version="0.1",
            sink_info=sink_info,
            taint_source_info=taint_source_info,
        )
        
        # Generate human-readable fingerprint
        fingerprint = f"{rule_id}:{file_path}:{instances[0]['line_start']}"
        
        rule_score = first.get("rule_score", first.get("score_contribution", 0.0))
        result = {
            "rule_id": rule_id,
            "id": finding_id,
            "fingerprint": fingerprint,
            "title": title,
            "description": first["description"],
            "category": first["category"],
            "severity": finding_severity,
            "rule_score": rule_score,
            "confidence": finding_confidence,
            "exploit_scenario": first.get("exploit_scenario", ""),
            "recommended_fix": first.get("recommended_fix", ""),
            "instances": instances,
            "references": first["references"],
        }
        
        # Add optional structured fields if present
        # Handle sink aggregation: if multiple unique sinks, use "functions" (plural)
        if all_sink_functions:
            if len(all_sink_functions) == 1:
                result["sink"] = {
                    "type": first.get("sink", {}).get("type", "http_request"),
                    "function": list(all_sink_functions)[0],
                }
            else:
                result["sink"] = {
                    "type": first.get("sink", {}).get("type", "http_request"),
                    "functions": sorted(all_sink_functions),
                }
        
        # Handle taint_sources aggregation: deduplicate by path
        if all_taint_sources:
            seen_paths = set()
            unique_taint_sources = []
            for ts in all_taint_sources:
                path = ts.get("path", "")
                if path and path not in seen_paths:
                    seen_paths.add(path)
                    unique_taint_sources.append(ts)
                elif not path:  # Include sources without paths
                    unique_taint_sources.append(ts)
            result["taint_sources"] = unique_taint_sources
        
        deduplicated.append(result)
    
    return deduplicated
