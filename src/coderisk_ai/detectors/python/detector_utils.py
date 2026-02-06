"""
Helper utilities for CodeRisk AI detectors.
Provides finding deduplication and formatting utilities.
"""
from __future__ import annotations

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
        rule_id = finding.get("rule_id", finding["id"])
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
        # Generate unique ID: rule_id:file:first_line
        # But if the first finding already has a properly formatted unique id, use it
        if "rule_id" in first and "id" in first and first["id"] != first["rule_id"]:
            # Detector already set both rule_id and unique id properly
            unique_id = first["id"]
        else:
            # Legacy: generate unique id from rule_id
            unique_id = f"{rule_id}:{file_path}:{instances[0]['line_start']}"
        
        rule_score = first.get("rule_score", first.get("score_contribution", 0.0))
        result = {
            "rule_id": rule_id,
            "id": unique_id,
            "title": title,
            "description": first["description"],
            "category": first["category"],
            "severity": finding_severity,
            "rule_score": rule_score,
            "score_contribution": rule_score,  # Deprecated: backward compatibility only (remove in v0.2)
            "confidence": finding_confidence,
            "exploit_scenario": first.get("exploit_scenario", ""),
            "recommended_fix": first.get("recommended_fix", ""),
            "instances": instances,
            "references": first["references"],
        }
        
        deduplicated.append(result)
    
    return deduplicated
