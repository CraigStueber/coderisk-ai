"""
Helper utilities for CodeRisk AI detectors.
Provides finding deduplication and formatting utilities.
"""
from __future__ import annotations

from typing import Any


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
        # Use id as rule_id (for now they're the same)
        rule_id = finding["id"]
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
            instances.append(instance)
        
        # Calculate finding-level confidence as max of instance confidences
        # Rationale: Finding confidence reflects the strongest supported instance
        finding_confidence = max(instance_confidences) if instance_confidences else first["confidence"]
        
        # Enhance title with algorithm list if multiple algorithms detected
        title = first["title"]
        if algorithms and len(algorithms) > 1:
            algo_list = ", ".join(sorted(algorithms)).upper()
            if "algorithm detected" in title.lower():
                title = title.replace("detected", f"detected ({algo_list})")
        
        # Build deduplicated finding
        # Generate unique ID: rule_id:file:first_line
        unique_id = f"{rule_id}:{file_path}:{instances[0]['line_start']}"
        
        rule_score = first.get("rule_score", first.get("score_contribution", 0.0))
        result = {
            "rule_id": rule_id,
            "id": unique_id,
            "title": title,
            "description": first["description"],
            "category": first["category"],
            "severity": first["severity"],
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
