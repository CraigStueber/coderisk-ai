from __future__ import annotations

import re
from typing import Any

from .detector_utils import deduplicate_findings


# v0.1: narrow, sink-based heuristics (no taint tracking yet)
# High-signal sinks:
# - pickle.loads / pickle.load
# - marshal.loads / marshal.load
# - yaml.load without SafeLoader (or with UnsafeLoader)
_PICKLE_SINK = re.compile(r"\bpickle\.(loads|load)\s*\(", re.IGNORECASE)
_MARSHAL_SINK = re.compile(r"\bmarshal\.(loads|load)\s*\(", re.IGNORECASE)

# yaml.load(...) is only unsafe if not explicitly SafeLoader
# We'll flag:
# - yaml.load(...) with no Loader=... arg
# - yaml.load(..., Loader=yaml.UnsafeLoader) or yaml.FullLoader
_YAML_LOAD_SINK = re.compile(r"\byaml\.load\s*\(", re.IGNORECASE)
_YAML_SAFELOADER = re.compile(r"\bLoader\s*=\s*(yaml\.)?SafeLoader\b", re.IGNORECASE)
_YAML_UNSAFELOADER = re.compile(r"\bLoader\s*=\s*(yaml\.)?(UnsafeLoader|FullLoader)\b", re.IGNORECASE)


def _severity_from_score(score: float) -> str:
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
    file_path: str,
    line_no: int,
    snippet: str,
    sink_name: str,
    impact_f: float,
    exploitability_f: float,
    confidence_f: float,
) -> dict[str, Any]:
    base_score_f = (impact_f * exploitability_f) / 10.0
    rule_score_f = round(base_score_f * confidence_f, 2)

    # severity: based on base score (not confidence), which is more intuitive for reviewers
    severity = _severity_from_score(base_score_f)

    explanation = (
        f"Detected use of {sink_name}, which can be unsafe when parsing untrusted input. "
        "Unsafe deserialization may allow arbitrary code execution or data integrity compromise. "
        "Prefer safe formats (e.g., JSON) or safe loaders (e.g., yaml.safe_load / SafeLoader), "
        "and never deserialize untrusted data with pickle/marshal."
    )
    
    # Determine exploit scenario and fix based on sink type
    if "pickle" in sink_name.lower():
        exploit_scenario = "Attacker provides malicious pickle data to execute arbitrary code on the server."
        recommended_fix = "Avoid pickle for untrusted data; use JSON or other safe serialization formats."
    elif "marshal" in sink_name.lower():
        exploit_scenario = "Attacker provides malicious marshal data to execute arbitrary code or corrupt application state."
        recommended_fix = "Avoid marshal for untrusted data; use JSON or other safe serialization formats."
    else:
        exploit_scenario = "Attacker provides malicious YAML to execute code or manipulate application behavior."
        recommended_fix = "Use yaml.safe_load() or SafeLoader instead of yaml.load()."

    return {
        "id": finding_id,
        "title": "Potential unsafe deserialization",
        "description": "A high-risk deserialization sink was detected. If the input is untrusted, this may lead to code execution.",
        "category": "A08_integrity_failures",
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
        "references": [
            {"type": "CWE", "value": "CWE-502"},
            {"type": "OWASP", "value": "A08:2021 Software and Data Integrity Failures"},
        ],
    }


def detect_unsafe_deserialization(source: str, file_path: str) -> list[dict[str, Any]]:
    """
    v0.1 unsafe deserialization detector (Python).

    This is intentionally conservative:
    - Flags known dangerous sinks regardless of proven user input.
    - Evidence includes file + line + snippet for auditability.
    """
    findings: list[dict[str, Any]] = []
    lines = source.splitlines()

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # pickle.* sinks (very high severity)
        if _PICKLE_SINK.search(line):
            findings.append(
                _make_finding(
                    finding_id="INTEGRITY.DESERIALIZATION.PICKLE",
                    file_path=file_path,
                    line_no=idx,
                    snippet=stripped,
                    sink_name="pickle.load(s)/pickle.loads",
                    impact_f=9.0,
                    exploitability_f=7.0,
                    confidence_f=0.80,
                )
            )
            continue

        # marshal.* sinks (high severity)
        if _MARSHAL_SINK.search(line):
            findings.append(
                _make_finding(
                    finding_id="INTEGRITY.DESERIALIZATION.MARSHAL",
                    file_path=file_path,
                    line_no=idx,
                    snippet=stripped,
                    sink_name="marshal.load(s)/marshal.loads",
                    impact_f=8.0,
                    exploitability_f=6.0,
                    confidence_f=0.75,
                )
            )
            continue

        # yaml.load(...) checks
        if _YAML_LOAD_SINK.search(line):
            # SafeLoader explicitly present => do not flag
            if _YAML_SAFELOADER.search(line):
                continue

            # UnsafeLoader or FullLoader explicitly present => flag (higher confidence)
            if _YAML_UNSAFELOADER.search(line):
                findings.append(
                    _make_finding(
                        finding_id="INTEGRITY.DESERIALIZATION.YAML_UNSAFE_LOADER",
                        file_path=file_path,
                        line_no=idx,
                        snippet=stripped,
                        sink_name="yaml.load with UnsafeLoader/FullLoader",
                        impact_f=8.0,
                        exploitability_f=6.0,
                        confidence_f=0.70,
                    )
                )
                continue

            # yaml.load with no explicit SafeLoader => flag (lower confidence)
            findings.append(
                _make_finding(
                    finding_id="INTEGRITY.DESERIALIZATION.YAML_LOAD",
                    file_path=file_path,
                    line_no=idx,
                    snippet=stripped,
                    sink_name="yaml.load without SafeLoader",
                    impact_f=7.0,
                    exploitability_f=5.0,
                    confidence_f=0.55,
                )
            )

    return deduplicate_findings(findings)
