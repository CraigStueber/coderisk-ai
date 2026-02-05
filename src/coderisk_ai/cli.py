from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from coderisk_ai.detectors.python.broken_access_control import detect_broken_access_control
from coderisk_ai.detectors.python.cryptographic_failures import detect_cryptographic_failures
from coderisk_ai.detectors.python.sql_injection import detect_sql_injection
from coderisk_ai.detectors.python.unsafe_deserialization import detect_unsafe_deserialization
from coderisk_ai.detectors.python.security_misconfiguration import detect_security_misconfiguration
from coderisk_ai.detectors.python.identification_authentication_failures import detect_identification_authentication_failures
from coderisk_ai.detectors.python.vulnerable_outdated_components import detect_vulnerable_outdated_components



def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(x, hi))


def build_result(target_path: str) -> dict:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    p = Path(target_path)

    findings = []
    language = "unknown"
    file_count = 0

    def analyze_file(fp: Path):
        nonlocal findings
        source = fp.read_text(encoding="utf-8", errors="replace")
        file_path = str(fp).replace("\\", "/")
        
        # Check if this is a dependency file
        # Treat files whose basename contains "pyproject" as dependency manifests
        file_lower = fp.name.lower()
        is_dependency_file = (
            "requirements" in file_lower or
            "constraints" in file_lower or
            file_lower == "pipfile" or
            file_lower == "pipfile.lock" or
            "pyproject" in file_lower or  # Any file with "pyproject" in name
            file_lower == "poetry.lock" or
            file_lower == "setup.cfg"
        )
        
        # Run A06 detector on dependency files
        if is_dependency_file:
            findings.extend(detect_vulnerable_outdated_components(source=source, file_path=file_path))
        
        # Run standard detectors on Python files
        if fp.suffix.lower() == ".py":
            findings.extend(detect_broken_access_control(source=source, file_path=file_path))
            findings.extend(detect_cryptographic_failures(source=source, file_path=file_path))
            findings.extend(detect_sql_injection(source=source, file_path=file_path))
            findings.extend(detect_unsafe_deserialization(source=source, file_path=file_path))
            findings.extend(detect_security_misconfiguration(source=source, file_path=file_path))
            findings.extend(detect_identification_authentication_failures(source=source, file_path=file_path))

    if p.is_file():
        file_count = 1
        language = "python" if p.suffix.lower() == ".py" else "unknown"
        analyze_file(p)

    elif p.is_dir():
        py_files = list(p.rglob("*.py"))
        # Also scan for dependency files
        # Include any file with "pyproject" in basename (pyproject.toml, pyproject_unpinned.toml, etc.)
        dep_files = []
        for pattern in ["*requirements*", "*constraints*", "Pipfile", "Pipfile.lock", "*pyproject*", "poetry.lock", "setup.cfg"]:
            dep_files.extend(p.rglob(pattern))
        
        all_files = py_files + dep_files
        file_count = len(all_files)
        language = "python"
        for fp in all_files:
            analyze_file(fp)

    else:
        findings = []

    # Severity counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in sev_counts:
            sev_counts[sev] += 1

    # OWASP rollup (v0.1: A01 + A02 + A03 + A05 + A06 + A07 + A08)
    a01_score = clamp(
        max((f.get("rule_score", 0.0) for f in findings if f.get("category") == "A01_access_control"), default=0.0),
        0.0,
        10.0,
    )
    a02_score = clamp(
        max((f.get("rule_score", 0.0) for f in findings if f.get("category") == "A02_cryptographic_failures"), default=0.0),
        0.0,
        10.0,
    )
    a03_score = clamp(
        max((f.get("rule_score", 0.0) for f in findings if f.get("category") == "A03_injection"), default=0.0),
        0.0,
        10.0,
    )
    a05_score = clamp(
        max((f.get("rule_score", 0.0) for f in findings if f.get("category") == "A05_security_misconfiguration"), default=0.0),
        0.0,
        10.0,
    )
    a06_score = clamp(
        max((f.get("rule_score", 0.0) for f in findings if f.get("category") == "A06_vulnerable_outdated_components"), default=0.0),
        0.0,
        10.0,
    )
    a07_score = clamp(
        max((f.get("rule_score", 0.0) for f in findings if f.get("category") == "A07_identification_authentication_failures"), default=0.0),
        0.0,
        10.0,
    )
    a08_score = clamp(
        max((f.get("rule_score", 0.0) for f in findings if f.get("category") == "A08_integrity_failures"), default=0.0),
        0.0,
        10.0,
    )
    owasp = {}
    if findings:
        owasp["A01_access_control"] = round(a01_score, 2)
        owasp["A02_cryptographic_failures"] = round(a02_score, 2)
        owasp["A03_injection"] = round(a03_score, 2)
        owasp["A05_security_misconfiguration"] = round(a05_score, 2)
        owasp["A06_vulnerable_outdated_components"] = round(a06_score, 2)
        owasp["A07_identification_authentication_failures"] = round(a07_score, 2)
        owasp["A08_integrity_failures"] = round(a08_score, 2)

    # CVSS-like quick rollup (simple placeholder)
    # If we have any A03 finding, assume higher impact/exploitability.
    cvss_like = {"impact": 0.0, "exploitability": 0.0}
    if findings:
        cvss_like["impact"] = 7.5
        cvss_like["exploitability"] = 7.0

    # Overall score (v0.1): max of all OWASP category scores, capped at 10.0
    # Rationale: Each category score already represents the highest-risk finding in that category.
    # The overall risk is driven by the worst category, not the sum (which would penalize diverse issues).
    # This approach: 1) keeps score bounded [0, 10], 2) highlights the most critical area,
    # 3) avoids artificial inflation when multiple categories have findings.
    overall_score = round(min(10.0, max(owasp.values()) if owasp else 0.0), 2)

    # Confidence (v0.1 placeholder):
    # Start at 0.7 if we found something; otherwise 0.5.
    confidence = 0.7 if findings else 0.5

    # Signals (v0.1 stub; you’ll refine later)
    signals = {
        "hallucination_markers": {"level": "low", "indicators": []},
        "nondeterminism_sensitivity": {"level": "low", "rationale": "v0.1 stub"},
        "dependency_volatility": {"level": "low"},
    }

    return {
        "schema_version": "0.1",
        "analyzer": {
            "name": "coderisk-ai",
            "version": "0.0.1",
            "ruleset_version": "0.1",
            "timestamp_utc": now,
        },
        "target": {
            "path": target_path,
            "language": language,
            "file_count": file_count,
        },
        "summary": {
            "overall_score": overall_score,
            "confidence": confidence,
            "scoring_model": "max_category",
            "score_rationale": "Overall score equals the maximum OWASP category score to represent worst-case risk exposure",
            "severity_counts": sev_counts,
            "owasp": owasp,
            "cvss_like": cvss_like,
        },
        "signals": signals,
        "findings": findings,
        "metadata": {},
    }


def cmd_analyze(args: argparse.Namespace) -> int:
    result = build_result(args.path)
    if args.pretty:
        print(json.dumps(result, indent=2, sort_keys=False))
    else:
        print(json.dumps(result))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coderisk", description="CodeRisk AI CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a file (v0.1 is file-only)")
    analyze.add_argument("path", help="Path to file to analyze")
    analyze.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    analyze.set_defaults(func=cmd_analyze)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
