from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from coderisk_ai.detectors.sql_injection import detect_sql_injection
from coderisk_ai.detectors.unsafe_deserialization import detect_unsafe_deserialization



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
        findings.extend(detect_sql_injection(source=source, file_path=file_path))
        findings.extend(detect_unsafe_deserialization(source=source, file_path=file_path))

    if p.is_file():
        file_count = 1
        language = "python" if p.suffix.lower() == ".py" else "unknown"
        analyze_file(p)

    elif p.is_dir():
        py_files = list(p.rglob("*.py"))
        file_count = len(py_files)
        language = "python"
        for fp in py_files:
            analyze_file(fp)

    else:
        findings = []

    # Severity counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in sev_counts:
            sev_counts[sev] += 1

    # OWASP rollup (v0.1: A03 + A08)
    a03_score = clamp(
        sum(f.get("score_contribution", 0.0) for f in findings if f.get("category") == "A03_injection"),
        0.0,
        10.0,
    )
    a08_score = clamp(
        sum(f.get("score_contribution", 0.0) for f in findings if f.get("category") == "A08_integrity_failures"),
        0.0,
        10.0,
    )
    owasp = {}
    if findings:
        owasp["A03_injection"] = round(a03_score, 2)
        owasp["A08_integrity_failures"] = round(a08_score, 2)

    # CVSS-like quick rollup (simple placeholder)
    # If we have any A03 finding, assume higher impact/exploitability.
    cvss_like = {"impact": 0.0, "exploitability": 0.0}
    if findings:
        cvss_like["impact"] = 7.5
        cvss_like["exploitability"] = 7.0

    # Overall score (v0.1 placeholder): use max OWASP category score (bounded)
    overall_score = round(clamp(max(owasp.values()) if owasp else 0.0, 0.0, 10.0), 2)

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
