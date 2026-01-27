from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def build_mock_result(target_path: str) -> dict:
    # Minimal schema-compliant mock (v0.1). Replace internals later.
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

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
            "language": "python",
            "file_count": 1 if Path(target_path).is_file() else 0,
        },
        "summary": {
            "overall_score": 0.0,
            "confidence": 0.5,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "owasp": {},
            "cvss_like": {"impact": 0.0, "exploitability": 0.0},
        },
        "signals": {
            "hallucination_markers": {"level": "low", "indicators": []},
            "nondeterminism_sensitivity": {"level": "low", "rationale": "stub"},
            "dependency_volatility": {"level": "low"},
        },
        "findings": [],
        "metadata": {},
    }


def cmd_analyze(args: argparse.Namespace) -> int:
    result = build_mock_result(args.path)
    if args.pretty:
        print(json.dumps(result, indent=2, sort_keys=False))
    else:
        print(json.dumps(result))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coderisk", description="CodeRisk AI CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a file or directory")
    analyze.add_argument("path", help="Path to file or directory to analyze")
    analyze.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    analyze.set_defaults(func=cmd_analyze)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
