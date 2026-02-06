#!/usr/bin/env python3
"""
Validation script for A07 Identification & Authentication Failures detector.
Tests that the detector produces valid schema output.
"""

import json
import subprocess
import sys


def validate_finding_schema(finding, finding_idx):
    """Validate that a finding matches the expected schema."""
    errors = []
    
    # Required fields
    required_fields = [
        "rule_id", "id", "title", "description", "category", "severity",
        "rule_score", "confidence", "exploit_scenario", "recommended_fix",
        "instances", "references"
    ]
    
    for field in required_fields:
        if field not in finding:
            errors.append(f"Finding {finding_idx}: Missing required field '{field}'")
    
    # Validate rule_id
    if "rule_id" in finding:
        valid_rule_ids = ["AUTH.CUSTOM.PASSWORD_CHECK", "AUTH.PLAINTEXT.PASSWORD_COMPARE"]
        if finding["rule_id"] not in valid_rule_ids:
            errors.append(f"Finding {finding_idx}: Invalid rule_id '{finding['rule_id']}'")
    
    # Validate category
    if "category" in finding and finding["category"] != "A07_identification_authentication_failures":
        errors.append(f"Finding {finding_idx}: Invalid category '{finding['category']}'")
    
    # Validate severity
    if "severity" in finding:
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if finding["severity"] not in valid_severities:
            errors.append(f"Finding {finding_idx}: Invalid severity '{finding['severity']}'")
    
    # Validate rule_score range
    if "rule_score" in finding:
        score = finding["rule_score"]
        if not (0.0 <= score <= 10.0):
            errors.append(f"Finding {finding_idx}: rule_score {score} out of range [0, 10]")
    
    # Validate confidence range
    if "confidence" in finding:
        conf = finding["confidence"]
        if not (0.0 <= conf <= 1.0):
            errors.append(f"Finding {finding_idx}: confidence {conf} out of range [0, 1]")
    
    # Validate instances
    if "instances" in finding:
        if not isinstance(finding["instances"], list) or len(finding["instances"]) == 0:
            errors.append(f"Finding {finding_idx}: instances must be a non-empty list")
        else:
            for inst_idx, inst in enumerate(finding["instances"]):
                required_inst_fields = ["file", "line_start", "line_end", "snippet", "explanation"]
                for field in required_inst_fields:
                    if field not in inst:
                        errors.append(f"Finding {finding_idx}, Instance {inst_idx}: Missing field '{field}'")
    
    # Validate references
    if "references" in finding:
        if not isinstance(finding["references"], list):
            errors.append(f"Finding {finding_idx}: references must be a list")
        else:
            # Check for OWASP reference
            has_owasp = any(
                ref.get("type") == "OWASP" and "A07" in ref.get("value", "")
                for ref in finding["references"]
            )
            if not has_owasp:
                errors.append(f"Finding {finding_idx}: Missing OWASP A07 reference")
    
    return errors


def main():
    # Run the analyzer
    result = subprocess.run(
        ["python", "-m", "coderisk_ai.cli", "analyze",
         "examples/a07_identification_authentication_failures_test.py"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Analyzer failed: {result.stderr}")
        return 1
    
    # Parse output
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON output: {e}")
        return 1
    
    # Filter A07 findings
    a07_findings = [
        f for f in data.get("findings", [])
        if f.get("category") == "A07_identification_authentication_failures"
    ]
    
    if not a07_findings:
        print("❌ No A07 findings detected")
        return 1
    
    print(f"✅ Found {len(a07_findings)} A07 finding groups")
    
    # Count total instances
    total_instances = sum(len(f.get("instances", [])) for f in a07_findings)
    print(f"✅ Total instances: {total_instances}")
    
    # Validate each finding
    all_errors = []
    for idx, finding in enumerate(a07_findings):
        errors = validate_finding_schema(finding, idx)
        all_errors.extend(errors)
    
    if all_errors:
        print("\n❌ Schema validation errors:")
        for error in all_errors:
            print(f"  - {error}")
        return 1
    
    print("✅ All findings pass schema validation")
    
    # Check for expected rules
    rule_ids = {f["rule_id"] for f in a07_findings}
    expected_rules = {"AUTH.CUSTOM.PASSWORD_CHECK", "AUTH.PLAINTEXT.PASSWORD_COMPARE"}
    
    if rule_ids != expected_rules:
        print(f"⚠️  Warning: Expected rules {expected_rules}, got {rule_ids}")
    else:
        print(f"✅ Both expected rules detected: {rule_ids}")
    
    # Summary statistics
    print("\n📊 Detection Summary:")
    for finding in a07_findings:
        rule_id = finding["rule_id"]
        num_instances = len(finding["instances"])
        confidence = finding["confidence"]
        severity = finding["severity"]
        rule_score = finding["rule_score"]
        print(f"  {rule_id}:")
        print(f"    - Instances: {num_instances}")
        print(f"    - Severity: {severity}")
        print(f"    - Confidence: {confidence}")
        print(f"    - Rule Score: {rule_score}")
    
    # Check OWASP score
    owasp_score = data.get("summary", {}).get("owasp", {}).get("A07_identification_authentication_failures", 0)
    print(f"\n📈 A07 OWASP Score: {owasp_score}")
    
    if owasp_score > 0:
        print("✅ A07 contributing to overall score")
    else:
        print("⚠️  Warning: A07 score is 0")
    
    print("\n✅ All validation checks passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
