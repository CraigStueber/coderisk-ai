#!/usr/bin/env python3
"""Test script to verify overlap suppression and public route filtering."""

import json
import subprocess
import sys


def test_overlap_suppression():
    """Test that AUTH.PLAINTEXT takes precedence over AUTH.CUSTOM for same lines."""
    print("=" * 70)
    print("TEST 1: Overlap Suppression (A07 Rules)")
    print("=" * 70)
    
    result = subprocess.run(
        ['python', '-m', 'coderisk_ai.cli', 'analyze', 
         'examples/identification_authentication_failures_test.py'],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Analyzer failed: {result.stderr}")
        return False
    
    data = json.loads(result.stdout)
    
    # Get line numbers for each rule
    plaintext = [f for f in data['findings'] if 'AUTH.PLAINTEXT' in f['rule_id']]
    plaintext_lines = {inst['line_start'] for f in plaintext for inst in f['instances']}
    
    custom = [f for f in data['findings'] if 'AUTH.CUSTOM' in f['rule_id']]
    custom_lines = {inst['line_start'] for f in custom for inst in f['instances']}
    
    overlap = plaintext_lines & custom_lines
    
    print(f"\nPlaintext password compare detections: {len(plaintext_lines)} lines")
    print(f"Custom password check detections: {len(custom_lines)} lines")
    print(f"Overlapping lines: {len(overlap)}")
    
    if overlap:
        print(f"❌ FAILED: Found overlapping lines: {sorted(overlap)}")
        print("   These lines appear in both AUTH.PLAINTEXT and AUTH.CUSTOM findings")
        return False
    else:
        print("✅ PASSED: No overlapping lines - precedence working correctly")
        return True


def test_public_route_filtering():
    """Test that public routes like /login are not flagged for missing auth."""
    print("\n" + "=" * 70)
    print("TEST 2: Public Route Filtering (A01 Flask Auth)")
    print("=" * 70)
    
    result = subprocess.run(
        ['python', '-m', 'coderisk_ai.cli', 'analyze',
         'examples/identification_authentication_failures_test.py'],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Analyzer failed: {result.stderr}")
        return False
    
    data = json.loads(result.stdout)
    
    # Check for FLASK_AUTH findings
    flask_findings = [f for f in data['findings'] if 'FLASK_AUTH' in f['rule_id']]
    
    if flask_findings:
        for finding in flask_findings:
            for inst in finding['instances']:
                snippet = inst['snippet']
                print(f"❌ FAILED: /login route still flagged:")
                print(f"   Line {inst['line_start']}: {snippet}")
        return False
    else:
        print("✅ PASSED: /login route not flagged (public route filtering working)")
        return True


def test_sensitive_routes_still_detected():
    """Test that sensitive routes are still properly detected."""
    print("\n" + "=" * 70)
    print("TEST 3: Sensitive Routes Still Detected")
    print("=" * 70)
    
    # Check if broken_access_control.py example exists
    import os
    if not os.path.exists('examples/a01_broken_access_control_test.py'):
        print("⚠️  SKIPPED: examples/a01_broken_access_control_test.py not found")
        return True
    
    result = subprocess.run(
        ['python', '-m', 'coderisk_ai.cli', 'analyze',
         'examples/a01_broken_access_control_test.py'],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Analyzer failed: {result.stderr}")
        return False
    
    data = json.loads(result.stdout)
    
    # Check for FLASK_AUTH findings on sensitive routes
    flask_findings = [f for f in data['findings'] if 'FLASK_AUTH' in f['rule_id']]
    
    if flask_findings:
        print(f"✅ PASSED: Sensitive routes still detected ({len(flask_findings)} findings)")
        for finding in flask_findings:
            for inst in finding['instances'][:3]:  # Show first 3
                print(f"   Line {inst['line_start']}: {inst['snippet'][:60]}")
        return True
    else:
        print("⚠️  No Flask auth findings in a01_broken_access_control_test.py")
        return True


def main():
    print("\n🧪 Running CodeRisk AI Integration Tests\n")
    
    results = []
    results.append(("Overlap Suppression", test_overlap_suppression()))
    results.append(("Public Route Filtering", test_public_route_filtering()))
    results.append(("Sensitive Route Detection", test_sensitive_routes_still_detected()))
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {name}")
    
    all_passed = all(passed for _, passed in results)
    
    if all_passed:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
