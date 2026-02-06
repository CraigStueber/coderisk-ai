#!/usr/bin/env python3
"""
Test script for SSRF (A10) detector.
Validates that vulnerable examples are detected and safe examples are not.
"""
import json
import subprocess
import sys


def run_analyzer(file_path: str) -> dict:
    """Run the analyzer on a file and return parsed JSON result."""
    result = subprocess.run(
        ['python', '-m', 'coderisk_ai.cli', 'analyze', file_path],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Analyzer failed for {file_path}: {result.stderr}")
        sys.exit(1)
    
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON output: {e}")
        print(f"Output was: {result.stdout}")
        sys.exit(1)


def test_vulnerable_requests():
    """Test that ssrf_requests.py is detected."""
    print("=" * 70)
    print("TEST 1: Vulnerable SSRF patterns using requests library")
    print("=" * 70)
    
    data = run_analyzer('examples/ssrf_requests.py')
    
    # Check for A10_ssrf findings
    a10_findings = [f for f in data['findings'] if f.get('category') == 'A10_ssrf']
    
    if not a10_findings:
        print("❌ FAILED: No SSRF findings detected in ssrf_requests.py")
        return False
    
    print(f"✅ Found {len(a10_findings)} SSRF finding(s)")
    
    # Count instances across all findings
    total_instances = sum(len(f.get('instances', [])) for f in a10_findings)
    print(f"   Total instances detected: {total_instances}")
    
    # Check that A10_ssrf score exists in summary
    a10_score = data['summary']['owasp'].get('A10_ssrf', 0.0)
    print(f"   A10 SSRF score: {a10_score}")
    
    if a10_score == 0.0:
        print("❌ FAILED: A10_ssrf score is 0 despite findings")
        return False
    
    # Show a few instance details
    print(f"\n   Sample detections:")
    count = 0
    for finding in a10_findings:
        for instance in finding.get('instances', [])[:3]:  # Show first 3
            count += 1
            if count > 5:  # Limit total samples
                break
            print(f"     - Line {instance['line_start']}: {instance['snippet'][:60]}...")
        if count > 5:
            break
    
    print("✅ PASSED: SSRF patterns detected in ssrf_requests.py")
    return True


def test_vulnerable_urllib():
    """Test that ssrf_urllib.py is detected."""
    print("\n" + "=" * 70)
    print("TEST 2: Vulnerable SSRF patterns using urllib library")
    print("=" * 70)
    
    data = run_analyzer('examples/ssrf_urllib.py')
    
    # Check for A10_ssrf findings
    a10_findings = [f for f in data['findings'] if f.get('category') == 'A10_ssrf']
    
    if not a10_findings:
        print("❌ FAILED: No SSRF findings detected in ssrf_urllib.py")
        return False
    
    print(f"✅ Found {len(a10_findings)} SSRF finding(s)")
    
    # Count instances
    total_instances = sum(len(f.get('instances', [])) for f in a10_findings)
    print(f"   Total instances detected: {total_instances}")
    
    # Show a few instance details
    print(f"\n   Sample detections:")
    count = 0
    for finding in a10_findings:
        for instance in finding.get('instances', [])[:3]:
            count += 1
            if count > 5:
                break
            print(f"     - Line {instance['line_start']}: {instance['snippet'][:60]}...")
        if count > 5:
            break
    
    print("✅ PASSED: SSRF patterns detected in ssrf_urllib.py")
    return True


def test_safe_examples():
    """Test that ssrf_safe.py does NOT produce SSRF findings."""
    print("\n" + "=" * 70)
    print("TEST 3: Safe SSRF patterns (should not be detected)")
    print("=" * 70)
    
    data = run_analyzer('examples_safe/ssrf_safe.py')
    
    # Check for A10_ssrf findings (should be none)
    a10_findings = [f for f in data['findings'] if f.get('category') == 'A10_ssrf']
    
    if a10_findings:
        print(f"❌ FAILED: Found {len(a10_findings)} false positive(s) in ssrf_safe.py")
        
        # Show details of false positives
        print("\n   False positives:")
        for finding in a10_findings:
            for instance in finding.get('instances', []):
                print(f"     - Line {instance['line_start']}: {instance['snippet']}")
        
        return False
    
    print("✅ No SSRF findings (as expected)")
    print("✅ PASSED: Safe examples not flagged")
    return True


def test_finding_format():
    """Test that findings have the correct schema format."""
    print("\n" + "=" * 70)
    print("TEST 4: Validate finding schema format")
    print("=" * 70)
    
    data = run_analyzer('examples/ssrf_requests.py')
    a10_findings = [f for f in data['findings'] if f.get('category') == 'A10_ssrf']
    
    if not a10_findings:
        print("❌ FAILED: No findings to validate")
        return False
    
    finding = a10_findings[0]
    
    # Check required fields
    required_fields = [
        'id', 'title', 'description', 'category', 'severity', 
        'rule_score', 'confidence', 'exploit_scenario', 
        'recommended_fix', 'references', 'instances'
    ]
    
    missing_fields = [field for field in required_fields if field not in finding]
    
    if missing_fields:
        print(f"❌ FAILED: Missing required fields: {missing_fields}")
        return False
    
    print(f"✅ Finding has all required fields")
    
    # Check that category is correct
    if finding['category'] != 'A10_ssrf':
        print(f"❌ FAILED: Expected category 'A10_ssrf', got '{finding['category']}'")
        return False
    
    print(f"✅ Category is 'A10_ssrf'")
    
    # Check severity is valid
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    if finding['severity'] not in valid_severities:
        print(f"❌ FAILED: Invalid severity '{finding['severity']}'")
        return False
    
    print(f"✅ Severity is valid: {finding['severity']}")
    
    # Check instances format
    if not isinstance(finding['instances'], list) or len(finding['instances']) == 0:
        print(f"❌ FAILED: Instances should be a non-empty list")
        return False
    
    instance = finding['instances'][0]
    instance_fields = ['file', 'line_start', 'line_end', 'snippet', 'explanation']
    missing_instance_fields = [field for field in instance_fields if field not in instance]
    
    if missing_instance_fields:
        print(f"❌ FAILED: Instance missing fields: {missing_instance_fields}")
        return False
    
    print(f"✅ Instance format is correct")
    
    # Check references
    if not isinstance(finding['references'], list):
        print(f"❌ FAILED: References should be a list")
        return False
    
    # Check for CWE-918 reference
    has_cwe_918 = any(
        ref.get('type') == 'CWE' and ref.get('value') == 'CWE-918' 
        for ref in finding['references']
    )
    
    if not has_cwe_918:
        print(f"❌ FAILED: Should reference CWE-918")
        return False
    
    print(f"✅ References include CWE-918")
    print("✅ PASSED: Finding format is correct")
    return True


def main():
    """Run all tests."""
    print("\n🧪 Testing OWASP A10 SSRF Detector\n")
    
    tests = [
        ("Vulnerable requests.py", test_vulnerable_requests),
        ("Vulnerable urllib.py", test_vulnerable_urllib),
        ("Safe examples", test_safe_examples),
        ("Finding format", test_finding_format),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            results.append((name, test_func()))
        except Exception as e:
            print(f"\n❌ Test '{name}' raised an exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
