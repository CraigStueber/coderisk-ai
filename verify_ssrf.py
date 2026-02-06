#!/usr/bin/env python3
"""
Quick manual verification of SSRF detector.
This script directly imports and tests the detector without using the CLI.
"""
from coderisk_ai.detectors.python.a10_ssrf import detect_ssrf


# Test 1: Vulnerable code with requests
test_vulnerable_requests = '''
import requests
import sys

def fetch_data():
    url = sys.argv[1]
    response = requests.get(url)
    return response.text
'''

# Test 2: Vulnerable code with urllib
test_vulnerable_urllib = '''
import urllib.request

def fetch_page():
    url = input("Enter URL: ")
    response = urllib.request.urlopen(url)
    return response.read()
'''

# Test 3: Safe code with constant URL
test_safe_constant = '''
import requests

def fetch_status():
    response = requests.get("https://api.example.com/status")
    return response.json()
'''

# Test 4: Vulnerable f-string
test_vulnerable_fstring = '''
import requests
import os

def webhook_call():
    host = os.environ["WEBHOOK_HOST"]
    url = f"http://{host}/callback"
    response = requests.post(url, json={"event": "test"})
    return response.status_code
'''


def print_findings(findings, test_name):
    """Print findings in a readable format."""
    print(f"\n{'='*60}")
    print(f"Test: {test_name}")
    print(f"{'='*60}")
    
    if not findings:
        print("✅ No findings (as expected for safe code)")
        return
    
    for finding in findings:
        print(f"\n🔍 Finding: {finding['title']}")
        print(f"   ID: {finding['id']}")
        print(f"   Severity: {finding['severity']}")
        print(f"   Category: {finding['category']}")
        print(f"   Rule Score: {finding['rule_score']}")
        print(f"   Confidence: {finding['confidence']}")
        
        if 'instances' in finding:
            print(f"\n   Instances ({len(finding['instances'])}):")
            for inst in finding['instances'][:3]:  # Show first 3
                print(f"     - Line {inst['line_start']}: {inst['snippet']}")
                print(f"       {inst['explanation']}")


def main():
    print("\n🧪 SSRF Detector Quick Verification")
    print("="*60)
    
    # Test 1: Vulnerable requests
    findings1 = detect_ssrf(test_vulnerable_requests, "test_requests.py")
    print_findings(findings1, "Vulnerable requests.get with sys.argv")
    if findings1:
        print("✅ PASS: Detected SSRF vulnerability")
    else:
        print("❌ FAIL: Should have detected SSRF")
    
    # Test 2: Vulnerable urllib
    findings2 = detect_ssrf(test_vulnerable_urllib, "test_urllib.py")
    print_findings(findings2, "Vulnerable urllib.request.urlopen with input()")
    if findings2:
        print("✅ PASS: Detected SSRF vulnerability")
    else:
        print("❌ FAIL: Should have detected SSRF")
    
    # Test 3: Safe constant
    findings3 = detect_ssrf(test_safe_constant, "test_safe.py")
    print_findings(findings3, "Safe constant URL")
    if not findings3:
        print("✅ PASS: No false positive")
    else:
        print("❌ FAIL: Should NOT have detected SSRF")
    
    # Test 4: Vulnerable f-string
    findings4 = detect_ssrf(test_vulnerable_fstring, "test_fstring.py")
    print_findings(findings4, "Vulnerable f-string with os.environ")
    if findings4:
        print("✅ PASS: Detected SSRF vulnerability")
    else:
        print("❌ FAIL: Should have detected SSRF")
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    
    tests = [
        ("Vulnerable requests", bool(findings1)),
        ("Vulnerable urllib", bool(findings2)),
        ("Safe constant (no FP)", not bool(findings3)),
        ("Vulnerable f-string", bool(findings4)),
    ]
    
    passed = sum(1 for _, result in tests if result)
    total = len(tests)
    
    for name, result in tests:
        status = "✅" if result else "❌"
        print(f"{status} {name}")
    
    print(f"\nResult: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All quick verification tests passed!")
        print("\nYou can now run:")
        print("  - python -m coderisk_ai.cli analyze examples/a10_ssrf_requests_test.py --pretty")
        print("  - python tests/test_ssrf_a10.py")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")


if __name__ == "__main__":
    main()
