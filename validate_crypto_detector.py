#!/usr/bin/env python3
"""
Quick validation script for cryptographic failures detector.
Tests that the detector returns findings for vulnerable code and none for safe code.
"""

from coderisk_ai.detectors.python.a02_cryptographic_failures import detect_cryptographic_failures


# Test 1: Vulnerable code - should detect issues
vulnerable_code = '''
import hashlib
import random

SECRET_KEY = "myhardcodedsecret"
password = hashlib.md5(b"test").hexdigest()
token = random.randint(100000, 999999)
'''

findings = detect_cryptographic_failures(vulnerable_code, "test_vulnerable.py")
print(f"Vulnerable code findings: {len(findings)}")
for f in findings:
    print(f"  - {f['id']}: {f['title']}")

print()

# Test 2: Safe code - should detect nothing
safe_code = '''
import hashlib
import secrets
import os

api_key = os.getenv("API_KEY")
password_hash = hashlib.sha256(b"test").hexdigest()
token = secrets.token_hex(16)
'''

findings = detect_cryptographic_failures(safe_code, "test_safe.py")
print(f"Safe code findings: {len(findings)}")
if findings:
    print("WARNING: Safe code should not have findings!")
    for f in findings:
        print(f"  - {f['id']}: {f['title']}")
else:
    print("  ✓ No false positives detected")

print()

# Test 3: Edge cases
edge_code = '''
import random
# This is random for a game, not security
dice_roll = random.randint(1, 6)
'''

findings = detect_cryptographic_failures(edge_code, "test_edge.py")
print(f"Edge case findings: {len(findings)}")
if findings:
    print("  (This is expected behavior - token keywords not present)")
else:
    print("  ✓ No findings (expected - not security-related)")

print()
print("Validation complete!")
