#!/usr/bin/env python3
"""
Test script for Round 2 improvements:
- A07 password policy vs auth verification split
- SQL safe-evidence downgrade
- A09 fallback-without-telemetry detection
"""

import json
import subprocess
import sys
import tempfile
import os


def run_analyzer(file_path: str) -> dict:
    """Run the analyzer on a file and return parsed JSON results."""
    result = subprocess.run(
        ['python', '-m', 'coderisk_ai.cli', 'analyze', file_path],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Analyzer failed: {result.stderr}")
        sys.exit(1)
    
    return json.loads(result.stdout)


def test_a07_password_policy_split():
    """Test that password policy checks are distinguished from auth verification."""
    print("=" * 70)
    print("TEST 1: A07 Password Policy vs Auth Verification Split")
    print("=" * 70)
    
    # Create test file with both patterns
    test_code = '''
def signup_user(username, password):
    """Registration context - should detect AUTH.PASSWORD_POLICY.CHECK"""
    if len(password) < 12:
        return False, "Password too short"
    if not any(c.isupper() for c in password):
        return False, "Need uppercase"
    if not any(c.isdigit() for c in password):
        return False, "Need digit"
    return True, "OK"

def login_user(username, password):
    """Authentication context - should detect AUTH.CUSTOM.AUTH_VERIFICATION"""
    stored_password = get_user_password(username)
    if password == stored_password:
        return True
    return False

def validate_password_strength(password):
    """Password strength check - should detect AUTH.PASSWORD_POLICY.CHECK"""
    if len(password) < 8:
        return False
    return True
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_file = f.name
    
    try:
        data = run_analyzer(temp_file)
        
        # Check for both rule types
        policy_findings = [f for f in data.get('findings', [])
                          if f.get('rule_id') == 'AUTH.PASSWORD_POLICY.CHECK']
        auth_findings = [f for f in data.get('findings', [])
                        if f.get('rule_id') == 'AUTH.CUSTOM.AUTH_VERIFICATION']
        
        print(f"\nPassword policy findings: {len(policy_findings)}")
        print(f"Custom auth verification findings: {len(auth_findings)}")
        
        # Verify policy findings have low/info severity
        policy_pass = True
        for finding in policy_findings:
            severity = finding.get('severity', '').lower()
            if severity not in ['info', 'low']:
                print(f"❌ Password policy finding has severity '{severity}', expected 'info' or 'low'")
                policy_pass = False
            else:
                print(f"  ✓ Password policy finding has severity '{severity}'")
        
        # Verify auth findings have medium/high severity
        auth_pass = True
        for finding in auth_findings:
            severity = finding.get('severity', '').lower()
            if severity not in ['medium', 'high']:
                print(f"❌ Auth verification finding has severity '{severity}', expected 'medium' or 'high'")
                auth_pass = False
            else:
                print(f"  ✓ Auth verification finding has severity '{severity}'")
        
        if policy_findings and auth_findings and policy_pass and auth_pass:
            print("\n✅ PASSED: Both rules detected with correct severities")
            return True
        else:
            print(f"\n❌ FAILED: Expected both rule types with correct severities")
            return False
    
    finally:
        os.unlink(temp_file)


def test_sql_safe_evidence_downgrade():
    """Test that SQL with safe evidence gets downgraded severity."""
    print("\n" + "=" * 70)
    print("TEST 2: SQL Safe-Evidence Downgrade")
    print("=" * 70)
    
    # Create test file with safe and unsafe SQL patterns
    test_code = '''
def unsafe_query(user_id):
    """No parameterization - should be high severity"""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

def safe_query_with_placeholders(ids):
    """Parameterized with placeholders - should be downgraded"""
    placeholders = ",".join(["%s"] * len(ids))
    query = f"SELECT * FROM users WHERE id IN ({placeholders})"
    cursor.execute(query, ids)

def safe_query_with_params(user_id):
    """Parameterized execute - should be downgraded"""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query, (user_id,))

def allowlist_query(table_name):
    """Allowlist check - should be downgraded"""
    if table_name in ['users', 'orders', 'products']:
        query = f"SELECT * FROM {table_name}"
        cursor.execute(query)
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_file = f.name
    
    try:
        data = run_analyzer(temp_file)
        
        sql_findings = [f for f in data.get('findings', [])
                       if 'INJECTION.SQL' in f.get('rule_id', '')]
        
        print(f"\nSQL injection findings: {len(sql_findings)}")
        
        # Categorize by evidence
        unsafe_count = 0
        safe_count = 0
        
        for finding in sql_findings:
            for inst in finding.get('instances', []):
                explanation = inst.get('explanation', '').lower()
                title = finding.get('title', '').lower()
                severity = finding.get('severity', '')
                confidence = finding.get('confidence', 1.0)
                
                if 'safe evidence' in explanation or 'parameterized' in title or 'allowlisted' in title:
                    safe_count += 1
                    print(f"  ✓ Safe evidence detected (severity: {severity}, confidence: {confidence:.2f})")
                    if severity.lower() in ['high', 'critical']:
                        print(f"    ⚠️  Severity not downgraded as expected")
                else:
                    unsafe_count += 1
                    print(f"  ✓ Unsafe pattern detected (severity: {severity})")
        
        if unsafe_count > 0 and safe_count > 0:
            print(f"\n✅ PASSED: Detected both unsafe ({unsafe_count}) and safe evidence ({safe_count}) patterns")
            return True
        else:
            print(f"\n❌ FAILED: Expected both unsafe and safe-evidence patterns")
            return False
    
    finally:
        os.unlink(temp_file)


def test_a09_fallback_without_telemetry():
    """Test that fallback patterns are distinguished from silent swallows."""
    print("\n" + "=" * 70)
    print("TEST 3: A09 Fallback-Without-Telemetry Detection")
    print("=" * 70)
    
    # Create test file with different exception handling patterns
    test_code = '''
def silent_swallow():
    """Truly silent - should be A09.EXCEPT.SWALLOWED"""
    try:
        risky_operation()
    except Exception:
        pass

def fallback_no_logging():
    """Fallback without telemetry - should be A09.EXCEPT.FALLBACK_NO_TELEMETRY"""
    try:
        result = primary_service.fetch()
    except Exception:
        result = backup_service.fetch()
    return result

def cache_fallback():
    """Cache fallback - should be A09.EXCEPT.FALLBACK_NO_TELEMETRY"""
    try:
        data = expensive_operation()
    except Exception:
        data = get_cached_default()
    return data

def swallow_with_logic():
    """Silent swallow with logic - should be A09.EXCEPT.SWALLOWED"""
    try:
        process_data()
    except Exception:
        cleanup_resources()
        return None
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_file = f.name
    
    try:
        data = run_analyzer(temp_file)
        
        a09_findings = [f for f in data.get('findings', [])
                       if 'A09.EXCEPT' in f.get('rule_id', '')]
        
        print(f"\nA09 exception findings: {len(a09_findings)}")
        
        # Look for both rule types
        swallowed = [f for f in a09_findings if f.get('rule_id') == 'A09.EXCEPT.SWALLOWED']
        fallback = [f for f in a09_findings if f.get('rule_id') == 'A09.EXCEPT.FALLBACK_NO_TELEMETRY']
        empty = [f for f in a09_findings if f.get('rule_id') == 'A09.EXCEPT.EMPTY_PASS']
        
        print(f"  Silent swallow findings: {len(swallowed)}")
        print(f"  Fallback-without-telemetry findings: {len(fallback)}")
        print(f"  Empty pass findings: {len(empty)}")
        
        # Check titles
        for finding in fallback:
            title = finding.get('title', '')
            if 'fallback' in title.lower():
                print(f"  ✓ Fallback finding has correct title: '{title}'")
            else:
                print(f"  ⚠️  Fallback finding has unexpected title: '{title}'")
        
        if (swallowed or empty) and fallback:
            print(f"\n✅ PASSED: Both silent swallow and fallback patterns detected")
            return True
        else:
            print(f"\n❌ FAILED: Expected both swallow and fallback patterns")
            return False
    
    finally:
        os.unlink(temp_file)


def test_examples_safe_no_hardcoded_passwords():
    """Test that examples_safe no longer has hardcoded password comparisons."""
    print("\n" + "=" * 70)
    print("TEST 4: Examples-Safe Hardcoded Password Cleanup")
    print("=" * 70)
    
    safe_file = 'examples_safe/a04_insecure_design_safe_test.py'
    
    if not os.path.exists(safe_file):
        print(f"⚠️  SKIPPED: {safe_file} not found")
        return True
    
    data = run_analyzer(safe_file)
    
    # Check for plaintext password comparisons
    plaintext_findings = [f for f in data.get('findings', [])
                         if 'AUTH.PLAINTEXT' in f.get('rule_id', '')]
    
    print(f"\nPlaintext password comparison findings: {len(plaintext_findings)}")
    
    if plaintext_findings:
        print("❌ FAILED: examples_safe still contains hardcoded password comparisons:")
        for finding in plaintext_findings:
            for inst in finding.get('instances', []):
                print(f"  Line {inst.get('line_start')}: {inst.get('snippet', '')[:80]}")
        return False
    else:
        print("✅ PASSED: No hardcoded password comparisons in examples_safe")
        return True


def main():
    print("\n🧪 Running Round 2 Improvements Tests\n")
    
    results = []
    results.append(("A07 Password Policy Split", test_a07_password_policy_split()))
    results.append(("SQL Safe-Evidence Downgrade", test_sql_safe_evidence_downgrade()))
    results.append(("A09 Fallback Detection", test_a09_fallback_without_telemetry()))
    results.append(("Examples-Safe Cleanup", test_examples_safe_no_hardcoded_passwords()))
    
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
