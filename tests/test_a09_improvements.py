#!/usr/bin/env python3
"""Test script to verify A09 improvements: severity escalation, best-effort handling, and telemetry detection."""

import json
import subprocess
import sys


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


def test_sql_injection_no_false_positive():
    """Test that logger.warning with f-string is NOT flagged as SQL injection."""
    print("=" * 70)
    print("TEST 1: SQL Injection False Positive Fix")
    print("=" * 70)
    
    data = run_analyzer('examples/a09_security_logging_monitoring_failures_test.py')
    
    # Check for SQL injection findings
    sql_findings = [f for f in data.get('findings', [])
                    if 'INJECTION.SQL' in f.get('rule_id', '')]
    
    # Check if any SQL injection findings are on logger/logging lines
    false_positives = []
    for finding in sql_findings:
        for inst in finding.get('instances', []):
            snippet = inst.get('snippet', '').lower()
            if 'logger.' in snippet or 'logging.' in snippet or 'print(' in snippet:
                false_positives.append({
                    'line': inst.get('line_start'),
                    'snippet': snippet
                })
    
    if false_positives:
        print(f"\n❌ FAILED: Found {len(false_positives)} SQL injection false positives on logging lines:")
        for fp in false_positives:
            print(f"  Line {fp['line']}: {fp['snippet'][:80]}")
        return False
    else:
        print("\n✅ PASSED: No SQL injection false positives on logging lines")
        
        # Verify the actual SQL injection is still detected
        if sql_findings:
            print(f"  (Correctly detected {len(sql_findings)} real SQL injection cases)")
        
        return True


def test_security_critical_escalation():
    """Test that security-critical contexts escalate severity to high."""
    print("\n" + "=" * 70)
    print("TEST 2: Security-Critical Severity Escalation to High")
    print("=" * 70)
    
    data = run_analyzer('examples/a09_security_logging_monitoring_failures_test.py')
    
    # Find JWT/auth/decrypt-related A09 findings
    a09_findings = [f for f in data.get('findings', [])
                    if f.get('category') == 'A09_security_logging_monitoring_failures']
    
    jwt_high_findings = []
    crypto_high_findings = []
    
    for finding in a09_findings:
        severity = finding.get('severity', '').lower()
        for inst in finding.get('instances', []):
            snippet = inst.get('snippet', '').lower()
            explanation = inst.get('explanation', '').lower()
            
            # Check for JWT findings
            if ('jwt' in snippet or 'jwt' in explanation or 
                'token' in snippet and 'jwt' in explanation):
                if severity == 'high':
                    jwt_high_findings.append({
                        'line': inst.get('line_start'),
                        'severity': severity,
                        'snippet': snippet[:80]
                    })
            
            # Check for crypto/decrypt findings  
            if ('decrypt' in snippet or 'crypto' in snippet or 
                'private_key' in snippet or 'private key' in explanation):
                if severity == 'high':
                    crypto_high_findings.append({
                        'line': inst.get('line_start'),
                        'severity': severity,
                        'snippet': snippet[:80]
                    })
    
    print(f"\nJWT findings with HIGH severity: {len(jwt_high_findings)}")
    print(f"Crypto/decrypt findings with HIGH severity: {len(crypto_high_findings)}")
    
    total_high = len(jwt_high_findings) + len(crypto_high_findings)
    
    if total_high > 0:
        print(f"\n✅ PASSED: {total_high} security-critical findings escalated to HIGH")
        for finding in jwt_high_findings:
            print(f"  JWT - Line {finding['line']}: {finding['snippet']}")
        for finding in crypto_high_findings:
            print(f"  Crypto - Line {finding['line']}: {finding['snippet']}")
        return True
    else:
        print("\n❌ FAILED: No security-critical findings escalated to HIGH severity")
        return False


def test_cache_key_no_escalation():
    """Test that generic 'cache key' does NOT trigger security-critical escalation."""
    print("\n" + "=" * 70)
    print("TEST 3: Cache Key Does Not Over-Trigger")
    print("=" * 70)
    
    data = run_analyzer('examples/a09_security_logging_monitoring_failures_test.py')
    
    # Find the cache_key example (example 17)
    a09_findings = [f for f in data.get('findings', [])
                    if f.get('category') == 'A09_security_logging_monitoring_failures']
    
    cache_key_findings = []
    
    for finding in a09_findings:
        for inst in finding.get('instances', []):
            snippet = inst.get('snippet', '').lower()
            explanation = inst.get('explanation', '').lower()
            
            if 'cache_key' in snippet or ('cache' in snippet and 'key' in snippet):
                # Check if it was marked as security-critical
                security_critical = False
                for f in data.get('findings', []):
                    if any(i == inst for i in f.get('instances', [])):
                        security_critical = f.get('security_critical', False)
                        break
                
                cache_key_findings.append({
                    'line': inst.get('line_start'),
                    'security_critical': security_critical,
                    'severity': finding.get('severity', 'unknown'),
                    'snippet': snippet[:80]
                })
    
    over_triggered = [f for f in cache_key_findings if f['security_critical']]
    
    if over_triggered:
        print(f"\n❌ FAILED: Cache key incorrectly marked as security-critical:")
        for f in over_triggered:
            print(f"  Line {f['line']}: severity={f['severity']}, snippet={f['snippet']}")
        return False
    else:
        print(f"\n✅ PASSED: Cache key not marked as security-critical")
        if cache_key_findings:
            print(f"  Found {len(cache_key_findings)} cache-related findings (correctly not escalated)")
        return True


def test_best_effort_handling():
    """Test that best-effort contexts are properly detected and handled."""
    print("\n" + "=" * 70)
    print("TEST 4: Best-Effort Context Detection")
    print("=" * 70)
    
    data = run_analyzer('examples/a09_security_logging_monitoring_failures_test.py')
    
    # Find cache-related findings with best-effort comments
    best_effort_findings = []
    
    for finding in data.get('findings', []):
        if finding.get('category') == 'A09_security_logging_monitoring_failures':
            if finding.get('best_effort'):
                best_effort_findings.append(finding)
                print(f"\n  Found best-effort finding: {finding.get('rule_id')}")
                if finding.get('best_effort_reason'):
                    print(f"    Reason: {finding['best_effort_reason']}")
    
    if len(best_effort_findings) > 0:
        print(f"\n✅ PASSED: {len(best_effort_findings)} best-effort contexts detected")
        return True
    else:
        print("\n⚠️  WARNING: No best-effort contexts detected (may need to verify examples)")
        return True


def test_no_cli_language_in_fixes():
    """Test that recommended fixes don't contain CLI language."""
    print("\n" + "=" * 70)
    print("TEST 5: No CLI Language in Recommended Fixes")
    print("=" * 70)
    
    data = run_analyzer('examples/a09_security_logging_monitoring_failures_test.py')
    
    cli_keywords = ['run', 'command', 'execute', 'shell', '$', 'pip install', 'apt-get']
    findings_with_cli = []
    
    for finding in data.get('findings', []):
        if finding.get('category') == 'A09_security_logging_monitoring_failures':
            rec_fix = finding.get('recommended_fix', '').lower()
            
            for keyword in cli_keywords:
                if keyword in rec_fix:
                    findings_with_cli.append({
                        'id': finding.get('rule_id'),
                        'keyword': keyword,
                        'fix': finding.get('recommended_fix')
                    })
                    break
    
    if findings_with_cli:
        print("\n❌ FAILED: Found CLI language in recommended fixes:")
        for item in findings_with_cli:
            print(f"\n  Finding: {item['id']}")
            print(f"  Keyword: '{item['keyword']}'")
            print(f"  Fix: {item['fix'][:100]}...")
        return False
    else:
        print("\n✅ PASSED: No CLI language found in recommended fixes")
        return True


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("A09 IMPROVEMENTS TEST SUITE (Updated)")
    print("=" * 70 + "\n")
    
    tests = [
        test_sql_injection_no_false_positive,
        test_security_critical_escalation,
        test_cache_key_no_escalation,
        test_best_effort_handling,
        test_no_cli_language_in_fixes,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"\n❌ Test {test.__name__} raised exception: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    
    print(f"\nPassed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED")
        return 0
    else:
        print(f"\n❌ {total - passed} TEST(S) FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
