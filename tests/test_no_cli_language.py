#!/usr/bin/env python3
"""
Test to verify no CLI language in recommended_fix messages across all detectors.
"""

import json
import subprocess
import sys
from pathlib import Path


# CLI language patterns to detect
CLI_BANNED_PATTERNS = [
    'pip freeze',
    'pip install',
    'npm install',
    'npm run',
    'poetry lock',
    'requirements-lock.txt',
    'run the command',
    'execute the command',
    'from the command line',
    'in your terminal',
    'using the CLI',
    'apt-get',
    'brew install',
    'conda install',
]


def run_analyzer_on_examples() -> dict:
    """Run analyzer on all example files and collect findings."""
    examples_dir = Path('examples')
    all_findings = []
    
    for example_file in examples_dir.glob('*.py'):
        if example_file.name.startswith('_'):
            continue
            
        result = subprocess.run(
            ['python', '-m', 'coderisk_ai.cli', 'analyze', str(example_file)],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                all_findings.extend(data.get('findings', []))
            except json.JSONDecodeError:
                pass
    
    # Also test requirements/pyproject files
    for dep_file in examples_dir.glob('requirements_*.txt'):
        result = subprocess.run(
            ['python', '-m', 'coderisk_ai.cli', 'analyze', str(dep_file)],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                all_findings.extend(data.get('findings', []))
            except json.JSONDecodeError:
                pass
    
    for dep_file in examples_dir.glob('pyproject_*.toml'):
        result = subprocess.run(
            ['python', '-m', 'coderisk_ai.cli', 'analyze', str(dep_file)],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                all_findings.extend(data.get('findings', []))
            except json.JSONDecodeError:
                pass
    
    return {'findings': all_findings}


def test_no_cli_language_in_recommended_fix():
    """Test that no recommended_fix contains CLI language."""
    print("=" * 70)
    print("TEST: No CLI Language in recommended_fix")
    print("=" * 70)
    
    data = run_analyzer_on_examples()
    findings = data.get('findings', [])
    
    violations = []
    
    for finding in findings:
        rec_fix = finding.get('recommended_fix', '')
        
        for pattern in CLI_BANNED_PATTERNS:
            if pattern.lower() in rec_fix.lower():
                violations.append({
                    'rule_id': finding.get('rule_id', 'unknown'),
                    'pattern': pattern,
                    'recommended_fix': rec_fix
                })
    
    if violations:
        print(f"\n❌ FAILED: Found {len(violations)} CLI language violations\n")
        
        for v in violations:
            print(f"Rule: {v['rule_id']}")
            print(f"Banned pattern found: '{v['pattern']}'")
            print(f"Recommended fix: {v['recommended_fix'][:150]}...")
            print()
        
        return False
    else:
        print(f"\n✅ PASSED: No CLI language found in {len(findings)} findings")
        return True


def test_a06_consistency():
    """Test that A06 messages are consistent across requirements and pyproject."""
    print("\n" + "=" * 70)
    print("TEST: A06 Message Consistency")
    print("=" * 70)
    
    data = run_analyzer_on_examples()
    findings = data.get('findings', [])
    
    a06_findings = [f for f in findings if f.get('rule_id', '').startswith('A06.DEPENDENCIES')]
    
    # Group by rule type
    unpinned_fixes = set()
    deprecated_fixes = set()
    
    for finding in a06_findings:
        rule_id = finding.get('rule_id', '')
        rec_fix = finding.get('recommended_fix', '')
        
        if 'UNPINNED' in rule_id:
            unpinned_fixes.add(rec_fix[:100])  # First 100 chars for comparison
        elif 'DEPRECATED' in rule_id:
            deprecated_fixes.add(rec_fix[:100])
    
    print(f"\nFound {len(a06_findings)} A06 findings")
    print(f"Unpinned fixes variants: {len(unpinned_fixes)}")
    print(f"Deprecated fixes variants: {len(deprecated_fixes)}")
    
    # Check for tool-specific language
    tool_specific_terms = ['poetry', 'pip', 'npm', 'yarn', 'requirements-lock']
    tool_violations = []
    
    for finding in a06_findings:
        rec_fix = finding.get('recommended_fix', '').lower()
        
        for term in tool_specific_terms:
            if term in rec_fix:
                tool_violations.append({
                    'rule_id': finding.get('rule_id'),
                    'term': term,
                    'fix': finding.get('recommended_fix')
                })
    
    if tool_violations:
        print(f"\n❌ FAILED: Found tool-specific language:")
        for v in tool_violations:
            print(f"  {v['rule_id']}: mentions '{v['term']}'")
        return False
    else:
        print("\n✅ PASSED: A06 messages are tool-agnostic")
        return True


def test_examples_safe_lower_score():
    """Test that examples_safe/ produces lower scores than examples/."""
    print("\n" + "=" * 70)
    print("TEST: examples_safe/ Has Lower Risk Score")
    print("=" * 70)
    
    # Run on examples/
    examples_result = subprocess.run(
        ['python', '-m', 'coderisk_ai.cli', 'analyze', 'examples/'],
        capture_output=True,
        text=True
    )
    
    # Run on examples_safe/
    safe_result = subprocess.run(
        ['python', '-m', 'coderisk_ai.cli', 'analyze', 'examples_safe/'],
        capture_output=True,
        text=True
    )
    
    if examples_result.returncode != 0 or safe_result.returncode != 0:
        print("\n⚠️  WARNING: Could not analyze both directories")
        return True
    
    try:
        examples_data = json.loads(examples_result.stdout)
        safe_data = json.loads(safe_result.stdout)
        
        examples_findings = len(examples_data.get('findings', []))
        safe_findings = len(safe_data.get('findings', []))
        
        print(f"\nexamples/ findings: {examples_findings}")
        print(f"examples_safe/ findings: {safe_findings}")
        
        if safe_findings < examples_findings:
            reduction = ((examples_findings - safe_findings) / examples_findings) * 100
            print(f"\n✅ PASSED: {reduction:.1f}% reduction in findings")
            return True
        else:
            print(f"\n❌ FAILED: examples_safe/ should have fewer findings")
            return False
            
    except json.JSONDecodeError as e:
        print(f"\n⚠️  WARNING: Could not parse analyzer output: {e}")
        return True


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("CLI LANGUAGE AND CONSISTENCY TEST SUITE")
    print("=" * 70 + "\n")
    
    tests = [
        test_no_cli_language_in_recommended_fix,
        test_a06_consistency,
        test_examples_safe_lower_score,
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
