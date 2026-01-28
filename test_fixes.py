#!/usr/bin/env python3
"""Quick test to verify the final polish fixes"""

from coderisk_ai.cli import build_result
import json

print("=" * 70)
print("FINAL POLISH VERIFICATION")
print("=" * 70)

# Test 1: Algorithm in instances + enhanced title
print("\n1. Algorithm field location and title enhancement")
print("-" * 70)

result = build_result("examples/comprehensive_crypto_test.py")
weak_hash_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO.WEAK.HASH"]

if weak_hash_findings:
    finding = weak_hash_findings[0]
    
    # Check algorithm NOT at finding level
    if "algorithm" not in finding:
        print("✓ Algorithm not at finding level")
    else:
        print("✗ FAIL: Algorithm still at finding level")
    
    # Check algorithm IN instances
    algorithms = [inst.get("algorithm") for inst in finding["instances"]]
    if all(algorithms):
        print(f"✓ Algorithm in all instances: {', '.join(set(algorithms))}")
    else:
        print("✗ FAIL: Algorithm missing from some instances")
    
    # Check title enhancement
    if len(set(algorithms)) > 1:
        if "MD5" in finding["title"] or "SHA1" in finding["title"]:
            print(f"✓ Title enhanced with algorithms: {finding['title']}")
        else:
            print(f"⚠ Title not enhanced (multiple algorithms detected): {finding['title']}")
    else:
        print(f"  Title: {finding['title']}")

# Test 2: Confidence calculation and documentation
print("\n2. Finding-level confidence (max of instances)")
print("-" * 70)

result = build_result("examples/security_misconfiguration.py")
debug_findings = [f for f in result["findings"] if f["rule_id"] == "MISCONFIG.DEBUG.TRUE"]

if debug_findings:
    finding = debug_findings[0]
    instance_confs = [inst.get("confidence", finding["confidence"]) for inst in finding["instances"]]
    max_conf = max(instance_confs)
    
    if finding["confidence"] == max_conf:
        print(f"✓ Finding confidence = max(instance confidences) = {max_conf}")
    else:
        print(f"✗ FAIL: Finding confidence ({finding['confidence']}) != max ({max_conf})")
    
    print(f"  Instance confidences: {instance_confs}")

# Test 3: Clean explanations (no password advice for medium severity)
print("\n3. Context-appropriate explanations")
print("-" * 70)

result = build_result("examples/comprehensive_crypto_test.py")
weak_hash_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO.WEAK.HASH"]

if weak_hash_findings:
    finding = weak_hash_findings[0]
    
    # Check each instance explanation
    for inst in finding["instances"]:
        expl = inst["explanation"]
        has_password_advice = any(word in expl.lower() for word in ["bcrypt", "scrypt", "argon2"])
        has_security_context = "security-sensitive context" in expl.lower()
        
        if has_security_context:
            if has_password_advice:
                print(f"✓ High-severity instance (line {inst['line_start']}): includes password advice")
            else:
                print(f"⚠ High-severity instance missing password advice")
        else:
            if not has_password_advice:
                print(f"✓ Medium-severity instance (line {inst['line_start']}): no password advice")
            else:
                print(f"✗ FAIL: Medium-severity instance includes password advice")

# Test 4: Backward compatibility and deprecation
print("\n4. Score field backward compatibility")
print("-" * 70)

if result["findings"]:
    finding = result["findings"][0]
    
    if "rule_score" in finding:
        print(f"✓ rule_score present (canonical): {finding['rule_score']}")
    else:
        print("✗ FAIL: rule_score missing")
    
    if "score_contribution" in finding:
        print(f"✓ score_contribution present (deprecated): {finding['score_contribution']}")
    else:
        print("✗ FAIL: score_contribution missing")
    
    if finding.get("rule_score") == finding.get("score_contribution"):
        print("✓ Both fields have identical values")
    else:
        print("✗ FAIL: Fields have different values")

# Test 5: Clean snippets
print("\n5. Clean snippets (no confusing comments)")
print("-" * 70)

result = build_result("examples/security_misconfiguration.py")
debug_findings = [f for f in result["findings"] if f["rule_id"] == "MISCONFIG.DEBUG.TRUE"]

if debug_findings:
    finding = debug_findings[0]
    for inst in finding["instances"]:
        snippet = inst["snippet"]
        if "should not flag" in snippet.lower():
            print(f"✗ FAIL: Line {inst['line_start']} has confusing comment: {snippet}")
        else:
            print(f"✓ Clean snippet (line {inst['line_start']}): {snippet[:50]}...")

print("\n" + "=" * 70)
print("VERIFICATION COMPLETE")
print("=" * 70)

