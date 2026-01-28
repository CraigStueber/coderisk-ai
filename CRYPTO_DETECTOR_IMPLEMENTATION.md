# Cryptographic Failures Detector - Implementation Summary

## Files Created/Modified

### New Detector

- **src/coderisk_ai/detectors/python/cryptographic_failures.py**
  - Main detector implementation
  - Function signature: `detect_cryptographic_failures(source: str, file_path: str) -> list[dict]`
  - Line-based scanning with regex patterns
  - No AST parsing

### Integration Changes

- **src/coderisk*ai/detectors/python/\_init*.py**
  - Added import for `detect_cryptographic_failures`
  - Added to `__all__` export list

- **src/coderisk_ai/cli.py**
  - Added import for the new detector
  - Integrated detector call in `analyze_file()` function
  - Added A02_cryptographic_failures to OWASP rollup calculation

### Example Files

- **examples/cryptographic_failures.py** - Basic demonstration
- **examples/safe_crypto.py** - Safe code (zero findings expected)
- **examples/comprehensive_crypto_test.py** - Comprehensive test cases

### Validation Script

- **validate_crypto_detector.py** - Quick validation script

## Detection Patterns

### 1. Hardcoded Secrets (CRYPTO.HARDCODED.SECRET)

- **Pattern**: Variables named like `secret`, `password`, `api_key`, `token`, `auth_token`, etc.
- **Trigger**: Hardcoded string values ≥ 8 characters
- **Severity**: High
- **Confidence**: 0.80
- **Score Contribution**: ~4.48
- **CWE References**: CWE-798, CWE-259

**Example**:

```python
SECRET_KEY = "myhardcodedsecret"  # FLAGGED
API_KEY = "sk-test-1234567890"    # FLAGGED
```

### 2. Weak Hashing Algorithms (CRYPTO.WEAK.HASH)

- **Pattern**: `hashlib.md5()` or `hashlib.sha1()`
- **Severity**: High
- **Confidence**: 0.85
- **Score Contribution**: ~3.57
- **CWE References**: CWE-327, CWE-328

**Example**:

```python
hashlib.md5(password.encode()).hexdigest()   # FLAGGED
hashlib.sha1(data.encode()).digest()         # FLAGGED
```

### 3. Insecure Randomness (CRYPTO.INSECURE.RANDOM)

- **Pattern**: `random.random()`, `random.randint()`, or `random.choice()` in token-like context
- **Context Detection**: Line contains keywords like `token`, `secret`, `key`, `session`, `auth`, `api_key`, `password`
- **Severity**: Medium
- **Confidence**: 0.70
- **Score Contribution**: ~2.10
- **CWE References**: CWE-338

**Example**:

```python
session_token = random.randint(100000, 999999)  # FLAGGED
auth_key = str(random.random())                 # FLAGGED
api_secret = random.choice(['a', 'b', 'c'])     # FLAGGED
```

## Safe Patterns (Not Flagged)

### Safe Secrets Management

```python
api_key = os.getenv("API_KEY")
password = os.environ.get("PASSWORD")
```

### Strong Hashing

```python
hashlib.sha256(data.encode()).hexdigest()
hashlib.sha512(data.encode()).digest()
```

### Cryptographically Secure Randomness

```python
secrets.token_hex(32)
secrets.token_urlsafe(16)
secrets.randbelow(1000000)
os.urandom(64)
```

### Non-Security Random Usage

```python
dice_roll = random.randint(1, 6)          # NOT FLAGGED - no token keywords
game_choice = random.choice(['a', 'b'])   # NOT FLAGGED - no token keywords
```

## Output Format

Each finding conforms to the CodeRisk AI schema:

```python
{
    "id": "CRYPTO.HARDCODED.SECRET",
    "title": "Hardcoded secret detected",
    "description": "A variable name suggests it contains sensitive data...",
    "category": "A02_cryptographic_failures",
    "severity": "high",
    "score_contribution": 4.48,
    "confidence": 0.80,
    "evidence": {
        "file": "path/to/file.py",
        "line_start": 10,
        "line_end": 10,
        "snippet": "SECRET_KEY = \"myhardcodedsecret\"",
        "explanation": "Hardcoded secrets in source code can be easily extracted..."
    },
    "references": [
        {"type": "CWE", "value": "CWE-798"},
        {"type": "CWE", "value": "CWE-259"},
        {"type": "OWASP", "value": "A02:2021 Cryptographic Failures"}
    ]
}
```

## Design Decisions

1. **Line-based scanning**: Simple, fast, and predictable
2. **One finding per line**: Prevents duplicate findings
3. **Conservative confidence values**: 0.70-0.85 range
4. **Realistic score contributions**: 2.10-4.48 range
5. **Context-aware random detection**: Only flags when token-like variable names are present
6. **No false positives on safe APIs**: Explicitly avoids flagging `secrets.*` and `os.urandom()`

## Testing Recommendations

Run the detector on the example files:

```bash
python -m coderisk_ai.cli analyze examples/cryptographic_failures.py --pretty
python -m coderisk_ai.cli analyze examples/safe_crypto.py --pretty
python -m coderisk_ai.cli analyze examples/comprehensive_crypto_test.py --pretty
```

Or use the validation script:

```bash
python validate_crypto_detector.py
```

## Completion Checklist

✅ Detector implementation matches project conventions  
✅ Function signature matches specification  
✅ Output format conforms to existing schema  
✅ Finding IDs use specified format (CRYPTO.\*)  
✅ Category set to "A02_cryptographic_failures"  
✅ Severity values (high/medium) match requirements  
✅ Confidence values in 0.7-0.85 range  
✅ CWE and OWASP references included  
✅ CLI integration complete  
✅ OWASP rollup includes A02 category  
✅ No unrelated code modified  
✅ No new dependencies added  
✅ Zero findings on safe code  
✅ Findings on obvious misuse patterns
