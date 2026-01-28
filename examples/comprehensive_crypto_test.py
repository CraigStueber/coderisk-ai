"""
Comprehensive test for cryptographic failures detector

This file contains various patterns to validate the detector:
- Lines that SHOULD trigger findings
- Lines that should NOT trigger findings
"""

import hashlib
import random
import secrets
import os

# =============================================================================
# SHOULD FLAG: Hardcoded secrets (3 findings expected)
# =============================================================================

SECRET_KEY = "myhardcodedsecret"  # Should flag: hardcoded secret
API_KEY = "sk-test-1234567890abcdefg"  # Should flag: hardcoded API key
password = "SuperSecretPass123"  # Should flag: hardcoded password


# =============================================================================
# SHOULD FLAG: Weak hashing algorithms (2 findings expected)
# =============================================================================

def weak_hash_md5(data):
    return hashlib.md5(data.encode()).hexdigest()  # Should flag: MD5


def weak_hash_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()  # Should flag: SHA1


# =============================================================================
# SHOULD FLAG: Insecure randomness for tokens (3 findings expected)
# =============================================================================

session_token = random.randint(100000, 999999)  # Should flag: random for token
auth_key = str(random.random())  # Should flag: random for key
api_secret = random.choice(['abc', 'def', 'ghi'])  # Should flag: random for secret


# =============================================================================
# SHOULD NOT FLAG: Safe cryptographic practices
# =============================================================================

# Safe: Environment variables for secrets
api_key_safe = os.getenv("API_KEY")
password_safe = os.environ.get("PASSWORD")

# Safe: Strong hashing
def strong_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


def strong_hash_512(data):
    return hashlib.sha512(data.encode()).digest()


# Safe: Cryptographically secure randomness
secure_token = secrets.token_hex(32)
secure_key = secrets.token_urlsafe(16)
secure_bytes = os.urandom(64)

# Safe: Regular random for non-security purposes
dice = random.randint(1, 6)
card = random.choice(['hearts', 'diamonds', 'clubs', 'spades'])
lottery = random.random()


# =============================================================================
# EDGE CASES: Should NOT flag
# =============================================================================

# Short string - should NOT flag (less than 8 chars)
test = "short"

# Not a secret variable name - should NOT flag
config = "this_is_a_long_config_value_more_than_8_chars"

# Comment with secret keyword - should NOT flag
# password = "this_is_commented_out"
