"""Test file to demonstrate cryptographic failures detector"""
import hashlib
import random
import secrets
import os

# Should be flagged: hardcoded secrets
API_KEY = "sk_test_abcdef123456789"
password = "mypassword123"
auth_token = "bearer_xyz_super_secret"

# Should be flagged: weak hashing
def hash_password_weak(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def verify_hash(data):
    return hashlib.sha1(data.encode()).digest()

# Should be flagged: insecure randomness for tokens
session_token = random.randint(100000, 999999)
api_key = str(random.random())
secret = random.choice(['a', 'b', 'c', 'd'])

# Should NOT be flagged: safe alternatives
safe_token = secrets.token_hex(16)
safe_random = secrets.randbelow(1000000)
safe_bytes = os.urandom(32)

# Should NOT be flagged: strong hashing
def hash_password_strong(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

# Should NOT be flagged: random for non-security purposes
dice_roll = random.randint(1, 6)
game_choice = random.choice(['rock', 'paper', 'scissors'])
