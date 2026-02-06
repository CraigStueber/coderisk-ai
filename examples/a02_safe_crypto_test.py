"""Safe cryptographic code - should produce zero findings"""
import hashlib
import secrets
import os

# Safe: no hardcoded secrets
api_key = os.getenv("API_KEY")
password = input("Enter password: ")

# Safe: strong hashing algorithms
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def verify_hash(data):
    return hashlib.sha512(data.encode()).digest()

# Safe: cryptographically secure randomness
token = secrets.token_hex(32)
session_id = secrets.token_urlsafe(16)
random_bytes = os.urandom(64)

# Safe: regular random for non-security purposes
import random
lottery_number = random.randint(1, 100)
game_result = random.choice(['win', 'lose'])
