"""
Safe version - Cryptographic Failures Fixed
This file demonstrates proper cryptographic practices.
"""
import hashlib
import secrets
import os
from passlib.hash import argon2


# SAFE: No hardcoded secrets - use environment variables
def get_api_key() -> str:
    """Retrieve API key from environment variable"""
    api_key = os.getenv("API_KEY")
    if not api_key:
        raise ValueError("API_KEY environment variable not set")
    return api_key


def get_auth_token() -> str:
    """Retrieve auth token from secure configuration"""
    token = os.getenv("AUTH_TOKEN")
    if not token:
        raise ValueError("AUTH_TOKEN environment variable not set")
    return token


# SAFE: Use proper password hashing
def hash_password_safe(pwd: str) -> str:
    """Hash password using argon2 (recommended)"""
    return argon2.hash(pwd)


def verify_password_safe(pwd: str, pwd_hash: str) -> bool:
    """Verify password using argon2"""
    return argon2.verify(pwd, pwd_hash)


# SAFE: Use SHA-256 for general hashing (not passwords)
def hash_data_safe(data: str) -> str:
    """Hash data using SHA-256 for integrity checks"""
    return hashlib.sha256(data.encode()).hexdigest()


def hash_file_safe(filepath: str) -> str:
    """Hash file contents for integrity verification"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# SAFE: Use secrets module for cryptographic randomness
def generate_session_token() -> str:
    """Generate cryptographically secure session token"""
    return secrets.token_hex(32)


def generate_api_key() -> str:
    """Generate cryptographically secure API key"""
    return secrets.token_urlsafe(32)


def generate_verification_code() -> str:
    """Generate secure 6-digit verification code"""
    return str(secrets.randbelow(900000) + 100000)


def generate_secret_key() -> bytes:
    """Generate cryptographically secure secret key"""
    return secrets.token_bytes(32)


# SAFE: Use os.urandom for random bytes
def generate_salt() -> bytes:
    """Generate cryptographic salt"""
    return os.urandom(16)


def generate_iv() -> bytes:
    """Generate initialization vector for encryption"""
    return os.urandom(16)


# SAFE: Proper key derivation
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2"""
    import hashlib
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)


# SAFE: Use random module only for non-security purposes
def roll_dice() -> int:
    """Roll a dice (non-security use of random is OK)"""
    import random
    return random.randint(1, 6)


def get_game_choice() -> str:
    """Get random game choice (non-security use)"""
    import random
    return random.choice(['rock', 'paper', 'scissors'])


def shuffle_deck() -> list:
    """Shuffle a deck of cards (non-security use)"""
    import random
    deck = list(range(1, 53))
    random.shuffle(deck)
    return deck


# SAFE: Complete example - secure user registration
def register_user(username: str, password: str, email: str) -> dict:
    """
    Securely register a new user with proper cryptography.
    """
    # Generate salt for email verification
    verification_salt = generate_salt()
    
    # Hash password properly
    password_hash = hash_password_safe(password)
    
    # Generate secure verification token
    verification_token = secrets.token_urlsafe(32)
    
    # Generate secure user ID
    user_id = secrets.token_hex(16)
    
    return {
        'user_id': user_id,
        'username': username,
        'password_hash': password_hash,
        'email': email,
        'verification_token': verification_token,
        'verification_salt': verification_salt.hex()
    }


# SAFE: Secure token comparison
def verify_token(provided_token: str, stored_token: str) -> bool:
    """
    Verify token using constant-time comparison to prevent timing attacks.
    """
    return secrets.compare_digest(provided_token, stored_token)
