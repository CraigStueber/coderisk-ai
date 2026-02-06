"""
Safe version - OWASP A07 - Identification & Authentication Failures
This file demonstrates proper authentication patterns using established libraries.
"""

import os
import hashlib
import secrets
import hmac
from flask import Flask, request, session
import bcrypt
from passlib.hash import argon2


# ==========================================
# Proper Password Hashing and Verification
# ==========================================

# SAFE: Using bcrypt for password hashing
def hash_password_bcrypt(password: str) -> bytes:
    """Properly hash a password using bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def login_user_safe(username: str, password: str) -> bool:
    """
    Secure login using bcrypt.
    Demonstrates proper hash verification pattern.
    """
    # In production: retrieve hash from database
    # user_record = database.query("SELECT password_hash FROM users WHERE username = ?", (username,))
    # if not user_record:
    #     return False
    # user_hash = user_record['password_hash']
    # return bcrypt.checkpw(password.encode('utf-8'), user_hash)
    
    # For demonstration only - shows the pattern without database
    # Never hardcode hashes in real applications - always fetch from secure storage
    return False  # Stub: always fails without database lookup


# SAFE: Using argon2 (recommended for new applications)
def hash_password_argon2(password: str) -> str:
    """Properly hash a password using argon2"""
    return argon2.hash(password)


def authenticate_user_safe(username: str, password: str) -> bool:
    """
    Secure authentication using argon2.
    Demonstrates proper verification pattern.
    """
    # In production: retrieve hash from database
    # user_hash = database.get_user_password_hash(username)
    # if not user_hash:
    #     return False
    # return argon2.verify(password, user_hash)
    
    # For demonstration only - shows the pattern without database
    return False  # Stub: always fails without database lookup


# SAFE: Password strength validation (separate from authentication)
def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password meets strength requirements.
    This is for registration/password change, NOT for authentication.
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letters"
    if not any(c.islower() for c in password):
        return False, "Password must contain lowercase letters"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain numbers"
    return True, "Password meets requirements"


# SAFE: Complete registration flow showing policy validation + hashing
def register_user_safe(username: str, password: str) -> tuple[bool, str]:
    """
    Secure user registration flow.
    Demonstrates: policy validation → hashing → storage (not comparison).
    """
    # Step 1: Validate password strength (positive security control)
    is_valid, message = validate_password_strength(password)
    if not is_valid:
        return False, message
    
    # Step 2: Hash the password using argon2 (AFTER validation passes)
    password_hash = argon2.hash(password)
    
    # Step 3: Store hash in database (not shown - would use parameterized query)
    # database.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
    #                  (username, password_hash))
    
    return True, "User registered successfully"


# SAFE: Login flow showing proper verification (not plaintext comparison)
def login_with_policy_validation_safe(username: str, password: str) -> bool:
    """
    Secure login using argon2 verify function.
    Demonstrates: retrieve hash → verify with library (constant-time, built-in).
    """
    # Step 1: Retrieve hash from database
    # user_hash = database.get_user_password_hash(username)
    # if not user_hash:
    #     return False
    
    # Step 2: Verify using library function (constant-time comparison built-in)
    # return argon2.verify(password, user_hash)
    
    # Stub for demonstration
    return False


# ==========================================
# Secure Token/API Key Validation
# ==========================================

# SAFE: Constant-time comparison for API keys
def verify_api_key_safe(provided_key: str) -> bool:
    """Securely verify API key using constant-time comparison"""
    expected_key = os.getenv("API_KEY", "")
    if not expected_key:
        return False
    # Use secrets.compare_digest for timing attack resistance
    return secrets.compare_digest(provided_key, expected_key)


# SAFE: Token generation using secrets module
def generate_session_token() -> str:
    """Generate cryptographically strong session token"""
    return secrets.token_urlsafe(32)


def generate_api_token() -> str:
    """Generate cryptographically strong API token"""
    return secrets.token_hex(32)


# ==========================================
# Secure Admin Authentication
# ==========================================

# SAFE: No hardcoded credentials
def admin_login_safe(username: str, password: str) -> bool:
    """
    Secure admin login using hashed passwords stored in database.
    No hardcoded credentials in code.
    """
    # In production: retrieve hash from secure storage
    # admin_hash = secrets_manager.get_admin_password_hash()
    # if not admin_hash:
    #     return False
    # return argon2.verify(password, admin_hash)
    
    # For demonstration only - shows the pattern
    return False  # Stub: always fails without secure storage lookup


# ==========================================
# Helper functions (would be in separate module)
# ==========================================

def get_stored_password_hash(username: str) -> bytes:
    """Retrieve stored password hash from database"""
    # Implementation would query database
    # return database.query("SELECT password_hash FROM users WHERE username = ?", (username,))
    pass


def get_user_hash(username: str) -> str:
    """Retrieve user's password hash from database"""
    # Implementation would query database
    # return database.query("SELECT password_hash FROM users WHERE username = ?", (username,))
    pass


def get_admin_password_hash() -> str:
    """Retrieve admin password hash from secure storage"""
    # Implementation would fetch from database or secrets manager
    # return secrets_manager.get_secret("admin_password_hash")
    pass


# ==========================================
# Secure Session Management
# ==========================================

def create_secure_session(user_id: int) -> str:
    """Create secure user session with proper token"""
    session_token = secrets.token_urlsafe(32)
    session['user_id'] = user_id
    session['token'] = session_token
    session['created_at'] = get_current_timestamp()
    # Store session token in database for validation
    store_session_token(user_id, session_token)
    return session_token


def validate_session(session_token: str) -> bool:
    """Validate session token using constant-time comparison"""
    if 'token' not in session:
        return False
    stored_token = get_stored_session_token(session.get('user_id'))
    if not stored_token:
        return False
    return secrets.compare_digest(session_token, stored_token)


def get_current_timestamp():
    """Get current timestamp"""
    import time
    return int(time.time())


def store_session_token(user_id: int, token: str):
    """Store session token in database"""
    pass


def get_stored_session_token(user_id: int) -> str:
    """Retrieve session token from database"""
    pass
