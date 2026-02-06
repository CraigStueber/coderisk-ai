"""
Test cases for OWASP A07 - Identification & Authentication Failures
This file contains various authentication anti-patterns that should be detected by CodeRisk AI.
"""

import os
import hashlib
from flask import Flask, request, session


# ==========================================
# AUTH.CUSTOM.PASSWORD_CHECK Test Cases
# ==========================================

# TC1: Direct password comparison in if statement (HIGH CONFIDENCE)
def login_user_v1(username, password):
    """Custom password check in login context - should be detected"""
    stored_password = get_stored_password(username)
    if password == stored_password:  # DETECT: Custom password check
        return True
    return False


# TC2: Manual password validation in authentication (MEDIUM-HIGH CONFIDENCE)
def authenticate_user_v2(username, password):
    """Manual password checks in auth flow - should be detected"""
    if len(password) < 8:  # DETECT: Custom password check
        return False
    if password.isdigit():  # DETECT: Custom password check
        return False
    return verify_credentials(username, password)


# TC3: Custom password logic with multiple checks (MEDIUM CONFIDENCE)
def check_user_password(user_input, stored_pwd):
    """Custom password validation logic - should be detected"""
    if user_input != stored_pwd:  # DETECT: Custom password check
        return False
    return True


# TC4: Manual password strength validation at signup (LOWER CONFIDENCE)
def validate_password_strength(password):
    """Password strength validation at signup - may be detected with lower confidence"""
    if len(password) < 12:  # DETECT: Custom password check (lower confidence)
        return False
    if not any(c.isupper() for c in password):  # DETECT: Custom password check
        return False
    return True


# TC5: Should NOT be detected - using established library
def login_with_bcrypt(username, password):
    """Proper authentication using bcrypt - should NOT be detected"""
    import bcrypt
    stored_hash = get_user_hash(username)
    return bcrypt.checkpw(password.encode(), stored_hash)


# TC6: Should NOT be detected - using passlib
def authenticate_with_passlib(username, password):
    """Proper authentication using passlib - should NOT be detected"""
    from passlib.hash import bcrypt
    stored_hash = get_user_hash(username)
    return bcrypt.verify(password, stored_hash)


# ==========================================
# AUTH.PLAINTEXT.PASSWORD_COMPARE Test Cases
# ==========================================

# TC7: Hardcoded password comparison (VERY HIGH CONFIDENCE)
def admin_login_v1(username, password):
    """Plaintext comparison with hardcoded password - should be detected"""
    if username == "admin" and password == "admin123":  # DETECT: Plaintext password compare
        return True
    return False


# TC8: Password variable comparison (HIGH CONFIDENCE)
def verify_user_v1(user, input_password):
    """Direct plaintext password comparison - should be detected"""
    if input_password == user.password:  # DETECT: Plaintext password compare
        session['user_id'] = user.id
        return True
    return False


# TC9: Environment variable password comparison (HIGH CONFIDENCE)
def api_auth_v1(api_key):
    """Plaintext comparison with env variable - should be detected"""
    if api_key == os.getenv("API_PASSWORD"):  # DETECT: Plaintext password compare
        return True
    return False


# TC10: Configuration password comparison (HIGH CONFIDENCE)
def authenticate_v2(password, config):
    """Plaintext comparison with config value - should be detected"""
    if password == config["admin_password"]:  # DETECT: Plaintext password compare
        return True
    return False


# TC11: Multiple plaintext comparisons (HIGH CONFIDENCE)
class AuthManager:
    def __init__(self):
        self.admin_pwd = "super_secret_123"
    
    def check_admin(self, pwd):
        """Plaintext comparison with stored attribute - should be detected"""
        if pwd == self.admin_pwd:  # DETECT: Plaintext password compare
            return True
        return False


# TC12: Form password comparison (HIGH CONFIDENCE)
@app.route('/login', methods=['POST'])
def login_endpoint():
    """Web endpoint with plaintext password comparison - should be detected"""
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    if user and password == user.passwd:  # DETECT: Plaintext password compare
        session['logged_in'] = True
        return "Login successful"
    return "Login failed"


# TC13: Negated password comparison (HIGH CONFIDENCE)
def check_password_mismatch(input_pwd, stored_pwd):
    """Plaintext password comparison with != operator - should be detected"""
    if input_pwd != stored_pwd:  # DETECT: Plaintext password compare
        return False
    return True


# TC14: Secret comparison (HIGH CONFIDENCE)
def verify_secret_key(provided_secret):
    """Plaintext secret comparison - should be detected"""
    MASTER_SECRET = "my-secret-key-12345"  # Also a hardcoded secret
    if provided_secret == MASTER_SECRET:  # DETECT: Plaintext password compare
        return True
    return False


# TC15: API key comparison (HIGH CONFIDENCE)
def validate_api_key(request_key):
    """Plaintext API key comparison - should be detected"""
    if request_key == os.environ["API_SECRET"]:  # DETECT: Plaintext password compare
        return True
    return False


# ==========================================
# NEGATIVE TEST CASES (Should NOT Detect)
# ==========================================

# TC16: Should NOT be detected - proper hashing
def secure_login_v1(username, password):
    """Secure authentication with hashing - should NOT be detected"""
    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    stored_hash = get_user_hash(username)
    return password_hash == stored_hash  # Comparing hashes, not plaintext


# TC17: Should NOT be detected - using Django auth
def django_login(request, username, password):
    """Django authentication - should NOT be detected"""
    from django.contrib.auth import authenticate
    user = authenticate(username=username, password=password)
    return user is not None


# TC18: Should NOT be detected - non-password comparison
def check_user_status(user):
    """Non-password comparison - should NOT be detected"""
    if user.status == "active":
        return True
    return False


# TC19: Should NOT be detected - password in comment
def some_function():
    """Function with password in comment - should NOT be detected"""
    # TODO: Don't hardcode password like: if password == "admin"
    # This is just a comment, not actual code
    return True


# ==========================================
# EDGE CASES
# ==========================================

# TC20: Multiple issues in one function
def bad_auth_multiple_issues(username, password):
    """Function with multiple authentication issues - should detect multiple"""
    # Custom check
    if len(password) < 6:  # DETECT: Custom password check
        return False
    
    # Plaintext comparison
    if password == "default123":  # DETECT: Plaintext password compare
        return True
    
    # Another plaintext comparison
    stored = get_password(username)
    if password == stored:  # DETECT: Plaintext password compare (or custom check)
        return True
    
    return False


# TC21: Complex authentication logic
def complex_auth(username, password, token):
    """Complex authentication with multiple checks"""
    # This should be detected as custom password check
    if not password or len(password) < 8:  # DETECT: Custom password check
        return False
    
    user = find_user(username)
    if not user:
        return False
    
    # This should be detected as plaintext comparison
    if password != user.password_hash:  # DETECT: Plaintext password compare (misleading name)
        return False
    
    return True


# TC22: Credential comparison in authorization
def check_api_authorization(request):
    """API authorization with plaintext comparison"""
    auth_header = request.headers.get('Authorization')
    # Should detect plaintext comparison
    if auth_header == os.getenv('API_SECRET_KEY'):  # DETECT: Plaintext password compare
        return True
    return False


# Helper functions (for context)
def get_stored_password(username):
    return "dummy"

def get_user_hash(username):
    return b"dummy"

def verify_credentials(username, password):
    return True

def get_password(username):
    return "dummy"

def find_user(username):
    class User:
        password_hash = "dummy"
    return User()

class User:
    password = "dummy"
    passwd = "dummy"
    id = 1

app = Flask(__name__)
