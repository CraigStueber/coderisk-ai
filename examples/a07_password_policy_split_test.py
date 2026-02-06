"""
Test cases for A07 password policy vs custom auth verification split.
Demonstrates the distinction between password strength validation and custom authentication.
"""

# ==========================================
# PASSWORD POLICY CHECKS (Low/Info Severity)
# ==========================================

def register_user(username: str, password: str) -> tuple[bool, str]:
    """
    Registration context: Password policy checks should be detected with LOW severity.
    These are legitimate password strength validations at signup.
    """
    # AUTH.PASSWORD_POLICY.CHECK - info/low severity
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    
    # AUTH.PASSWORD_POLICY.CHECK - info/low severity
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letters"
    
    # AUTH.PASSWORD_POLICY.CHECK - info/low severity
    if not any(c.isdigit() for c in password):
        return False, "Password must contain numbers"
    
    # This is fine - policy checks at signup, paired with proper hashing
    # In production: store argon2.hash(password) or bcrypt.hashpw(password)
    return True, "Password meets policy"


def validate_password_strength(password: str) -> bool:
    """
    Password strength validation - should detect AUTH.PASSWORD_POLICY.CHECK.
    """
    # AUTH.PASSWORD_POLICY.CHECK - info/low severity
    if len(password) < 8:
        return False
    
    # AUTH.PASSWORD_POLICY.CHECK - info/low severity
    if not any(c.islower() for c in password):
        return False
    
    return True


def create_account(username: str, password: str, email: str):
    """
    Account creation context with password policy validation.
    """
    # AUTH.PASSWORD_POLICY.CHECK - info/low severity
    if len(password) < 10:
        raise ValueError("Password too short for account creation")
    
    # AUTH.PASSWORD_POLICY.CHECK - info/low severity
    has_special = any(c in "!@#$%^&*" for c in password)
    if not has_special:
        raise ValueError("Password must contain special characters")
    
    # In production: store with proper hashing
    # store_user(username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()))


# ==========================================
# CUSTOM AUTH VERIFICATION (Medium/High Severity)
# ==========================================

def login_user_v1(username: str, password: str) -> bool:
    """
    Custom authentication logic - should detect AUTH.CUSTOM.AUTH_VERIFICATION.
    This is risky custom auth, not just policy validation.
    """
    stored_password = get_user_password(username)  # Indicates auth context
    
    # AUTH.CUSTOM.AUTH_VERIFICATION - medium/high severity
    if password == stored_password:
        return True
    return False


def authenticate_user_v2(username: str, password: str) -> bool:
    """
    Custom password verification in authentication context.
    """
    user = get_user_from_db(username)
    
    # AUTH.CUSTOM.AUTH_VERIFICATION - medium/high severity
    # Manual password validation in auth context with stored credentials
    if len(password) < 8:
        return False
    
    # AUTH.CUSTOM.AUTH_VERIFICATION - medium/high severity
    if password != user.password:
        return False
    
    return True


def verify_credentials(username: str, password: str) -> bool:
    """
    Custom verification logic with stored credentials.
    """
    # Get stored password (indicates auth verification, not policy)
    stored_pwd = fetch_password_from_config(username)
    
    # AUTH.CUSTOM.AUTH_VERIFICATION - medium/high severity
    if password == stored_pwd:
        return True
    return False


def check_user_auth(username: str, password: str):
    """
    Authentication function with custom password checks.
    """
    user_data = query_user_table(username)
    
    # AUTH.CUSTOM.AUTH_VERIFICATION - medium/high severity
    # Manual validation in auth context
    if len(password) > 0 and password == user_data['pwd']:
        return True
    return False


# ==========================================
# AMBIGUOUS CASES
# ==========================================

def validate_password_input(password: str) -> bool:
    """
    No clear context - likely treated as policy check due to lack of auth indicators.
    """
    # Likely AUTH.PASSWORD_POLICY.CHECK - no auth context or stored credentials
    if len(password) < 6:
        return False
    
    # Likely AUTH.PASSWORD_POLICY.CHECK
    if password.isdigit():
        return False
    
    return True


# Helper functions (stubs)
def get_user_password(username: str) -> str:
    pass

def get_user_from_db(username: str):
    class User:
        password = "stored_password"
    return User()

def fetch_password_from_config(username: str) -> str:
    pass

def query_user_table(username: str) -> dict:
    return {'pwd': 'stored_pwd'}
