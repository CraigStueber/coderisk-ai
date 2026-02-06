"""
Real-world authentication failure examples
These patterns are commonly seen in AI-generated code.
"""

# Example 1: Simple admin panel with hardcoded credentials
def admin_login(username, password):
    """Typical AI-generated admin login"""
    if username == "admin" and password == "admin123":
        return True
    return False


# Example 2: Custom password validation (common AI pattern)
def verify_user(username, password):
    """AI often generates custom password checking"""
    stored_pass = get_user_password(username)
    if password == stored_pass:
        return True
    return False


# Example 3: Password strength validation in auth flow
def authenticate_user(username, password):
    """AI mixes validation with authentication"""
    if len(password) < 8:
        return False
    if password.isdigit():
        return False
    # ... continues with custom auth logic
    return check_credentials(username, password)


# Example 4: Environment variable password comparison
import os

def api_authenticate(api_key):
    """Common pattern in AI-generated API auth"""
    if api_key == os.getenv("API_SECRET"):
        return True
    return False


# Example 5: Config-based authentication
def config_auth(password, config):
    """AI-generated config-based auth"""
    if password == config.get("admin_password"):
        return True
    return False


# Helper functions
def get_user_password(username):
    return "dummy"

def check_credentials(username, password):
    return True
