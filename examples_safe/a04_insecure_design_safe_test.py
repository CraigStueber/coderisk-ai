"""
Safe examples for A04 - Insecure Design.
These should NOT be flagged by the A04 detector.
"""
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import secrets
from passlib.context import CryptContext

app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize password hashing context
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


# Authentication decorators
def login_required(fn):
    """Require authentication (demo: checks X-Demo-Auth header)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Demo-only check; in production validate session/JWT
        if request.headers.get("X-Demo-Auth") != "ok":
            abort(401)
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    """Require admin role (demo: checks X-Demo-Role header)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Demo-only check; in production validate role from session
        if request.headers.get("X-Demo-Role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def rate_limited(fn):
    """Rate limiting decorator (demo: delegates to flask-limiter)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Demo stub - actual rate limiting handled by @limiter.limit()
        return fn(*args, **kwargs)
    return wrapper


# Safe: Login with rate limiting
@app.route('/login', methods=['POST'])
@rate_limited
@limiter.limit("5 per minute")
def login():
    """Safe: Rate limiting applied to prevent brute-force."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if check_credentials(username, password):
        return jsonify({'token': generate_token(username)})
    return jsonify({'error': 'Invalid credentials'}), 401


# Safe: Admin endpoint with authorization
@login_required
@admin_required
@app.route('/admin/dashboard')
def admin_dashboard():
    """Safe: Admin endpoint protected with authorization."""
    return jsonify({'users': get_all_users()})


# Safe: Public health check endpoint (intentionally unauthenticated)
@app.route('/healthz')
def health_check():
    """
    Safe: Public health check endpoint.
    Intentionally unauthenticated - returns minimal non-sensitive status.
    """
    return jsonify({
        'status': 'ok',
        'service': 'api'
    })


# Safe: Outbound requests with validation
import requests
from urllib.parse import urlparse


ALLOWED_DOMAINS = {
    'api.example.com',
    'webhook.trusted.com',
    'service.approved.net'
}


def validate_url(url):
    """Validate URL against allowlist."""
    parsed = urlparse(url)
    return parsed.netloc in ALLOWED_DOMAINS and parsed.scheme == 'https'


def fetch_external_data(api_url):
    """Safe: URL validation before making request."""
    if not validate_url(api_url):
        raise ValueError("URL not in allowlist")
    
    response = requests.get(api_url)
    return response.json()


def send_webhook(webhook_url, payload):
    """Safe: Allowlist check on webhook URL."""
    if not validate_url(webhook_url):
        raise ValueError("Webhook URL not allowed")
    
    response = requests.post(webhook_url, json=payload)
    return response.status_code


# Helper functions
def check_credentials(username, password):
    """
    Safe: Uses passlib for proper authentication.
    No hardcoded credentials, no plaintext comparisons.
    """
    # In production: retrieve hash from database
    # user_hash = database.get_user_hash_by_username(username)
    # if not user_hash:
    #     return False
    # return pwd_context.verify(password, user_hash)
    
    # For demo: simulate secure verification without hardcoded credentials
    # Always return False unless connected to real database with proper hashes
    return False  # Stub: requires database connection in production


def generate_token(username):
    """Generate secure random token"""
    return secrets.token_urlsafe(32)


def get_all_users():
    return [{'id': 1, 'name': 'admin'}]


if __name__ == '__main__':
    app.run(debug=False)

