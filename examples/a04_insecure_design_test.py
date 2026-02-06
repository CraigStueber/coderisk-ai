"""
Examples demonstrating OWASP A04 - Insecure Design patterns.
These should be detected by the A04 detector with lower confidence (heuristic-based).
"""
from flask import Flask, request, jsonify

app = Flask(__name__)


# A04.1: Missing brute-force protection on login handler
@app.route('/login', methods=['POST'])
def login():
    """Vulnerable: No rate limiting on authentication endpoint."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Check credentials (simplified)
    if username == 'admin' and password == 'secret':
        return jsonify({'token': 'abc123'})
    return jsonify({'error': 'Invalid credentials'}), 401


# Another login example
@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    """Vulnerable: No throttling or rate limit."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Authenticate user
    if check_credentials(username, password):
        return jsonify({'success': True})
    return jsonify({'success': False}), 401


# A04.2: Insecure admin endpoint without authorization
@app.route('/admin/dashboard')
def admin_dashboard():
    """Vulnerable: Admin endpoint without authorization check."""
    return jsonify({'users': get_all_users()})


@app.route('/debug/status')
def debug_status():
    """Vulnerable: Debug endpoint exposed without checks."""
    return jsonify({
        'database': 'connected',
        'cache': 'redis',
        'env': 'production'
    })


# A04.3: Missing outbound request guardrails
import requests


def fetch_external_data(api_url):
    """Vulnerable: No URL validation or allowlist."""
    response = requests.get(api_url)
    return response.json()


def send_webhook(webhook_url, payload):
    """Vulnerable: No validation on outbound requests."""
    response = requests.post(webhook_url, json=payload)
    return response.status_code


def sync_to_external_service(service_url, data):
    """Vulnerable: Multiple outbound requests without validation."""
    headers_response = requests.get(f"{service_url}/headers")
    post_response = requests.post(f"{service_url}/data", json=data)
    return post_response.status_code


# Helper functions (stubs)
def check_credentials(username, password):
    return username == 'admin' and password == 'secret'


def get_all_users():
    return [{'id': 1, 'name': 'admin'}]


if __name__ == '__main__':
    app.run(debug=True)
