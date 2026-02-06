"""
Safe examples for SSRF - using constant URLs and proper validation.
These should NOT be flagged by the A10 SSRF detector.
"""
import logging
import requests
import urllib.request
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Safe Example 1: Constant URL (no user input)
def fetch_constant_url():
    """Safe: URL is a hardcoded constant"""
    response = requests.get("https://api.example.com/status")
    return response.json()


# Safe Example 2: Multiple hardcoded URLs
def fetch_multiple_constants():
    """Safe: All URLs are constants"""
    urls = [
        "https://api.github.com/status",
        "https://httpbin.org/get",
        "https://jsonplaceholder.typicode.com/posts/1"
    ]
    results = []
    for url in urls:
        response = requests.get(url)
        results.append(response.status_code)
    return results


# Safe Example 3: Allowlist validation
def fetch_with_allowlist(user_domain):
    """Safe: Domain is validated against an allowlist"""
    allowed_domains = {
        "api.example.com",
        "api.trusted.com",
        "webhook.approved.net"
    }
    
    parsed = urlparse(f"https://{user_domain}")
    if parsed.netloc in allowed_domains:
        url = f"https://{parsed.netloc}/api/data"
        response = requests.get(url)
        return response.json()
    else:
        raise ValueError("Domain not in allowlist")


# Safe Example 4: Scheme restriction
def fetch_with_scheme_check(url):
    """Safe: Only allow HTTPS scheme"""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are allowed")
    
    # Additional validation could go here
    allowed_hosts = ["api.example.com", "secure.api.com"]
    if parsed.netloc not in allowed_hosts:
        raise ValueError("Host not allowed")
    
    response = requests.get(url)
    return response.content


# Safe Example 5: Using urllib with constant URL
def fetch_urllib_constant():
    """Safe: urllib with hardcoded URL"""
    response = urllib.request.urlopen("https://www.example.com/api/v1/status")
    return response.read()


# Safe Example 6: Building URL from validated enum-like values
def fetch_from_enum(service_name):
    """Safe: Service name mapped to predefined URLs"""
    service_urls = {
        "users": "https://api.internal.com/users",
        "products": "https://api.internal.com/products",
        "orders": "https://api.internal.com/orders"
    }
    
    if service_name not in service_urls:
        raise ValueError("Invalid service name")
    
    url = service_urls[service_name]
    response = requests.get(url)
    return response.json()


# Safe Example 7: Constant base with safe path construction
def fetch_with_safe_path(resource_id):
    """Safe: Base URL is constant, only ID is variable and validated"""
    # Validate resource_id is numeric
    if not isinstance(resource_id, int) or resource_id < 0:
        raise ValueError("Invalid resource ID")
    
    base_url = "https://api.example.com/resources"
    url = f"{base_url}/{resource_id}"
    response = requests.get(url)
    return response.json()


# Safe Example 8: Using configuration file for URLs
def fetch_from_config(config):
    """Safe: URLs come from configuration, not user input"""
    api_url = config.get("api_endpoint", "https://default.api.com")
    response = requests.get(api_url)
    return response.status_code


# Safe Example 9: Proxy-based approach
def fetch_via_proxy(endpoint):
    """Safe: All requests go through a controlled proxy"""
    # Only allow predefined endpoints
    valid_endpoints = ["/users", "/products", "/status"]
    if endpoint not in valid_endpoints:
        raise ValueError("Invalid endpoint")
    
    # Use fixed internal proxy
    proxy_url = "http://internal-proxy.local:8080"
    full_url = f"{proxy_url}{endpoint}"
    response = requests.get(full_url)
    return response.json()


# Safe Example 10: Indirect constant usage
def fetch_indirect_constant():
    """Safe: Variable holds constant URL"""
    api_endpoint = "https://api.example.com/health"
    backup_endpoint = "https://backup-api.example.com/health"
    
    try:
        response = requests.get(api_endpoint)
        return response.json()
    except Exception:
        logger.warning("Primary endpoint failed; using backup", exc_info=True)
        response = requests.get(backup_endpoint, timeout=5)
        return response.json()


# Safe Example 11: Local file URL
def read_local_file():
    """Safe: Reading from local file system with constant path"""
    response = urllib.request.urlopen("file:///etc/hosts")
    return response.read()
