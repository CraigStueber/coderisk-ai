"""
Vulnerable examples of Server-Side Request Forgery (SSRF) using urllib library.
These patterns should be detected by the A10 SSRF detector.
"""
import urllib.request
import sys
import os


# Example 1: Direct user input via input()
def fetch_url_input():
    """Vulnerable: URL from input() passed to urllib.request.urlopen"""
    url = input("Enter URL to fetch: ")
    response = urllib.request.urlopen(url)
    return response.read()


# Example 2: URL from command-line argument
def fetch_url_argv():
    """Vulnerable: URL from sys.argv passed to urlopen"""
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        response = urllib.request.urlopen(target_url)
        return response.read().decode('utf-8')


# Example 3: URL from environment variable
def fetch_url_env():
    """Vulnerable: URL from os.environ passed to urlopen"""
    api_endpoint = os.environ["EXTERNAL_API"]
    response = urllib.request.urlopen(api_endpoint)
    return response.getcode()


# Example 4: URL from os.getenv()
def fetch_url_getenv():
    """Vulnerable: URL from os.getenv() passed to urlopen"""
    webhook = os.getenv("WEBHOOK_URL")
    response = urllib.request.urlopen(webhook)
    return response.info()


# Example 5: String concatenation with user input
def fetch_concatenated():
    """Vulnerable: URL built by concatenating user input"""
    path = input("Enter path: ")
    url = "http://192.168.1.100/" + path
    response = urllib.request.urlopen(url)
    return response.read()


# Example 6: f-string with user input
def fetch_fstring():
    """Vulnerable: URL built using f-string with user input"""
    resource = input("Enter resource ID: ")
    url = f"http://internal-service/{resource}"
    response = urllib.request.urlopen(url)
    return response.read()


# Example 7: .format() with user input
def fetch_format():
    """Vulnerable: URL built using .format() with user input"""
    query = input("Enter query: ")
    url = "http://api.internal/search?q={}".format(query)
    response = urllib.request.urlopen(url)
    return response.read()


# Example 8: With Request object (still vulnerable)
def fetch_with_request_object():
    """Vulnerable: Creating Request object with tainted URL"""
    url = sys.argv[1]
    req = urllib.request.Request(url)
    response = urllib.request.urlopen(req)
    return response.read()


# Example 9: Multiple assignments (taint propagation)
def fetch_indirect():
    """Vulnerable: User input propagated through variable assignment"""
    user_url = input("URL: ")
    target = user_url
    final_url = target
    response = urllib.request.urlopen(final_url)
    return response.read()


# Example 10: Building URL with multiple tainted parts
def fetch_complex():
    """Vulnerable: URL built from multiple user inputs"""
    host = input("Host: ")
    port = input("Port: ")
    path = input("Path: ")
    url = f"http://{host}:{port}/{path}"
    response = urllib.request.urlopen(url)
    return response.read()
