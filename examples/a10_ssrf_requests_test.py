"""
Vulnerable examples of Server-Side Request Forgery (SSRF) using requests library.
These patterns should be detected by the A10 SSRF detector.
"""
import requests
import sys
import os


# Example 1: Direct user input via input()
def fetch_url_from_input():
    """Vulnerable: URL from input() passed directly to requests.get"""
    url = input("Enter URL: ")
    response = requests.get(url)
    return response.text


# Example 2: URL from command-line argument
def fetch_url_from_argv():
    """Vulnerable: URL from sys.argv passed to requests.post"""
    if len(sys.argv) > 1:
        url = sys.argv[1]
        response = requests.post(url, data={"key": "value"})
        return response.json()


# Example 3: URL from environment variable
def fetch_url_from_env():
    """Vulnerable: URL from os.environ passed to requests.put"""
    api_url = os.environ["API_URL"]
    response = requests.put(api_url, json={"data": "test"})
    return response.status_code


# Example 4: URL from os.getenv()
def fetch_url_from_getenv():
    """Vulnerable: URL from os.getenv() passed to requests.delete"""
    target = os.getenv("TARGET_URL")
    response = requests.delete(target)
    return response.status_code


# Example 5: String concatenation with user input
def fetch_with_concatenation():
    """Vulnerable: URL constructed by concatenating user input"""
    user_path = input("Enter path: ")
    url = "http://internal-api.local/" + user_path
    response = requests.get(url)
    return response.text


# Example 6: f-string with user input
def fetch_with_fstring():
    """Vulnerable: URL constructed using f-string with user input"""
    host = input("Enter hostname: ")
    url = f"http://{host}/api/data"
    response = requests.post(url)
    return response.content


# Example 7: .format() with user input
def fetch_with_format():
    """Vulnerable: URL constructed using .format() with user input"""
    endpoint = input("Enter endpoint: ")
    url = "http://internal.local/{}".format(endpoint)
    response = requests.patch(url)
    return response.status_code


# Example 8: Flask-style request handling (simulated)
def fetch_from_request_args(request):
    """Vulnerable: URL from Flask request.args"""
    url = request.args["url"]
    response = requests.get(url)
    return response.text


def fetch_from_request_form(request):
    """Vulnerable: URL from Flask request.form"""
    target = request.form["target"]
    response = requests.post(target)
    return response.status_code


def fetch_from_request_json(request):
    """Vulnerable: URL from Flask request.json"""
    data = request.json
    url = data["webhook_url"]
    response = requests.post(url, json={"event": "test"})
    return response.status_code


# Example 9: Using requests.request() generic method
def generic_request_method():
    """Vulnerable: Using requests.request() with user-controlled URL"""
    url = sys.argv[1]
    method = sys.argv[2]
    response = requests.request(method, url)
    return response.text


# Example 10: Multiple levels of taint propagation
def indirect_taint():
    """Vulnerable: User input assigned to variable, then used in URL"""
    user_input = input("Enter server: ")
    server = user_input
    api_url = f"http://{server}/status"
    response = requests.get(api_url)
    return response.text
