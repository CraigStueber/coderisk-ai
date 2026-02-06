"""
Example file demonstrating A09 - Security Logging and Monitoring Failures
This file contains patterns that the A09 detector should flag.
"""

# Mock definitions to avoid undefined variable warnings
class AuthenticationError(Exception):
    pass

class JWTError(Exception):
    pass

class DatabaseError(Exception):
    pass

class CacheError(Exception):
    pass

class RequestException(Exception):
    pass

class DecryptionError(Exception):
    pass

class MockAuthService:
    def login(self, username, password):
        pass

class MockDatabase:
    def query(self, user_id):
        pass
    
    def execute(self, query):
        pass

class MockCache:
    def set(self, key, value):
        pass

class MockJWT:
    def decode(self, token, secret_key):
        pass

class MockCrypto:
    def decrypt(self, encrypted):
        pass

class MockRequests:
    def get(self, endpoint):
        pass

class MockLogger:
    def error(self, message):
        pass

# Mock instances and functions
auth_service = MockAuthService()
database = MockDatabase()
cache = MockCache()
jwt = MockJWT()
crypto = MockCrypto()
requests = MockRequests()
logger = MockLogger()
secret_key = "mock_secret_key"
items = []
key = "mock_key"
value = "mock_value"
user_id = 123  # Mock user ID

def charge_credit_card(amount):
    pass

def process(item):
    pass

def step1():
    pass

def step2():
    pass

def step3():
    pass

def risky_operation():
    pass

def api_call():
    pass


# Example 1: Empty exception handler with pass (A09.EXCEPT.EMPTY_PASS)
def process_payment(amount):
    try:
        charge_credit_card(amount)
    except Exception:
        pass  # Silent failure - no logging!


# Example 2: Empty exception handler with ellipsis (A09.EXCEPT.EMPTY_PASS)
def authenticate_user(username, password):
    try:
        return auth_service.login(username, password)
    except AuthenticationError:
        ...  # Silent failure


# Example 3: Empty exception handler with just return (A09.EXCEPT.EMPTY_PASS)
def get_user_data(user_id):
    try:
        return database.query(user_id)
    except:
        return


# Example 4: Empty exception handler with continue (A09.EXCEPT.EMPTY_PASS)
def process_batch():
    for item in items:
        try:
            process(item)
        except ValueError:
            continue  # Silently skip errors


# Example 5: Swallowed exception - has logic but no logging (A09.EXCEPT.SWALLOWED)
def fetch_api_data(endpoint):
    try:
        response = requests.get(endpoint)
        return response.json()
    except RequestException:
        # No logging - just return default
        return {"status": "error"}


# Example 6: Swallowed exception in security-sensitive context (A09.EXCEPT.SWALLOWED)
def validate_token(token):
    try:
        decoded = jwt.decode(token, secret_key)
        return decoded
    except JWTError:
        # Security-critical but no logging!
        return None


# Example 7: Swallowed exception with business logic (A09.EXCEPT.SWALLOWED)
def execute_db_query(query):
    try:
        result = database.execute(query)
        return result
    except DatabaseError:
        # Sets flag but doesn't log the error
        retry_flag = True
        return []


# Example 8: Multiple empty handlers (A09.EXCEPT.EMPTY_PASS)
def complex_operation():
    try:
        step1()
    except TypeError:
        pass
    
    try:
        step2()
    except ValueError:
        ...
    
    try:
        step3()
    except:
        return


# Example 9: Swallowed exception with intentional comment (A09.EXCEPT.SWALLOWED)
# Should still be flagged but with lower confidence
def optional_cache_update():
    try:
        cache.set(key, value)
    except CacheError:
        # Best effort - cache is optional
        cached = False


# Example 10: Good exception handling (should NOT be flagged)
def proper_error_handling():
    try:
        risky_operation()
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        raise


# Example 11: Good exception handling with logging (should NOT be flagged)
def proper_logging():
    try:
        api_call()
    except RequestException as e:
        print(f"API call failed: {e}")
        return None


# Example 12: Empty handler in crypto context (A09.EXCEPT.EMPTY_PASS)
def decrypt_data(encrypted):
    try:
        return crypto.decrypt(encrypted)
    except DecryptionError:
        pass  # Security-critical silent failure!


# Example 13: Best-effort with telemetry (should have reduced/no finding)
def update_cache_with_logging():
    try:
        cache.set(key, value)
    except CacheError as e:
        # Cache is optional/best-effort
        logger.warning(f"Cache update failed: {e}")
        cached = False


# Example 14: Security-critical JWT swallow (should escalate severity)
def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, secret_key)
        return payload
    except JWTError:
        # No logging - security-critical swallow!
        return {"error": "invalid"}


# Example 15: Best-effort without telemetry (reduced severity but still flagged)
def prefetch_optional_data():
    try:
        data = api_call()
    except RequestException:
        # Best effort - this is optional
        data = None


# Example 16: Security-critical authorization swallow
def check_user_permissions(user_id, resource):
    try:
        perms = database.query(f"SELECT * FROM permissions WHERE user_id={user_id}")
        return perms
    except DatabaseError:
        # Authorization check failed but no logging!
        return []


# Example 17: Cache with "key" term - should NOT escalate (generic cache context)
def update_cache_key():
    try:
        cache_key = f"user_{user_id}"
        cache.set(cache_key, value)
    except CacheError:
        # Cache key update - optional
        return None


# Example 18: Private key context - SHOULD escalate (security-critical)
def load_private_key():
    try:
        private_key = open("private.key").read()
        return private_key
    except IOError:
        # Private key loading failed - no logging!
        return None
