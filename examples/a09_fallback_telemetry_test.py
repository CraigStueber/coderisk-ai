"""
Test cases for A09 fallback-without-telemetry detection.
Demonstrates distinction between silent swallows and intentional fallback patterns.
"""

import requests
from typing import Optional


# ==========================================
# SILENT SWALLOW (High Severity)
# ==========================================

def truly_silent_swallow():
    """
    Truly silent exception - no action, no logging.
    Should be detected as A09.EXCEPT.EMPTY_PASS or A09.EXCEPT.SWALLOWED.
    """
    try:
        critical_operation()
    except Exception:
        pass  # A09.EXCEPT.EMPTY_PASS - silent swallow


def silent_return():
    """
    Silent return without logging.
    Should be A09.EXCEPT.EMPTY_PASS.
    """
    try:
        process_payment()
    except Exception:
        return  # A09.EXCEPT.EMPTY_PASS - silent swallow


def silent_continue():
    """
    Silent continue in loop.
    Should be A09.EXCEPT.EMPTY_PASS.
    """
    for item in items:
        try:
            process_item(item)
        except Exception:
            continue  # A09.EXCEPT.EMPTY_PASS - silent swallow


def silent_with_cleanup():
    """
    Silent swallow with cleanup but no logging.
    Should be A09.EXCEPT.SWALLOWED.
    """
    try:
        risky_operation()
    except Exception:
        cleanup_resources()  # A09.EXCEPT.SWALLOWED - logic but no logging
        return None


# ==========================================
# FALLBACK WITHOUT TELEMETRY (Medium Severity)
# ==========================================

def fallback_to_backup_service(user_id: int):
    """
    Fallback to backup service without logging.
    Should be A09.EXCEPT.FALLBACK_NO_TELEMETRY.
    """
    try:
        result = primary_api.get_user(user_id)
    except Exception:
        # A09.EXCEPT.FALLBACK_NO_TELEMETRY - intentional fallback, but no telemetry
        result = backup_api.get_user(user_id)
    return result


def cache_fallback_no_logging(key: str):
    """
    Cache fallback without telemetry.
    Should be A09.EXCEPT.FALLBACK_NO_TELEMETRY.
    """
    try:
        data = redis_cache.get(key)
    except Exception:
        # A09.EXCEPT.FALLBACK_NO_TELEMETRY - cache fallback, no logging
        data = get_default_cache_value(key)
    return data


def retry_with_alternative(endpoint: str):
    """
    Retry with alternative endpoint without logging.
    Should be A09.EXCEPT.FALLBACK_NO_TELEMETRY.
    """
    try:
        response = requests.get(f"https://primary.example.com{endpoint}")
    except RequestException:
        # A09.EXCEPT.FALLBACK_NO_TELEMETRY - backup/retry pattern
        response = requests.get(f"https://backup.example.com{endpoint}")
    return response


def optional_feature_fallback(user_id: int):
    """
    Optional feature with default fallback.
    Should be A09.EXCEPT.FALLBACK_NO_TELEMETRY.
    """
    try:
        recommendations = ml_service.get_recommendations(user_id)
    except Exception:
        # A09.EXCEPT.FALLBACK_NO_TELEMETRY - optional feature, default fallback
        recommendations = get_default_recommendations()
    return recommendations


def secondary_service_fallback(data: dict):
    """
    Secondary service as fallback.
    Should be A09.EXCEPT.FALLBACK_NO_TELEMETRY.
    """
    try:
        result = external_api.process(data)
    except Exception:
        # A09.EXCEPT.FALLBACK_NO_TELEMETRY - secondary service
        result = secondary_processor.process(data)
    return result


# ==========================================
# PROPER HANDLING (No Detection)
# ==========================================

def fallback_with_logging():
    """
    Fallback WITH logging - should NOT be flagged.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        result = primary_api.fetch_data()
    except Exception as e:
        logger.warning(f"Primary API failed, using backup: {e}")  # Has logging!
        result = backup_api.fetch_data()
    return result


def fallback_with_metrics():
    """
    Fallback with metrics - should NOT be flagged.
    """
    try:
        data = cache.get('key')
    except CacheError:
        metrics.increment('cache.miss')  # Has telemetry!
        data = fetch_from_db()
    return data


def proper_logging_and_rethrow():
    """
    Proper logging with re-raise - should NOT be flagged.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        critical_operation()
    except Exception as e:
        logger.exception("Critical operation failed")
        raise  # Re-raises


# ==========================================
# MIXED CASES
# ==========================================

def best_effort_no_logging():
    """
    Best-effort operation without logging.
    Should still be flagged but with context awareness.
    """
    try:
        # Best effort: send telemetry to analytics
        analytics.track_event('user_action')
    except Exception:
        # A09.EXCEPT - but may be lower severity due to best-effort context
        pass  # Expected to fail if analytics is down


def cache_miss_silent():
    """
    Cache miss handled silently.
    May be flagged as fallback-without-telemetry.
    """
    try:
        value = cache.get('expensive_key')
    except TimeoutError:
        # A09.EXCEPT - cache timeout, returning default
        value = None
    return value


# Stubs
def critical_operation():
    pass

def process_payment():
    pass

def process_item(item):
    pass

def cleanup_resources():
    pass

def risky_operation():
    pass

def get_default_cache_value(key):
    return {}

def get_default_recommendations():
    return []

class primary_api:
    @staticmethod
    def get_user(user_id):
        pass
    
    @staticmethod
    def fetch_data():
        pass

class backup_api:
    @staticmethod
    def get_user(user_id):
        pass
    
    @staticmethod
    def fetch_data():
        pass

class redis_cache:
    @staticmethod
    def get(key):
        pass

class ml_service:
    @staticmethod
    def get_recommendations(user_id):
        pass

class external_api:
    @staticmethod
    def process(data):
        pass

class secondary_processor:
    @staticmethod
    def process(data):
        pass

class RequestException(Exception):
    pass

items = []
