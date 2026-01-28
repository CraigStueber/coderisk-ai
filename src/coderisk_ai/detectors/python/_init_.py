from .broken_access_control import detect_broken_access_control
from .cryptographic_failures import detect_cryptographic_failures
from .sql_injection import detect_sql_injection
from .unsafe_deserialization import detect_unsafe_deserialization
from .security_misconfiguration import detect_security_misconfiguration

__all__ = [
    "detect_broken_access_control",
    "detect_cryptographic_failures",
    "detect_sql_injection",
    "detect_unsafe_deserialization",
    "detect_security_misconfiguration",
]
