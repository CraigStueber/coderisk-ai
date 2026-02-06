from .a01_broken_access_control import detect_broken_access_control
from .a02_cryptographic_failures import detect_cryptographic_failures
from .a03_sql_injection import detect_sql_injection
from .a08_unsafe_deserialization import detect_unsafe_deserialization
from .a05_security_misconfiguration import detect_security_misconfiguration
from .a07_identification_authentication_failures import detect_identification_authentication_failures
from .a06_vulnerable_outdated_components import detect_vulnerable_outdated_components
from .a09_security_logging_monitoring_failures import detect_security_logging_monitoring_failures
from .a10_ssrf import detect_ssrf
from .a04_insecure_design import detect_insecure_design

__all__ = [
    "detect_broken_access_control",
    "detect_cryptographic_failures",
    "detect_sql_injection",
    "detect_unsafe_deserialization",
    "detect_security_misconfiguration",
    "detect_identification_authentication_failures",
    "detect_vulnerable_outdated_components",
    "detect_security_logging_monitoring_failures",
    "detect_ssrf",
    "detect_insecure_design",
]
