from .sql_injection import detect_sql_injection
from .unsafe_deserialization import detect_unsafe_deserialization

__all__ = [
    "detect_sql_injection",
    "detect_unsafe_deserialization",
]
