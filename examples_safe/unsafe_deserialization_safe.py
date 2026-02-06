"""
Safe version - Unsafe Deserialization Fixed
This file demonstrates safe deserialization practices.
"""
import json
from typing import Any, Dict, List
from dataclasses import dataclass, asdict
import yaml


# SAFE: Use JSON for untrusted data
def load_profile_safe(json_str: str) -> Dict[str, Any]:
    """Safely load profile data from JSON string"""
    try:
        data = json.loads(json_str)
        return data
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON data: {e}")


def save_profile_safe(profile: Dict[str, Any]) -> str:
    """Safely serialize profile data to JSON"""
    return json.dumps(profile, indent=2)


# SAFE: Use dataclasses with JSON for structured data
@dataclass
class UserProfile:
    """User profile data structure"""
    user_id: int
    username: str
    email: str
    preferences: Dict[str, Any]


def load_user_profile_safe(json_str: str) -> UserProfile:
    """Safely load user profile from JSON"""
    try:
        data = json.loads(json_str)
        return UserProfile(
            user_id=data['user_id'],
            username=data['username'],
            email=data['email'],
            preferences=data.get('preferences', {})
        )
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise ValueError(f"Invalid user profile data: {e}")


def save_user_profile_safe(profile: UserProfile) -> str:
    """Safely serialize user profile to JSON"""
    return json.dumps(asdict(profile), indent=2)


# SAFE: Use yaml.safe_load() instead of yaml.load()
def load_config_safe(yaml_str: str) -> Dict[str, Any]:
    """Safely load configuration from YAML"""
    try:
        data = yaml.safe_load(yaml_str)
        return data
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML data: {e}")


def load_config_from_file_safe(filepath: str) -> Dict[str, Any]:
    """Safely load configuration from YAML file"""
    try:
        with open(filepath, 'r') as f:
            return yaml.safe_load(f)
    except (yaml.YAMLError, IOError) as e:
        raise ValueError(f"Failed to load config: {e}")


# SAFE: Custom safe deserialization with validation
class SafeDataLoader:
    """
    Safe data loader with schema validation.
    Only accepts expected data types and structures.
    """
    
    ALLOWED_TYPES = (int, float, str, bool, list, dict, type(None))
    
    @classmethod
    def validate_data(cls, data: Any, max_depth: int = 10) -> bool:
        """Validate that data contains only safe types"""
        if max_depth <= 0:
            raise ValueError("Data structure too deeply nested")
        
        if isinstance(data, cls.ALLOWED_TYPES[:5]):  # Basic types
            return True
        elif isinstance(data, list):
            return all(cls.validate_data(item, max_depth - 1) for item in data)
        elif isinstance(data, dict):
            return all(
                isinstance(k, str) and cls.validate_data(v, max_depth - 1)
                for k, v in data.items()
            )
        else:
            return False
    
    @classmethod
    def load_safe(cls, json_str: str) -> Any:
        """Safely load and validate JSON data"""
        try:
            data = json.loads(json_str)
            if not cls.validate_data(data):
                raise ValueError("Data contains unsafe types")
            return data
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")


# SAFE: Message protocol with validation
@dataclass
class Message:
    """Message structure for inter-service communication"""
    message_type: str
    timestamp: float
    payload: Dict[str, Any]
    
    ALLOWED_MESSAGE_TYPES = ['user_created', 'user_updated', 'user_deleted']
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Message':
        """Safely deserialize message from JSON"""
        try:
            data = json.loads(json_str)
            
            # Validate message type
            msg_type = data.get('message_type')
            if msg_type not in cls.ALLOWED_MESSAGE_TYPES:
                raise ValueError(f"Invalid message type: {msg_type}")
            
            return cls(
                message_type=msg_type,
                timestamp=float(data['timestamp']),
                payload=dict(data['payload'])
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            raise ValueError(f"Invalid message format: {e}")
    
    def to_json(self) -> str:
        """Safely serialize message to JSON"""
        return json.dumps(asdict(self))


# SAFE: Session data handling
def load_session_data_safe(session_json: str) -> Dict[str, Any]:
    """
    Safely load session data from JSON.
    Never use pickle for session data!
    """
    try:
        session_data = json.loads(session_json)
        
        # Validate expected session structure
        required_keys = ['session_id', 'user_id', 'created_at']
        if not all(key in session_data for key in required_keys):
            raise ValueError("Missing required session keys")
        
        return session_data
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid session data: {e}")


def save_session_data_safe(session_data: Dict[str, Any]) -> str:
    """Safely serialize session data to JSON"""
    # Remove any non-serializable objects
    safe_data = {
        k: v for k, v in session_data.items()
        if isinstance(v, (int, float, str, bool, list, dict, type(None)))
    }
    return json.dumps(safe_data)


# SAFE: Cache data with TTL
@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    timestamp: float
    ttl: int
    
    def to_json(self) -> str:
        """Serialize cache entry to JSON"""
        return json.dumps({
            'key': self.key,
            'value': self.value,
            'timestamp': self.timestamp,
            'ttl': self.ttl
        })
    
    @classmethod
    def from_json(cls, json_str: str) -> 'CacheEntry':
        """Deserialize cache entry from JSON"""
        try:
            data = json.loads(json_str)
            return cls(
                key=str(data['key']),
                value=data['value'],
                timestamp=float(data['timestamp']),
                ttl=int(data['ttl'])
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            raise ValueError(f"Invalid cache entry: {e}")


# SAFE: File format detection and appropriate deserialization
def load_data_by_format_safe(filepath: str) -> Any:
    """
    Safely load data from file based on extension.
    Only supports safe formats.
    """
    if filepath.endswith('.json'):
        with open(filepath, 'r') as f:
            return json.load(f)
    elif filepath.endswith('.yaml') or filepath.endswith('.yml'):
        with open(filepath, 'r') as f:
            return yaml.safe_load(f)
    else:
        raise ValueError(f"Unsupported file format: {filepath}")


# Example: Complete safe data handling workflow
def process_user_data_safe(data_json: str) -> Dict[str, Any]:
    """
    Complete example of safe data handling:
    1. Deserialize with JSON
    2. Validate structure
    3. Process
    4. Serialize back to JSON
    """
    # Deserialize safely
    user_data = SafeDataLoader.load_safe(data_json)
    
    # Validate required fields
    required_fields = ['user_id', 'username', 'email']
    if not all(field in user_data for field in required_fields):
        raise ValueError("Missing required fields")
    
    # Process (example: normalize email)
    user_data['email'] = user_data['email'].lower().strip()
    
    # Serialize back
    return user_data
