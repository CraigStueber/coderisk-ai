"""
Safe version - Security Misconfiguration Fixed
This file demonstrates proper security configuration.
"""
import os
from flask import Flask
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# SAFE: Debug mode controlled by environment variable
def create_flask_app() -> Flask:
    """Create Flask app with secure configuration"""
    app = Flask(__name__)
    
    # Control debug mode via environment variable
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.config['DEBUG'] = debug_mode
    
    # Additional security configurations
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
    
    return app


# SAFE: Proper CORS configuration with explicit allowlist
def create_fastapi_app() -> FastAPI:
    """Create FastAPI app with secure CORS configuration"""
    app = FastAPI()
    
    # Define explicit list of allowed origins
    allowed_origins = [
        "https://example.com",
        "https://app.example.com",
        "https://www.example.com"
    ]
    
    # Add CORS middleware with explicit origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
        max_age=3600,
    )
    
    return app


# SAFE: Load CORS origins from environment configuration
def create_fastapi_app_with_env_config() -> FastAPI:
    """Create FastAPI app with CORS origins from environment"""
    app = FastAPI()
    
    # Load allowed origins from environment variable
    origins_str = os.getenv('ALLOWED_ORIGINS', 'https://example.com')
    allowed_origins = [origin.strip() for origin in origins_str.split(',')]
    
    # Validate that no wildcard is present
    if '*' in allowed_origins:
        raise ValueError("Wildcard '*' not allowed in CORS origins")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )
    
    return app


# SAFE: Environment-based configuration class
class Config:
    """Application configuration from environment variables"""
    
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    SECRET_KEY = os.getenv('SECRET_KEY', '')
    
    # Database
    DATABASE_URL = os.getenv('DATABASE_URL', '')
    
    # Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # CORS
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '').split(',')
    
    @classmethod
    def validate(cls):
        """Validate configuration"""
        if not cls.SECRET_KEY:
            raise ValueError("SECRET_KEY must be set")
        if '*' in cls.CORS_ORIGINS:
            raise ValueError("Wildcard CORS origins not allowed")
        if cls.DEBUG and os.getenv('ENVIRONMENT') == 'production':
            raise ValueError("DEBUG must be False in production")


def create_secure_flask_app() -> Flask:
    """Create Flask app with validated configuration"""
    # Validate configuration
    Config.validate()
    
    app = Flask(__name__)
    app.config.from_object(Config)
    
    return app


# SAFE: Different configurations for different environments
class DevelopmentConfig:
    """Development environment configuration"""
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"  # Safe: reads from environment
    TESTING = True
    CORS_ORIGINS = ['http://localhost:3000', 'http://localhost:8000']


class ProductionConfig:
    """Production environment configuration"""
    DEBUG = False  # Must be False
    TESTING = False
    CORS_ORIGINS = ['https://example.com', 'https://app.example.com']
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True


def get_config():
    """Get configuration based on environment"""
    env = os.getenv('ENVIRONMENT', 'development')
    
    if env == 'production':
        return ProductionConfig
    return DevelopmentConfig


# SAFE: Security headers middleware
def add_security_headers(app: Flask) -> Flask:
    """Add security headers to Flask app"""
    
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response
    
    return app


# SAFE: Complete secure application setup
def create_production_ready_app() -> Flask:
    """
    Create production-ready Flask application with all security configurations.
    """
    # Validate environment
    if os.getenv('ENVIRONMENT') != 'production':
        raise ValueError("This configuration is for production only")
    
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(ProductionConfig)
    
    # Ensure DEBUG is False
    app.config['DEBUG'] = False
    
    # Set secret key from environment
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key or len(secret_key) < 32:
        raise ValueError("SECRET_KEY must be set and at least 32 characters")
    app.config['SECRET_KEY'] = secret_key
    
    # Add security headers
    app = add_security_headers(app)
    
    # Additional security configurations
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
    
    return app


# Example usage with proper environment variable checks
if __name__ == '__main__':
    # Check environment
    env = os.getenv('ENVIRONMENT', 'development')
    
    if env == 'production':
        # Production: never use debug mode
        app = create_production_ready_app()
        # In production, use proper WSGI server (gunicorn, uwsgi)
        # Not: app.run()
    else:
        # Development: can use debug mode
        app = create_flask_app()
        debug_mode = os.getenv('FLASK_DEBUG', 'true').lower() == 'true'
        app.run(debug=debug_mode, host='127.0.0.1', port=5000)
