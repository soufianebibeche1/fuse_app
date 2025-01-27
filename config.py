import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base configuration class
class Config:
    """Base configuration with security, database, and session settings."""
    
    # Security and session settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')  # fallback to default if not set
    SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT', 'default_salt')  # fallback to default if not set
    APP_NAME = os.getenv('APP_NAME', 'Our Application')  # Default to 'Our Application' if APP_NAME is missing

    # Base upload folder
    UPLOAD_FOLDER = "C:/Users/LockJMein/Desktop/adda/static/uploads"

    # Subfolders for profile and cover pictures
    PROFILE_PICS_FOLDER = os.path.join(UPLOAD_FOLDER, "profile_pics")
    COVER_PICS_FOLDER = os.path.join(UPLOAD_FOLDER, "cover_pics")
    POST_MEDIA_FOLDER = os.path.join(UPLOAD_FOLDER, "post_media")

    # Allowed file extensions for uploads
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'bmp'}

    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///default.db')  # fallback to SQLite if not set
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable modification tracking to save resources

    # Session & cookie security settings
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True'
    REMEMBER_COOKIE_SECURE = os.getenv('REMEMBER_COOKIE_SECURE', 'True') == 'True'
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=int(os.getenv('PERMANENT_SESSION_LIFETIME', 604800)))  # 1 week default
    SESSION_COOKIE_HTTPONLY = True  # Helps mitigate XSS attacks

    # Mail configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', MAIL_USERNAME)

    # OAuth configuration for social login
    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
    FACEBOOK_CLIENT_ID = os.getenv('FACEBOOK_CLIENT_ID')
    FACEBOOK_CLIENT_SECRET = os.getenv('FACEBOOK_CLIENT_SECRET')
    TWITTER_CLIENT_ID = os.getenv('TWITTER_CLIENT_ID')
    TWITTER_CLIENT_SECRET = os.getenv('TWITTER_CLIENT_SECRET')
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

    # Logging configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')

    # Additional security settings (e.g., Content Security Policy)
    CSP_HEADER = os.getenv('CSP_HEADER', "default-src 'self'")

    # Redis configuration
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379
    REDIS_DB = 0
    REDIS_PASSWORD = None

    # Session configuration for Flask-Session (Redis-backed)
    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'session:'

    RATE_LIMIT_DEFAULT = "100 per minute"
    FLASK_LIMITER_KEY_FUNC = 'get_remote_address'

# Default configuration (used when no specific environment is set)
class DefaultConfig(Config):
    """Default configuration with settings suitable for all environments."""
    DEBUG = True  # Enable debug mode by default
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///default.db')  # Default database

    # Other configurations can be added here as needed

# Development configuration (specific to development environment)
class DevelopmentConfig(Config):
    DEBUG = True  # Enable debug mode in development
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///development.db')

# Production configuration (specific to production environment)
class ProductionConfig(Config):
    SESSION_COOKIE_SECURE = True
    DEBUG = False
    LOG_LEVEL = 'INFO'
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://user:password@localhost/production_db')

# Testing configuration (specific to testing environment)
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # Use in-memory database for testing
    WTF_CSRF_ENABLED = False  # Disable CSRF protection during testing

# Dictionary to map configuration names to classes
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DefaultConfig  # Set default configuration
}