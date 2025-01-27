# models/__init__.py

from sqlalchemy.orm import registry
from extensions import db

# Import all models for central reference
from .user import User
from .post import Post
from .notification import Notification
from .notificationmanager import NotificationManager
from .notificationsettings import NotificationSettings
from .login_activity import LoginActivity
from .user_activity import UserActivity
from .like import Like
from .comment import Comment

# Optional: Create metadata registry to centralize metadata for all models
mapper_registry = registry()

def initialize_database(app):
    """Initialize database models with Flask app context for robust integration.
    
    This function configures the database for a consistent structure with
    DevOps, security, and quality practices in mind. It allows lazy loading
    and defers model instantiation until the application is fully initialized.
    """
    with app.app_context():
        # Create tables if they do not exist
        db.create_all()
    
    # Ensure initial setup or constraints if needed
    setup_initial_data()
    
    return db

def setup_initial_data():
    """Set up initial data if necessary, e.g., default tags, roles, or settings.
    
    This function ensures that essential data is pre-populated in the database
    (e.g., common tags or notification settings) to support a fully functional 
    social media platform out-of-the-box.
    """
    pass  # Add any setup code as needed

__all__ = [
    'User', 'Post', 'Notification', 'NotificationManager', 'LoginActivity', 
    'UserActivity', 'NotificationSettings', 'Like', 'Comment', 'initialize_database', 'setup_initial_data'
]