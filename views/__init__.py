# views/__init__.py

import logging
from flask import Blueprint

# Import blueprints from individual modules
from .auth import bp as auth_bp  # Auth blueprint for login, register, password management
from .user import bp as user_bp  # User blueprint for profile management, account settings
from .post import bp as post_bp  # Post blueprint for creating, viewing, deleting posts
from .main import bp as main_bp  # Main blueprint for the homepage, feed, and general pages

# Set up logger
logger = logging.getLogger(__name__)

def register_blueprints(app):
    """Registers all blueprints with the Flask app instance."""
    logger.info("Registering blueprints...")

    # Authentication routes
    app.register_blueprint(auth_bp, url_prefix='/auth')
    logger.info("Registered auth blueprint with URL prefix /auth")

    # User routes
    app.register_blueprint(user_bp, url_prefix='/user')
    logger.info("Registered user blueprint with URL prefix /user")

    # Post routes
    app.register_blueprint(post_bp, url_prefix='/post')
    logger.info("Registered post blueprint with URL prefix /post")

    # Main routes for the homepage, feed, etc.
    app.register_blueprint(main_bp)
    logger.info("Registered main blueprint")

    logger.info("All blueprints registered successfully.")