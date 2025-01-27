from flask import Flask, redirect, request, jsonify, session, current_app
from dotenv import load_dotenv
from extensions import initialize_extensions, redis_client, csrf, db
from views import register_blueprints
from models import db
from models.user import User
from sqlalchemy import text
from flask_session import Session
from datetime import timedelta
import time
from sqlalchemy.exc import OperationalError
from models.notificationmanager import create_system_user_if_not_exists
import os
from flask_wtf.csrf import CSRFProtect
from utils import *
import logging


def create_app(config_name='default'):
    app = Flask(__name__)
    load_dotenv()

    # Load configuration dynamically based on environment
    app.config.from_object(f'config.{config_name.capitalize()}Config')
    app.config['WTF_CSRF_ENABLED'] = True

    initialize_extensions(app)

    # Debug configuration
    for key, value in app.config.items():
        app.logger.debug(f"{key}: {value}")

    logging.basicConfig(level=app.config['LOG_LEVEL'])
    app.logger.setLevel(app.config['LOG_LEVEL'])

    # Configure Redis-backed sessions
    Session(app)  # Initialize session management
    app.logger.debug("Flask-Session initialized.")

    # Ensure folders exist (use app.config)
    os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['COVER_PICS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['POST_MEDIA_FOLDER'], exist_ok=True)
    ensure_upload_folders(app)

    @app.before_request
    def set_session_timeout():
        # Set session to permanent and configure the expiration time
        session.permanent = True
        current_app.permanent_session_lifetime = timedelta(minutes=604800)

    @app.errorhandler(500)
    def internal_server_error(e):
        current_app.logger.error(f"An error occurred: {e}")
        return "Internal Server Error", 500

    @app.before_request
    def enforce_https_in_production():
        if not request.is_secure and app.config.get('ENV') == 'production':
            return redirect(request.url.replace('http://', 'https://', 1))

    register_blueprints(app)

    @app.after_request
    def add_header(response):
        """
        Add headers to force the browser to not cache static files.
        """
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "-1"
        return response
    
    @app.context_processor
    def utility_functions():
        """Make utility functions available in templates."""
        return dict(encode_user_id=encode_user_id)


    @app.route('/healthcheck')
    def healthcheck():
        try:
            result = db.session.execute(text("SELECT 1"))
            return jsonify({'status': 'ok'}), 200
        except Exception as e:
            app.logger.error(f"Database error: {e}")
            return jsonify({'status': 'error'}), 500

    @app.route('/test_session')
    def test_session():
        return jsonify({
            'session_cookie_name': current_app.config.get('SESSION_COOKIE_NAME'),
            'session_data': dict(session)
        })

    # Route to check database connection and list users
    @app.route('/check_db')
    def check_db():
        try:
            with current_app.extensions['migrate'].db.engine.connect() as connection:
                result = connection.execute(text("SELECT * FROM users;"))
                users = [dict(zip(result.keys(), row)) for row in result.fetchall()]
                return jsonify(users), 200
        except Exception as e:
            return f"Error connecting to the database: {str(e)}", 500

    with app.app_context():
        # Now that the connection is successful, create the system user if needed
        create_system_user_if_not_exists()

    return app

if __name__ == "__main__":
    app = create_app('development')
    app.run(host='0.0.0.0', port=5000)