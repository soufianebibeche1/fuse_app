from flask_login import logout_user
from extensions import redis_client
from flask import current_app, request, session
import os
import logging
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime, timedelta
from extensions import db, mail, csrf
from extensions import redis_client

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from models.login_activity import LoginActivity, LoginStatus, ActivityType
from models.notification import Notification
from models.notificationsettings import NotificationSettings
from forms import LoginForm, RegisterForm, ResetPasswordForm, PasswordForm, AccountForm, DeactivateAccountForm
from utils import get_location



from decorators import require_password, rate_limit

# Setting up a logger for the application
logger = logging.getLogger(__name__)  # Using the module name as the logger's name
logger.setLevel(logging.DEBUG)  # You can change this to INFO or ERROR depending on your needs
# Add a handler (console in this case)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)  # Log level for the handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def logout_other_sessions(user_id):
    session_key_pattern = f"user:{user_id}:session:*"
    for key in redis_client.scan_iter(session_key_pattern):
        redis_client.delete(key)

    # Optionally log out the current session
    logout_user()

# Helper function to send verification email
def send_verification_email(user):
    try:
        # Generate a verification token and a temporary password
        token = user.generate_verification_token(user.email)
        temp_password = user.generate_temp_password()

        # Save the token and temporary password in the database
        user.verification_token = token
        user.temp_password_expiration = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()  # Save changes

        # Generate the reset link
        verification_link = f"{os.getenv('FRONTEND_URL', 'http://127.0.0.1:5000')}/auth/verify?token={token}"
        msg = Message(
            subject="Verify Your Account",
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user.email]
        )
        msg.body = f"""
        Hello {user.firstname},

        Thank you for signing up! To complete your registration, please verify your account by clicking the link below:

        {verification_link}

        For your convenience, we’ve also provided a temporary password that is valid for 24 hours:
        Temporary Password: {temp_password}

        After verifying your account, you'll be able to log in and set a secure password.

        If you didn’t request this account, please ignore this email or contact our support team immediately.

        Best regards,  
        The {current_app.config['APP_NAME']} Team

        ---
        This is an automated message. Please do not reply to this email.
        """
        mail.send(msg)
        logger.info(f"Verification email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {e}")
        raise

# # Helper function to send reset email
def send_reset_email(user):
    """
    Send a password reset email with a verification token and temporary password.
    """
    try:
        token = user.generate_verification_token(user.email)
        temp_password = user.generate_temp_password()

        # Update the user with the token and temporary password
        user.verification_token = token
        user.temp_password = generate_password_hash(temp_password)
        user.temp_password_expiration = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()

        reset_link = f"{os.getenv('FRONTEND_URL', 'http://127.0.0.1:5000')}/auth/reset/{token}"
        msg = Message(
            subject="Reset Your Password",
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user.email],
        )
        msg.body = f"""
        Hello {user.firstname},

        We received a request to reset the password for your {current_app.config['APP_NAME']} account.

        To reset your password, click the link below or copy and paste it into your browser:

        {reset_link}

        Temporary Password: {temp_password}
        
        Please note:
        - The temporary password is valid for **24 hours**.
        - After clicking the link, you'll need to set a new secure password.

        If you didn't request this, you can safely ignore this email.

        Best regards,  
        The {current_app.config['APP_NAME']} Support Team
        """
        mail.send(msg)
        current_app.logger.info(f"Password reset email sent to {user.email}")
    except Exception as e:
        current_app.logger.error(f"Error sending reset email: {e}")
        raise

def handle_failed_login(user):
    """
    Handles the actions required after a failed login attempt.
    Checks if the lockout period has expired, resets failed attempts if it has,
    and increments failed attempts otherwise.
    """
    # Check if the lockout period has expired
    if user.lockout_until and datetime.utcnow() > user.lockout_until:
        user.failed_login_attempts = 0
        user.lockout_until = None
        db.session.commit()  # Commit changes after resetting
        logger.info(f"Lockout period expired for user {user.email}. Failed login attempts reset.")
    
    # Increment failed login attempts
    user.failed_login_attempts += 1

    if user.failed_login_attempts >= 5:
        user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
        log_login_activity(user, False, 'Account Locked', activity_type="Login")
        flash('Too many failed login attempts. Your account has been locked for 15 minutes.', 'danger')
    else:
        log_login_activity(user, False, 'Invalid Credentials', activity_type="Login")

    db.session.commit()
    logger.warning(f"Failed login attempt for user {user.email}. Failed attempts: {user.failed_login_attempts}")


def handle_successful_login(user, remember_me):
    """
    Handles the actions required after a successful login.
    Resets lockout, updates login data, and logs activity.
    """
    # Reset failed login attempts and lockout
    user.failed_login_attempts = 0
    user.lockout_until = None
    user.last_login = datetime.utcnow()
    user.is_online = True

    login_user(user, remember=remember_me)
    session['user_id'] = user.id

    # Log successful login activity
    log_login_activity(user, True, 'Successful Login', activity_type="Login")

    db.session.commit()
    logger.info(f"User {user.email} logged in successfully.")


def log_login_activity(user, success, reason, activity_type="Login"):
    """
    Logs login activity in the LoginActivity table.

    Args:
        user: The user object.
        success (bool): Whether the login was successful.
        reason (str): Reason or description of the login attempt.
        activity_type (str): The type of activity (e.g., 'Login', 'Logout').
    """
    ip_address = request.remote_addr
    city, country = get_location(ip_address)
    city = city or 'Unknown'
    country = country or 'Unknown'

    login_activity = LoginActivity(
        user_id=user.id,
        ip_address=ip_address,
        user_agent=request.user_agent.string,
        successful_login=success,
        activity_type=ActivityType[activity_type.upper()],  # Convert to ActivityType enum
        city=city,
        country=country,
        status=LoginStatus.SUCCESS if success else LoginStatus.FAILED,
        failure_reason=reason
    )
    db.session.add(login_activity)
    db.session.commit()
    logger.info(f"Login activity logged for user {user.email}: {reason}")


def log_logout_activity():
    """Logs the logout activity for the user."""
    try:
        ip_address = request.remote_addr
        city, country = get_location(ip_address)  # Unpack the tuple into city and country
        city = city or 'Unknown'
        country = country or 'Unknown'

        logout_activity = LoginActivity(
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=request.user_agent.string,
            successful_login=False,  # This is a logout event, not a successful login
            activity_type='Logout',  # Optional, to track logout explicitly
            city=city,
            country=country,
            status='Logout'  # Explicit logout status
        )

        db.session.add(logout_activity)
        db.session.commit()  # Commit logout activity
    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        current_app.logger.error(f"Error during logout activity logging: {e}")
        flash('An error occurred while logging your logout activity. Please try again.', 'danger')
        raise  # Reraise the exception to propagate it


def update_user_status():
    """Updates the user's online status and last login timestamp."""
    try:
        current_user.is_online = False
        current_user.last_login = datetime.utcnow()  # Optionally record the last logout time
        db.session.commit()  # Commit the status update
    except Exception as e:
        db.session.rollback()  # Rollback if there's an error during status update
        current_app.logger.error(f"Error during status update: {e}")
        flash('An error occurred while updating your status. Please try again.', 'danger')
        raise  # Reraise the exception to propagate it


def logout_user_and_clear_session():
    """Logs the user out and clears the session."""
    try:
        logout_user()
        session.pop('user_id', None)
    except Exception as e:
        current_app.logger.error(f"Error during session logout: {e}")
        flash('An error occurred while logging you out. Please try again.', 'danger')
        raise

def get_current_user_id():
    """
    Returns the ID of the currently logged-in user.
    If no user is logged in, returns None.
    """
    if current_user.is_authenticated:
        return current_user.id
    return None