# auth.py

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db, mail, csrf, limiter,oauth
from models.user import User, GenderEnum
from models.login_activity import LoginActivity, LoginStatus, ActivityType
from models.notification import Notification, NotificationType
from models.notificationsettings import NotificationSettings
from models.notificationmanager import NotificationManager
from forms import LoginForm, RegisterForm, ResetPasswordForm, PasswordForm, AccountForm, DeactivateAccountForm
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime, timedelta
from flask_mail import Message
import os
from flask import current_app, request
from decorators import require_password, rate_limit
from views.auth_heplpers import logout_other_sessions, send_verification_email, send_reset_email, log_logout_activity, update_user_status, logout_user_and_clear_session, log_login_activity, handle_failed_login, handle_successful_login
from flask_limiter import Limiter
from sqlalchemy.exc import SQLAlchemyError
import logging
from utils import get_country_choices, get_location
from sqlalchemy import desc
from flask_wtf.csrf import CSRFError
import json

# Blueprint for authentication
bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)



# @bp.route('/login', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")
# def login():
#     """
#     User login route for the social media platform.
#     Handles user authentication and session initialization.
#     """
#     login_form = LoginForm()
#     register_form = RegisterForm()
#     reset_password_form = ResetPasswordForm()

#     if login_form.validate_on_submit():
#         # Get input data
#         email_or_username = login_form.email_or_username.data.strip()
#         password = login_form.password.data.strip()

#         if not email_or_username or not password:
#             flash('Email/Username and password are required.', 'danger')
#             return redirect(url_for('auth.login'))

#         try:
#             # Check if user exists based on email or username
#             user = User.query.filter(
#                 (User.email == email_or_username) | (User.username == email_or_username)
#             ).first()

#             if user:
#                 # Check if the user is active
#                 if not user.is_active:
#                     flash('Your account is not active. Please contact support or request a password reset to recover access.', 'danger')
#                     return redirect(url_for('auth.login'))

#                 # Case for verified, old user with a password (normal login flow)
#                 if user.password_hash and user.is_verified:
#                     if user.verify_password(password):
#                         # Reset failed login attempts
#                         user.failed_login_attempts = 0
#                         user.lockout_until = None
#                         user.last_login = datetime.utcnow()
#                         user.is_online = True

#                         # Log successful login
#                         login_user(user, remember=login_form.remember_me.data)
#                         session['user_id'] = user.id

#                         # Log activity
#                         ip_address = request.remote_addr
#                         city, country = get_location(ip_address)
#                         city = city or 'Unknown'
#                         country = country or 'Unknown'
#                         login_activity = LoginActivity(
#                             user_id=user.id,
#                             ip_address=ip_address,
#                             user_agent=request.user_agent.string,
#                             successful_login=True,
#                             city=city,
#                             country=country,
#                             status='success'
#                         )
#                         db.session.add(login_activity)
#                         db.session.commit()

#                         flash('Login successful.', 'success')
#                         logger.info(f"User {user.email} logged in successfully.")
#                         return redirect(url_for('main.index'))

#                     else:
#                         # Log failed login attempt
#                         user.failed_login_attempts += 1
#                         if user.failed_login_attempts >= 5:
#                             user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
#                         db.session.commit()

#                         flash('Invalid credentials. Please try again.', 'danger')

#                 # Case for a new user with a temp password but no password set, user needs to verify
#                 elif user.temp_password and user.verification_token and not user.is_verified and not user.password_hash:
#                     if user.verify_temp_password(password):
#                         # Log activity
#                         ip_address = request.remote_addr
#                         city, country = get_location(ip_address)
#                         city = city or 'Unknown'
#                         country = country or 'Unknown'
#                         login_activity = LoginActivity(
#                             user_id=user.id,
#                             ip_address=ip_address,
#                             user_agent=request.user_agent.string,
#                             successful_login=True,
#                             city=city,
#                             country=country,
#                             status='success'
#                         )
#                         db.session.add(login_activity)
#                         db.session.commit()

#                         # Redirect user to /verify route to complete verification process
#                         return redirect(url_for('auth.verify_account', token=user.verification_token))

#                     else:
#                         flash('Invalid temporary password. Please try again.', 'danger')

#                 # Case for password reset, temp password should be used to go to /reset_password
#                 elif user.temp_password and user.verification_token and not user.is_verified:
#                     if user.verify_temp_password(password):
#                         # Redirect user to password reset route
#                         # flash('You are being redirected to reset your password.', 'info')
#                         # return redirect(url_for('auth.reset_password', token=user.verification_token))

#                         # Debugging log
#                         current_app.logger.debug(f"Temporary password verified for user {user.email}")
#                         # Debugging log
#                         current_app.logger.debug(f"User {user.email} logged in, redirecting to reset password")

#                         # Commit changes and redirect
#                         # db.session.commit()

#                         return redirect(url_for('auth.reset_with_token', token=user.verification_token))
#                     else:
#                         flash('Invalid temporary password. Please try again.', 'danger')

#                 else:
#                     flash('You need to set your password to log in.', 'warning')

#             else:
#                 flash('No user found with this email or username.', 'danger')

#         except SQLAlchemyError as e:
#             db.session.rollback()
#             flash('An error occurred while processing your request. Please try again later.', 'danger')
#             logger.error(f"Error processing login request: {e}")

#     return render_template(
#         'login.html',
#         login_form=login_form,
#         register_form=register_form,
#         reset_password_form=reset_password_form,
#         form_type='login'
#     )

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    """
    User login route for the social media platform.
    Handles user authentication, lockout mechanism, and session initialization.
    """
    login_form = LoginForm()
    register_form = RegisterForm()
    reset_password_form = ResetPasswordForm()

    if login_form.validate_on_submit():
        # Get input data
        email_or_username = login_form.email_or_username.data.strip()
        password = login_form.password.data.strip()

        if not email_or_username or not password:
            flash('Email/Username and password are required.', 'danger')
            return redirect(url_for('auth.login'))

        try:
            # Fetch user based on email or username
            user = User.query.filter(
                (User.email == email_or_username) | (User.username == email_or_username)
            ).first()

            if user:
                # Handle account lockout
                if user.lockout_until and datetime.utcnow() < user.lockout_until:
                    remaining_time = (user.lockout_until - datetime.utcnow()).seconds // 60
                    flash(f'Your account is locked. Please try again after {remaining_time} minutes.', 'danger')
                    log_login_activity(user, True, "Successful Login", activity_type="Login")
                    return redirect(url_for('auth.login'))

                # Check if account is active
                if not user.is_active:
                    flash('Your account is not active. Please contact support or request a password reset to recover access.', 'danger')
                    log_login_activity(user, False, 'Inactive Account')
                    return redirect(url_for('auth.login'))

                # Handle normal login with verified password
                if user.password_hash and user.is_verified:
                    if user.verify_password(password):
                        handle_successful_login(user, login_form.remember_me.data)
                        flash('Login successful.', 'success')
                        return redirect(url_for('main.index'))
                    else:
                        handle_failed_login(user)
                        flash('Invalid credentials. Please try again.', 'danger')

                # Handle temporary password login for new or password-reset users
                elif user.temp_password and user.verification_token:
                    if user.verify_temp_password(password):
                        if not user.is_verified and not user.password_hash:
                            # Redirect to account verification
                            log_login_activity(user, True, 'Temporary Password Verified')
                            return redirect(url_for('auth.verify_account', token=user.verification_token))

                        # Redirect to reset password route
                        log_login_activity(user, True, 'Temporary Password Verified')
                        return redirect(url_for('auth.reset_with_token', token=user.verification_token))
                    else:
                        flash('Invalid temporary password. Please try again.', 'danger')

                else:
                    flash('You need to set your password to log in.', 'warning')
            else:
                flash('No user found with this email or username.', 'danger')

        except SQLAlchemyError as e:
            db.session.rollback()
            flash('An error occurred while processing your request. Please try again later.', 'danger')
            logger.error(f"Error processing login request: {e}")

    return render_template(
        'login.html',
        login_form=login_form,
        register_form=register_form,
        reset_password_form=reset_password_form,
        form_type='login'
    )


# @bp.route('/sign_up', methods=['GET', 'POST'])
# def sign_up():
#     """
#     Handles user signup functionality.
#     Redirects authenticated users, validates input, checks for existing accounts,
#     and sends a verification email on successful registration.
#     """
#     # Redirect already authenticated users
#     if current_user.is_authenticated:
#         next_page = request.args.get('next', url_for('main.index'))
#         return redirect(next_page)
    
#     # Instantiate forms
#     login_form = LoginForm()
#     register_form = RegisterForm()
#     reset_password_form = ResetPasswordForm()

#     # Process signup form submission
#     if register_form.validate_on_submit():
#         email = register_form.email_createaccount.data.strip().lower()
#         username = register_form.username_createaccount.data.strip().lower()
#         firstname = register_form.firstname.data.strip()
#         lastname = register_form.lastname.data.strip()
#         gender = register_form.gender.data
#         age = register_form.age.data
#         country = register_form.country.data.strip()

#         # Handle gender assignment, ensuring it's a valid value from GenderEnum
#         try:
#             if isinstance(gender, GenderEnum):
#                 gender_enum = gender  # If gender is already an instance of GenderEnum, assign directly
#             else:
#                 gender_enum = GenderEnum[gender.lower()]  # Convert string to GenderEnum
#         except KeyError:
#             gender_enum = None  # Set to None if the gender value is invalid

#         # Check for existing user by email or username
#         existing_user = User.query.filter(
#             (User.email == email) | (User.username == username)
#         ).first()

#         if existing_user:
#             flash('A user with this email or username already exists.', 'danger')
#             return redirect(url_for('auth.sign_up'))

#         # Attempt to create the new user
#         try:
#             # Create a new user instance
#             new_user = User(
#                 email=email,
#                 username=username,
#                 firstname=firstname,
#                 lastname=lastname,
#                 gender=gender_enum,
#                 age=age,
#                 country=country,
#             )

#             # Add new user to the session (but do not commit yet)
#             db.session.add(new_user)
            
#             # Generate a temporary password or token and send verification email
#             send_verification_email(new_user)

#             # Commit the user to the database after sending the verification email
#             db.session.commit()

#             # Send account creation notification
#             NotificationManager.send_account_creation_notification(new_user)

#             flash('Account created successfully! Please check your email to verify your account.', 'success')
#             return redirect(url_for('auth.login'))

#         except Exception as e:
#             # Rollback the transaction in case of error to ensure no data is saved
#             db.session.rollback()
#             current_app.logger.error(f"Error during signup: {e}")
#             flash('An error occurred during signup. Please try again later.', 'danger')
#             return redirect(url_for('auth.sign_up'))

#     # Render signup form
#     return render_template(
#         'login.html',
#         login_form=login_form,
#         register_form=register_form,
#         reset_password_form=reset_password_form,
#         form_type='create_Account'
#     )

@bp.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    """
    Handles user signup functionality.
    Redirects authenticated users, validates input, checks for existing accounts,
    and sends a verification email on successful registration.
    """
    # Redirect already authenticated users
    if current_user.is_authenticated:
        next_page = request.args.get('next', url_for('main.index'))
        return redirect(next_page)

    # Instantiate forms
    login_form = LoginForm()
    register_form = RegisterForm()
    reset_password_form = ResetPasswordForm()

    # Process signup form submission
    if register_form.validate_on_submit():
        # Wrap the user creation process in a try-except block to ensure atomicity
        try:
            email = register_form.email_createaccount.data.strip().lower()
            username = register_form.username_createaccount.data.strip().lower()
            firstname = register_form.firstname.data.strip()
            lastname = register_form.lastname.data.strip()
            gender = register_form.gender.data
            age = register_form.age.data
            country = register_form.country.data.strip()

            # Handle gender assignment, ensuring it's a valid value from GenderEnum
            try:
                if isinstance(gender, GenderEnum):
                    gender_enum = gender  # If gender is already an instance of GenderEnum, assign directly
                else:
                    gender_enum = GenderEnum[gender.lower()]  # Convert string to GenderEnum
            except KeyError:
                flash('Invalid gender value provided.', 'danger')
                return redirect(url_for('auth.sign_up'))  # Stop execution on invalid gender

            # Check for existing user by email or username
            existing_user = User.query.filter(
                (User.email == email) | (User.username == username)
            ).first()

            if existing_user:
                flash('A user with this email or username already exists.', 'danger')
                return redirect(url_for('auth.sign_up'))  # Stop execution if user exists

            # Create a new user instance
            new_user = User(
                email=email,
                username=username,
                firstname=firstname,
                lastname=lastname,
                gender=gender_enum,
                age=age,
                country=country,
            )

            # Add new user to the session but do not commit yet
            db.session.add(new_user)

            # Generate a temporary password or token and send verification email
            send_verification_email(new_user)

            # Commit the user to the database only if everything succeeds
            db.session.commit()

            # Send account creation notification
            NotificationManager.send_account_creation_notification(new_user)

            flash('Account created successfully! Please check your email to verify your account.', 'success')
            return redirect(url_for('auth.login'))

        except Exception as e:
            # Rollback the transaction in case of error to ensure no data is saved
            db.session.rollback()
            current_app.logger.error(f"Error during signup: {e}")
            flash('An error occurred during signup. Please try again later.', 'danger')
            return redirect(url_for('auth.sign_up'))

    # Render signup form
    return render_template(
        'login.html',
        login_form=login_form,
        register_form=register_form,
        reset_password_form=reset_password_form,
        form_type='create_Account'
    )

# @bp.route('/verify', methods=['GET'])
# def verify_account():
#     """
#     User verification route for the social media platform.
#     Confirms new user account creation and sends notifications.
#     """
#     token = request.args.get('token')
#     if not token:
#         flash('Verification token is missing.', 'danger')
#         return redirect(url_for('auth.login'))

#     try:
#         # Decode the email from the token
#         email = User.verify_verification_token(token)
#         current_app.logger.info(f"Decoded email from token: {email}")

#         # Query the user by email
#         user = User.query.filter_by(email=email).first()
#         if not user:
#             current_app.logger.warning(f"No user found with email: {email}")
#             flash('User not found during verification process.', 'danger')
#             return redirect(url_for('auth.login'))

#         # Check if the user is already verified
#         if user.is_verified:
#             flash('Your account is already verified.', 'info')
#             return redirect(url_for('auth.login'))

#         # # Mark the user as verified
#         # user.is_verified = True
#         # db.session.commit()

#         # Send a notification for account verification
#         try:
#             NotificationManager.send_account_verified_notification(user)
#             current_app.logger.info(f"Account verification notification sent to {user.email}.")
#         except Exception as e:
#             current_app.logger.error(f"Failed to send account verified notification: {e}")
#             db.session.rollback()  # Undo verification if notification fails
#             flash('An error occurred while sending the verification notification. Please try again.', 'danger')
#             return redirect(url_for('auth.login'))

#         # Optionally, log the user in automatically after verification
#         login_user(user)
#         flash('Your account has been verified. Please set a strong and secure password.', 'success')

#         current_app.logger.info(f"User {user.email} successfully verified their account.")
#         return redirect(url_for('user.change_password'))

#     except ValueError as e:
#         current_app.logger.error(f"Verification failed: Invalid token or decoding error. {e}")
#         flash('The verification link is invalid or expired. Please try again.', 'danger')
#     except Exception as e:
#         current_app.logger.error(f"Unexpected error during verification: {e}")
#         flash('An unexpected error occurred during verification. Please try again.', 'danger')

#     return redirect(url_for('auth.login'))


@bp.route('/verify', methods=['GET'])
def verify_account():
    """
    User verification route for the social media platform.
    Confirms new user account creation and sends notifications.
    """
    token = request.args.get('token')
    if not token:
        flash('Verification token is missing.', 'danger')
        return redirect(url_for('auth.login'))

    try:
        # Decode the email from the token
        email = User.verify_verification_token(token)
        current_app.logger.info(f"Decoded email from token: {email}")

        # Query the user by email
        user = User.query.filter_by(email=email).first()
        if not user:
            current_app.logger.warning(f"No user found with email: {email}")
            flash('User not found during verification process.', 'danger')
            return redirect(url_for('auth.login'))

        # Check if the user is already verified
        if user.is_verified:
            flash('Your account is already verified.', 'info')
            return redirect(url_for('auth.login'))

        # Create a login activity for the verification attempt
        login_activity = LoginActivity(
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            activity_type=ActivityType.LOGIN,  # Assume user is trying to log in during verification
            successful_login=False,  # Initially mark as failed until the verification completes
            status=LoginStatus.FAILED  # Verification fails if it doesn't succeed
        )
        db.session.add(login_activity)
        db.session.commit()

        # # Mark the user as verified
        # user.is_verified = True
        # db.session.commit()

        # Send a notification for account verification
        try:
            NotificationManager.send_account_verified_notification(user)
            current_app.logger.info(f"Account verification notification sent to {user.email}.")
        except Exception as e:
            # Log the error and rollback the transaction if sending notification fails
            current_app.logger.error(f"Failed to send account verified notification: {e}")
            db.session.rollback()  # Undo verification if notification fails
            # Update login activity status to reflect that the process failed
            login_activity.status = LoginStatus.SUSPICIOUS
            login_activity.suspicious_activity = True
            db.session.commit()

            flash('An error occurred while sending the verification notification. Please try again.', 'danger')
            return redirect(url_for('auth.login'))

        # Successfully verified the user
        # Update login activity to reflect successful verification
        login_activity.status = LoginStatus.SUCCESS
        login_activity.successful_login = True
        db.session.commit()

        # Optionally, log the user in automatically after verification
        login_user(user)
        flash('Your account has been verified. Please set a strong and secure password.', 'success')

        current_app.logger.info(f"User {user.email} successfully verified their account.")
        return redirect(url_for('user.change_password'))

    except ValueError as e:
        # Handle errors in token verification
        current_app.logger.error(f"Verification failed: Invalid token or decoding error. {e}")
        flash('The verification link is invalid or expired. Please try again.', 'danger')
    except Exception as e:
        # Catch any other unexpected errors
        current_app.logger.error(f"Unexpected error during verification: {e}")
        flash('An unexpected error occurred during verification. Please try again.', 'danger')
        
        # If verification fails due to an error, cancel the activity and mark the login as failed
        if 'login_activity' in locals():  # If login_activity was created
            login_activity.status = LoginStatus.FAILED
            login_activity.successful_login = False
            db.session.commit()

    return redirect(url_for('auth.login'))


@bp.route('/login/<provider>')
def login_with_provider(provider):
    """
    Initiates the OAuth login flow with the specified provider (Google, GitHub, or Facebook).
    Redirects the user to the provider's login page.
    """
    # Check if the provider is valid
    if provider not in ['google', 'github', 'facebook']:
        flash('Invalid provider.', 'danger')
        return redirect(url_for('auth.login'))
    
    # Redirect the user to the provider's login page
    client = oauth.create_client(provider)
    return client.authorize_redirect(redirect_uri=url_for('auth.callback', provider=provider, _external=True))

@bp.route('/login/<provider>/callback')
def callback(provider):
    """
    Handles the callback after the OAuth provider has authenticated the user.
    Retrieves the user's info and logs them in, or creates a new user if not found.
    """
    # Check if the provider is valid
    if provider not in ['google', 'github', 'facebook']:
        flash('Invalid provider.', 'danger')
        return redirect(url_for('auth.login'))

    # Get the OAuth client for the provider
    client = oauth.create_client(provider)
    
    # Authorize and retrieve the token
    token = client.authorize_access_token()
    user_info = client.parse_id_token(token)

    # Check if the user exists in the database, create if not
    user = User.query.filter_by(social_id=user_info['sub'], auth_provider=provider).first()

    if not user:
        # Create a new user if none exists
        user = User(
            email=user_info.get('email'),  # Mandatory field, check for existence
            username=user_info.get('name'),  # Mandatory field, check for existence
            auth_provider=provider,
            social_id=user_info['sub'],
            is_verified=True,  # Assuming social accounts are verified by default

            # Optional fields, assign only if they exist in user_info
            firstname=user_info.get('given_name'),
            lastname=user_info.get('family_name'),
            profilepic=user_info.get('picture'),
            gender=user_info.get('gender'),
            age=user_info.get('age'),
            country=user_info.get('locale'),
        )
        db.session.add(user)
        db.session.commit()

    # Log the user in
    login_user(user)

    # Set user as online
    user.is_online = True
    db.session.commit()  # Commit changes to the database

    # Redirect user to desired page after login
    return redirect(url_for('main.index'))

# @bp.route('/reset_account', methods=['GET', 'POST'])
# def reset_account():
#     """
#     Handle requests for resetting passwords.
#     """
#     if current_user.is_authenticated:
#         return redirect(url_for('main.index'))

#     login_form = LoginForm()
#     register_form = RegisterForm()
#     reset_password_form = ResetPasswordForm()

#     if reset_password_form.validate_on_submit():
#         user = User.query.filter_by(email=reset_password_form.email.data).first()
#         if user:
#             try:
#                 # Clear old password and reset related fields
#                 user.temp_password = None
#                 user.temp_password_expiration = None
#                 user.is_verified = False
#                 user.is_deactivated = False  # Reactivate the account
#                 user.is_active = True
#                 db.session.commit()  # Commit before proceeding further

#                 # Log activity
#                 try:
#                     ip_address = request.remote_addr
#                     city, country = get_location(ip_address)  # Unpack the tuple into city and country
#                     city = city or 'Unknown'
#                     country = country or 'Unknown'
#                     login_activity = LoginActivity(
#                         user_id=user.id,
#                         ip_address=ip_address,
#                         user_agent=request.user_agent.string,
#                         successful_login=True,
#                         city=city,
#                         country=country,
#                         status='success'
#                     )
#                     db.session.add(login_activity)
#                     db.session.commit()
#                 except Exception as e:
#                     db.session.rollback()  # Rollback in case of error
#                     current_app.logger.error(f"Error logging activity during password reset: {e}")
#                     flash('An error occurred while logging activity. Please try again later.', 'danger')
#                     return redirect(url_for('auth.login'))

#                 # Notify the user about the reset using NotificationManager
#                 try:
#                     notification_created = NotificationManager.create_system_notification(
#                         recipient_id=user.id,
#                         title="Account Reactivated",
#                         message="Your account has been successfully reactivated.",
#                         notification_type="info",
#                         content="Welcome back! Your account is now active. Please reset your password to secure your account."
#                     )
#                     if not notification_created:
#                         raise Exception("Failed to create system notification.")
#                 except Exception as e:
#                     current_app.logger.error(f"Error creating notification: {e}")
#                     flash('An error occurred while notifying the user. Please try again later.', 'danger')
#                     return redirect(url_for('auth.login'))

#                 # Send the reset email with token and temporary password
#                 send_reset_email(user)
#                 flash('A password reset email has been sent. Please check your inbox.', 'success')
#                 return redirect(url_for('auth.login'))

#             except Exception as e:
#                 db.session.rollback()  # Rollback in case of error
#                 current_app.logger.error(f"Error during password reset: {e}")
#                 flash('An error occurred while processing your request. Please try again later.', 'danger')
#         else:
#             flash('No account found with that email address.', 'danger')

#     return render_template(
#         'login.html',
#         login_form=login_form,
#         register_form=register_form,
#         reset_password_form=reset_password_form,
#         form_type='reset_account'
#     )


# @bp.route('/reset/<token>', methods=['GET', 'POST'])
# def reset_with_token(token):
#     """
#     Handle password resets via token link.
#     """
#     try:
#         email = User.verify_verification_token(token)
#         user = User.query.filter_by(email=email, verification_token=token).first()

#         if not user:
#             flash('Invalid or expired reset link.', 'danger')
#             return redirect(url_for('auth.login'))

#         try:
#             # Automatically log the user in and prompt to set a new password
#             login_user(user)
#             db.session.commit()  # Commit before proceeding
#             flash('Set a new strong password to recover your password.', 'success')
#             return redirect(url_for('user.change_password'))

#         except Exception as e:
#             db.session.rollback()  # Rollback in case of error
#             current_app.logger.error(f"Error during reset with token: {e}")
#             flash('An error occurred while resetting your password. Please try again later.', 'danger')
#             return redirect(url_for('auth.login'))

#     except (BadSignature, SignatureExpired):
#         flash('Invalid or expired reset link.', 'danger')
#     except Exception as e:
#         current_app.logger.error(f"Unexpected error during reset with token: {e}")
#         flash('An unexpected error occurred. Please try again.', 'danger')

#     return redirect(url_for('auth.login'))


@bp.route('/reset_account', methods=['GET', 'POST'])
def reset_account():
    """
    Handle requests for resetting passwords.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    login_form = LoginForm()
    register_form = RegisterForm()
    reset_password_form = ResetPasswordForm()

    if reset_password_form.validate_on_submit():
        user = User.query.filter_by(email=reset_password_form.email.data).first()

        if user:
            try:
                # Reset user account fields
                user.temp_password = None
                user.temp_password_expiration = None
                user.is_verified = False
                user.is_deactivated = False  # Reactivate the account
                user.is_active = True
                db.session.commit()

                # Log activity
                try:
                    log_login_activity(
                        user=user,
                        success=True,
                        reason="Password reset initiated",
                        activity_type="Login"
                    )
                except Exception as e:
                    db.session.rollback()
                    current_app.logger.error(f"Error logging activity during password reset: {e}")
                    flash('An error occurred while logging activity. Please try again later.', 'danger')
                    return redirect(url_for('auth.login'))

                # Create notification for account reset
                try:
                    NotificationManager.send_data_reset_request_notification(user)
                except Exception as e:
                    current_app.logger.error(f"Error creating notification: {e}")
                    flash('An error occurred while notifying the user. Please try again later.', 'danger')
                    return redirect(url_for('auth.login'))

                # Send reset email
                send_reset_email(user)
                flash('A password reset email has been sent. Please check your inbox.', 'success')
                return redirect(url_for('auth.login'))

            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error during password reset: {e}")
                flash('An error occurred while processing your request. Please try again later.', 'danger')
        else:
            flash('No account found with that email address.', 'danger')

    return render_template(
        'login.html',
        login_form=login_form,
        register_form=register_form,
        reset_password_form=reset_password_form,
        form_type='reset_account'
    )


@bp.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    """
    Handle password resets via token link.
    """
    try:
        # Verify token
        email = User.verify_verification_token(token)
        user = User.query.filter_by(email=email, verification_token=token).first()

        if not user:
            flash('Invalid or expired reset link.', 'danger')
            return redirect(url_for('auth.login'))

        # Log activity
        try:
            log_login_activity(
                user=user,
                success=True,
                reason="Password reset token verified",
                activity_type="Login"
            )
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error logging activity for token reset: {e}")
            flash('An error occurred while logging activity. Please try again later.', 'danger')
            return redirect(url_for('auth.login'))

        # Auto-login and redirect to password change
        login_user(user)
        flash('Set a new strong password to recover your account.', 'success')
        return redirect(url_for('user.change_password'))

    except (BadSignature, SignatureExpired) as e:
        current_app.logger.error(f"Token verification error: {e}")
        flash('Invalid or expired reset link.', 'danger')
    except Exception as e:
        current_app.logger.error(f"Unexpected error during reset with token: {e}")
        flash('An unexpected error occurred. Please try again.', 'danger')

    return redirect(url_for('auth.login'))

# @bp.route('/logout')
# @login_required
# def logout():
#     """
#     Logs out the user and records the logout activity.
#     Updates the user's status and clears the session.
#     """
#     if current_user.is_authenticated:
#         try:
#             # Record logout activity
#             try:
#                 ip_address = request.remote_addr
#                 city, country = get_location(ip_address)  # Unpack the tuple into city and country
#                 city = city or 'Unknown'
#                 country = country or 'Unknown'
#                 logout_activity = LoginActivity(
#                     user_id=current_user.id,
#                     ip_address=ip_address,
#                     user_agent=request.user_agent.string,
#                     successful_login=False,
#                     city=city,
#                     country=country,
#                     status='logout'
#                 )
#                 db.session.add(logout_activity)
#                 db.session.commit()  # Commit logout activity
#             except Exception as e:
#                 db.session.rollback()  # Rollback if there's an error while logging activity
#                 current_app.logger.error(f"Error during logout activity logging: {e}")
#                 flash('An error occurred while logging your logout activity. Please try again.', 'danger')
#                 return redirect(url_for('main.index'))

#             # Update user's online status
#             try:
#                 current_user.is_online = False
#                 current_user.last_login = datetime.utcnow()  # Optionally record the last logout time
#                 db.session.commit()  # Commit status update
#             except Exception as e:
#                 db.session.rollback()  # Rollback if there's an error while updating the status
#                 current_app.logger.error(f"Error during status update: {e}")
#                 flash('An error occurred while updating your status. Please try again.', 'danger')
#                 return redirect(url_for('main.index'))

#             # Log the user out of the session
#             try:
#                 logout_user()
#                 session.pop('user_id', None)
#             except Exception as e:
#                 current_app.logger.error(f"Error during session logout: {e}")
#                 flash('An error occurred while logging you out. Please try again.', 'danger')
#                 return redirect(url_for('main.index'))

#             flash('You have been logged out successfully.', 'success')
#             return redirect(url_for('main.index'))

#         except Exception as e:
#             db.session.rollback()  # Rollback any changes in case of a top-level error
#             current_app.logger.error(f"Unexpected error during logout: {e}")
#             flash(f'Error during logout: {e}', 'danger')
#             return redirect(url_for('main.index'))
    
#     # If no user is authenticated, redirect to login page
#     flash('You are not logged in.', 'warning')
#     return redirect(url_for('auth.login'))


@bp.route('/logout')
@login_required
def logout():
    """
    Logs out the user and records the logout activity.
    Updates the user's status and clears the session.
    """
    if not current_user.is_authenticated:
        flash('You are not logged in.', 'warning')
        return redirect(url_for('auth.login'))

    try:
        # Log the logout activity
        log_logout_activity()

        # Update user's online status
        update_user_status()

        # Perform the logout
        logout_user_and_clear_session()

        flash('You have been logged out successfully.', 'success')
        return redirect(url_for('main.index'))

    except Exception as e:
        current_app.logger.error(f"Unexpected error during logout: {e}")
        db.session.rollback()  # Rollback any changes
        flash(f'Error during logout: {e}', 'danger')
        return redirect(url_for('main.index'))