from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, login_required, logout_user, current_user
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Optional  
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db, mail, csrf, limiter,oauth
from models.user import User, GenderEnum
from models.login_activity import LoginActivity, LoginStatus, ActivityType
from models.notification import Notification
from models.notificationsettings import NotificationSettings
from models.notificationmanager import NotificationManager
from views.auth_heplpers import logout_other_sessions, send_verification_email, send_reset_email, log_logout_activity, update_user_status, logout_user_and_clear_session, log_login_activity, handle_failed_login, handle_successful_login
from forms import LoginForm, RegisterForm, ResetPasswordForm, PasswordForm, AccountForm, DeactivateAccountForm
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime, timedelta
from flask_mail import Message
import os
from flask import current_app, request
from decorators import require_password, rate_limit
from views.auth_heplpers import logout_other_sessions, send_verification_email, send_reset_email
from flask_limiter import Limiter
from sqlalchemy.exc import SQLAlchemyError
import logging
from utils import *
from sqlalchemy import desc
from flask_wtf.csrf import CSRFError, CSRFProtect
import json
import random
import string
import uuid
from flask import send_from_directory
from models.friendship import Friendship, FriendshipStatusEnum



from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, current_app
from flask_login import current_user
from flask_login import login_required, current_user
from extensions import redis_client
from sqlalchemy.sql import func
from models.notificationmanager import NotificationManager, NotificationType
from models.post import Post, PostManager
from flask import Blueprint, jsonify, abort
from sqlalchemy import and_, or_




bp = Blueprint('user', __name__)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@bp.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notifications = Notification.query.filter_by(recipient_id=current_user.id).order_by(Notification.created_at.desc()).limit(5).all()
        return dict(notifications=notifications)
    return dict(notifications=[])

@bp.route('/user')
def user():
    return "User Page"

@bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    Handles password change functionality:
    - New users set a password for the first time.
    - Existing users must confirm their current password.
    """

    # Initialize forms
    changepassword_form = PasswordForm()
    accountinfo_form = AccountForm()
    deactivateacc_form = DeactivateAccountForm()

    user = current_user

    if not user.is_authenticated:
        return redirect(url_for('auth.login'))

    is_new_user = not user.password_hash or not user.is_verified

    # New User Workflow
    if is_new_user:
        changepassword_form.old_password.validators = []  # Remove old password validation for new users
        if changepassword_form.validate_on_submit():
            new_password = changepassword_form.new_password.data
            confirm_password = changepassword_form.confirm_password.data

            if new_password != confirm_password:
                flash('Passwords do not match. Please try again.', 'danger')
                return redirect(url_for('user.change_password'))

            try:
                user.set_password(new_password)
                user.is_verified = True
                user.temp_password = None
                user.updated_at = datetime.utcnow()
                user.temp_password_expiration = None
                user.verification_token = None
                db.session.commit()

                # Log the password set activity
                ip_address = request.remote_addr
                city, country = get_location(ip_address)
                login_activity = LoginActivity(
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=request.user_agent.string,
                    successful_login=True,
                    activity_type=ActivityType.LOGIN,  # Log as a login activity
                    city=city,
                    country=country,
                    status=LoginStatus.SUCCESS  # Log as successful activity
                )
                db.session.add(login_activity)
                db.session.commit()

                # Send notification using NotificationManager
                NotificationManager.send_account_verified_notification(user)

                flash('Password set successfully. Please log in with your new credentials.', 'success')
                return redirect(url_for('auth.logout'))
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error setting password for new user: {e}")
                flash('An error occurred while setting your password. Please try again.', 'danger')

    # Existing User Workflow
    else:
        changepassword_form.old_password.validators = [DataRequired()]  # Require old password
        if changepassword_form.validate_on_submit():
            old_password = changepassword_form.old_password.data
            new_password = changepassword_form.new_password.data
            confirm_password = changepassword_form.confirm_password.data

            if not user.verify_password(old_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('user.change_password'))

            if new_password != confirm_password:
                flash('Passwords do not match. Please try again.', 'danger')
                return redirect(url_for('user.change_password'))

            try:
                user.set_password(new_password)
                user.updated_at = datetime.utcnow()
                user.temp_password = None
                user.temp_password_expiration = None
                user.verification_token = None
                db.session.commit()

                # Log the password change activity
                ip_address = request.remote_addr
                city, country = get_location(ip_address)
                login_activity = LoginActivity(
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=request.user_agent.string,
                    successful_login=True,
                    activity_type=ActivityType.LOGIN,  # Log as a login activity
                    city=city,
                    country=country,
                    status=LoginStatus.SUCCESS  # Log as successful activity
                )
                db.session.add(login_activity)
                db.session.commit()

                # Send notification using NotificationManager
                NotificationManager.send_account_reset_notification(user)

                flash('Password updated successfully.', 'success')
                return redirect(url_for('user.change_password'))
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error updating password: {e}")
                flash('An error occurred while changing your password. Please try again.', 'danger')

    # Render the template with all forms passed in the context
    return render_template(
        'accountsettings.html',
        active_tab='password',
        user=current_user,
        changepassword_form=changepassword_form,
        accountinfo_form=accountinfo_form,
        deactivateacc_form=deactivateacc_form
    )


@bp.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user = User.query.filter_by(id=current_user.id).first()

    changepassword_form = PasswordForm()
    deactivateacc_form = DeactivateAccountForm()

    accountinfo_form = AccountForm(
        username=user.username,
        email=user.email,
        first_name=user.firstname,
        last_name=user.lastname,
        phone=user.phone,
        user_age=user.age,
        gender=user.gender.name if isinstance(user.gender, GenderEnum) else None,
        country=user.country,
    )

    if accountinfo_form.validate_on_submit():
        action = request.form.get('action')

        if action == 'save':
            try:
                # Update user details
                user.username = accountinfo_form.username.data
                user.email = accountinfo_form.email.data
                user.firstname = accountinfo_form.first_name.data
                user.lastname = accountinfo_form.last_name.data
                user.phone = accountinfo_form.phone.data
                user.age = accountinfo_form.user_age.data

                if accountinfo_form.gender.data:
                    user.gender = GenderEnum[accountinfo_form.gender.data.lower()]
                else:
                    user.gender = GenderEnum.other

                user.country = accountinfo_form.country.data

                # Handle profile picture upload
                if accountinfo_form.profile_pic.data:
                    try:
                        profile_pic_path = handle_file_upload(
                            accountinfo_form.profile_pic.data, 'profile', current_app
                        )
                        user.set_profile_pic(profile_pic_path)
                    except ValueError as ve:
                        flash(f"Profile picture error: {ve}", 'danger')

                if accountinfo_form.cover_pic.data:
                    try:
                        cover_pic_path = handle_file_upload(
                            accountinfo_form.cover_pic.data, 'cover', current_app
                        )
                        user.set_cover_pic(cover_pic_path)
                    except ValueError as ve:
                        flash(f"Cover picture error: {ve}", 'danger')

                # Commit the changes
                db.session.commit()
                flash('Your account has been updated!', 'success')
            except Exception as e:
                flash(f"Error updating account: {e}", 'danger')
                db.session.rollback()

            return redirect(url_for('user.account'))

    return render_template(
        'accountsettings.html',
        active_tab='account',
        user=user,
        accountinfo_form=accountinfo_form,
        changepassword_form=changepassword_form,
        deactivateacc_form=deactivateacc_form
    )


@bp.route('/view_notifications', methods=['GET'])
@login_required
def view_notifications():
    """
    Fetch and filter notifications, and render the template with the notifications list.
    Includes pagination and error handling.
    """
    try:
        # Get query parameters
        filter_type = request.args.get('filter', 'all')
        current_page = int(request.args.get('page', 1))  # Defaults to page 1
        notifications_per_page = 14  # Define the number of notifications per page

        # Base query for notifications
        query = Notification.query.filter_by(recipient_id=current_user.id)

        # Apply filtering
        if filter_type == 'read':
            query = query.filter(Notification.is_read.is_(True))
        elif filter_type == 'unread':
            query = query.filter(Notification.is_read.is_(False))
        elif filter_type == 'newest':
            query = query.order_by(Notification.created_at.desc())
        elif filter_type == 'oldest':
            query = query.order_by(Notification.created_at.asc())
        else:
            query = query.order_by(Notification.created_at.desc())

        # Pagination logic
        total_notifications = query.count()
        total_pages = (total_notifications + notifications_per_page - 1) // notifications_per_page
        notifications = query.offset((current_page - 1) * notifications_per_page).limit(notifications_per_page).all()

        # Render template with paginated notifications
        return render_template(
            'accountsettings.html',
            notifications=notifications,
            active_tab='notification',
            current_page=current_page,
            total_pages=total_pages,
            filter=filter_type,
            user=current_user,
            accountinfo_form=AccountForm(),
            changepassword_form=PasswordForm(),
            deactivateacc_form=DeactivateAccountForm()
        )
    except SQLAlchemyError as e:
        current_app.logger.error(f"Database error: {str(e)}")
        return render_template(
            'accountsettings.html',
            notifications=[],
            active_tab='notification',
            error="A database error occurred. Please try again later.",
            current_page=1,
            total_pages=1,
            filter='all',
            user=current_user,
            accountinfo_form=AccountForm(),
            changepassword_form=PasswordForm(),
            deactivateacc_form=DeactivateAccountForm()
        )
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return render_template(
            'accountsettings.html',
            notifications=[],
            active_tab='notification',
            error="An unexpected error occurred. Please try again later.",
            current_page=1,
            total_pages=1,
            filter='all',
            user=current_user,
            accountinfo_form=AccountForm(),
            changepassword_form=PasswordForm(),
            deactivateacc_form=DeactivateAccountForm()
        )


# Route to fetch notifications for AJAX request
@bp.route('/notifications/fetch', methods=['GET'])
@login_required
def fetch_notifications():
    """
    Fetch notifications with pagination for AJAX requests.
    """
    try:
        # Extract query parameters
        filter_type = request.args.get('filter', 'all')
        current_page = int(request.args.get('page', 1))
        notifications_per_page = 14

        # Fetch filtered notifications
        query = Notification.query.filter_by(recipient_id=current_user.id)
        if filter_type == 'read':
            query = query.filter(Notification.is_read.is_(True))
        elif filter_type == 'unread':
            query = query.filter(Notification.is_read.is_(False))
        # Pagination
        total_notifications = query.count()
        total_pages = (total_notifications + notifications_per_page - 1) // notifications_per_page
        notifications = query.offset((current_page - 1) * notifications_per_page).limit(notifications_per_page).all()

        # Render notifications partial HTML
        notifications_html = render_template('partials/notifications_list.html', notifications=notifications)
        return jsonify({
            "success": True,
            "notifications_html": notifications_html,
            "current_page": current_page,
            "total_pages": total_pages
        })
    except Exception as e:
        current_app.logger.error(f"Error fetching notifications: {str(e)}")
        return jsonify({"success": False, "error": "Error fetching notifications."}), 500

@bp.route('/mark_as_read', methods=['POST'])
def mark_as_read():
    try:
        logger.info("Received request to mark notifications as read.")
        data = request.get_json()
        notification_ids = data.get('notification_ids', [])

        if not notification_ids:
            logger.warning("No notification IDs provided.")
            return jsonify({'success': False, 'message': 'No notification IDs provided.'}), 400

        if not all(isinstance(id, int) for id in notification_ids):
            logger.warning("Invalid notification IDs provided.")
            return jsonify({'success': False, 'message': 'Invalid notification IDs provided.'}), 400
        

        # if not notification_ids:
        #     logger.warning("No notification IDs provided.")
        #     return jsonify({'success': False, 'message': 'No notification IDs provided.'}), 400

        # if not all(isinstance(id, int) for id in notification_ids):
        #     logger.warning("Invalid notification IDs provided.")
        #     return jsonify({'success': False, 'message': 'Invalid notification IDs provided.'}), 400

        notifications = Notification.query.filter(Notification.id.in_(notification_ids)).all()

        if not notifications:
            logger.warning("No notifications found for the given IDs.")
            return jsonify({'success': False, 'message': 'No notifications found for the given IDs.'}), 400

        for notification in notifications:
            notification.is_read = True

        db.session.commit()
        logger.info(f"Successfully marked {len(notifications)} notifications as read.")
        return jsonify({'success': True, 'message': 'Notifications marked as read.'})

    except Exception as e:
        logger.error(f"Error marking notifications as read: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@bp.route('/mark_as_unread', methods=['POST'])
def mark_as_unread():
    try:
        logger.info("Received request to mark notifications as unread.")
        data = request.get_json()
        notification_ids = data.get('notification_ids', [])

        if not notification_ids:
            logger.warning("No notification IDs provided.")
            return jsonify({'success': False, 'message': 'No notification IDs provided.'}), 400

        if not all(isinstance(id, int) for id in notification_ids):
            logger.warning("Invalid notification IDs provided.")
            return jsonify({'success': False, 'message': 'Invalid notification IDs provided.'}), 400

        # Query notifications to mark as unread
        notifications = Notification.query.filter(Notification.id.in_(notification_ids)).all()

        if not notifications:
            logger.warning("No notifications found for the given IDs.")
            return jsonify({'success': False, 'message': 'No notifications found for the given IDs.'}), 400

        # Mark notifications as unread
        for notification in notifications:
            notification.is_read = False  # Change is_read to False to mark as unread

        db.session.commit()
        logger.info(f"Successfully marked {len(notifications)} notifications as unread.")
        return jsonify({'success': True, 'message': 'Notifications marked as unread.'})

    except Exception as e:
        logger.error(f"Error marking notifications as unread: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Route to delete notifications
@bp.route('/delete_notifications', methods=['POST'])
def delete_notifications():
    try:
        logger.info("Received request to delete notifications.")
        data = request.get_json()
        notification_ids = data.get('notification_ids', [])

        if not notification_ids:
            logger.warning("No notification IDs provided.")
            return jsonify({'success': False, 'message': 'No notification IDs provided.'}), 400

        if not all(isinstance(id, int) for id in notification_ids):
            logger.warning("Invalid notification IDs provided.")
            return jsonify({'success': False, 'message': 'Invalid notification IDs provided.'}), 400

        # Query notifications to delete
        notifications = Notification.query.filter(Notification.id.in_(notification_ids)).all()

        if not notifications:
            logger.warning("No notifications found for the given IDs.")
            return jsonify({'success': False, 'message': 'No notifications found for the given IDs.'}), 400

        # Delete notifications
        for notification in notifications:
            db.session.delete(notification)

        db.session.commit()
        logger.info(f"Successfully deleted {len(notifications)} notifications.")
        return jsonify({'success': True, 'message': 'Notifications deleted successfully.'})

    except Exception as e:
        logger.error(f"Error deleting notifications: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# This is an example route to handle the filter change for your notifications (optional)
@bp.route('/apply_filter', methods=['GET'])
@login_required
def apply_filter():
    """
    Apply filter for notifications and render the appropriate filtered view.
    """
    filter_type = request.args.get('filter', 'all')
    return redirect(url_for('view_notifications', filter=filter_type))

@bp.route('/fetch_friend_requests', methods=['GET'])
@login_required
def fetch_friend_requests():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 6  # Number of requests per page
        result = Friendship.get_pending_friend_requests(current_user.id, page, per_page)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": True, **result})
        else:
            return render_template(
                'accountsettings.html',
                active_tab='requests',
                user=current_user,
                requests=result['requests'],
                total_pages=result['total_pages'],
                current_page=result['current_page'],
                changepassword_form=PasswordForm(),
                accountinfo_form=AccountForm(),
                deactivateacc_form=DeactivateAccountForm(),
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    
@bp.route('/accept_friend_request/<int:request_id>', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    try:
        friendship = Friendship.query.get(request_id)
        if friendship and friendship.friend_id == current_user.id:
            friendship.status = FriendshipStatusEnum.accepted
            db.session.commit()
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Request not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@bp.route('/reject_friend_request/<int:request_id>', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    try:
        friendship = Friendship.query.get(request_id)
        if friendship and friendship.friend_id == current_user.id:
            friendship.status = FriendshipStatusEnum.rejected
            db.session.commit()
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Request not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

## UPDATE FOR NEW ENHANCED VERSION 
# @bp.route('/security_login', methods=['GET'])
# @login_required
# def security_login():
#     return render_template(
#         'accountsettings.html',
#         active_tab='security_login',  # Set active tab
#         user=current_user
#     )

# @bp.route('/privacy', methods=['GET'])
# @login_required
# def privacy():
#     return render_template(
#         'accountsettings.html',
#         active_tab='privacy',  # Set active tab
#         user=current_user
#     )

# @bp.route('/blocking', methods=['GET'])
# @login_required
# def blocking():
#     return render_template(
#         'accountsettings.html',
#         active_tab='blocking',  # Set active tab
#         user=current_user
#     )

# @bp.route('/deactivate', methods=['GET', 'POST'])
# @login_required
# @require_password
# def deactivate_account():
#     """
#     Deactivates the currently logged-in user's account.
#     Updates the database, logs out the user securely, and clears the session.
#     """
#     # Redirect users with temporary passwords to set a permanent password first
#     if current_user.temp_password:
#         flash('Please set a permanent password before deactivating your account.', 'warning')
#         return redirect(url_for('user.change_password'))

#     # Initialize forms
#     changepassword_form = PasswordForm()
#     accountinfo_form = AccountForm()
#     deactivateacc_form = DeactivateAccountForm()

#     # Handle form submission
#     if deactivateacc_form.validate_on_submit():
#         email = deactivateacc_form.email.data.strip()
#         password = deactivateacc_form.password.data.strip()
#         explanation = deactivateacc_form.explanation.data
#         email_option_out = deactivateacc_form.email_option_out.data

#         # Validate email and password
#         if email != current_user.email:
#             flash('The email entered does not match your account email.', 'danger')
#             return redirect(url_for('main.account_settings'))

#         if not current_user.verify_password(password):
#             flash('Incorrect password. Please try again.', 'danger')
#             return redirect(url_for('main.account_settings'))

#         try:
#             # Update user status
#             current_user.is_active = False
#             current_user.is_deactivated = True
#             current_user.explanation = deactivateacc_form.explanation.data
#             current_user.email_option_out = deactivateacc_form.email_option_out.data
#             current_user.updated_at = datetime.utcnow()

#             # Save deactivation details (if necessary, e.g., logging the explanation)
#             if explanation:
#                 current_app.logger.info(f"User {current_user.id} deactivation explanation: {explanation}")
#             if email_option_out:
#                 current_app.logger.info(f"User {current_user.id} opted out of future emails.")

#             # Commit changes to the database
#             db.session.commit()

#             # Log out the user securely
#             logout_user()
#             session.clear()

#             # Notify user of successful deactivation
#             flash(
#                 'Your account has been successfully deactivated. '
#                 'To reactivate, request a password reset or contact support.', 
#                 'success'
#             )
#             return redirect(url_for('auth.login'))

#         except SQLAlchemyError as e:
#             db.session.rollback()  # Roll back changes if an error occurs
#             current_app.logger.error(f"Error during account deactivation for user {current_user.id}: {e}")
#             flash('An error occurred while deactivating your account. Please try again later.', 'danger')
#             return redirect(url_for('main.account_settings'))

#     # Render the template with all forms passed in the context
#     return render_template(
#         'accountsettings.html',
#         active_tab='deactivate',
#         user=current_user,
#         changepassword_form=changepassword_form,
#         accountinfo_form=accountinfo_form,
#         deactivateacc_form=deactivateacc_form,
#     )


@bp.route('/deactivate', methods=['GET', 'POST'])
@login_required
@require_password
def deactivate_account():
    """
    Deactivates the currently logged-in user's account.
    Updates the database, logs out the user securely, and clears the session.
    """
    # Redirect users with temporary passwords to set a permanent password first
    if current_user.temp_password:
        flash('Please set a permanent password before deactivating your account.', 'warning')
        return redirect(url_for('user.change_password'))

    # Initialize forms
    changepassword_form = PasswordForm()
    accountinfo_form = AccountForm()
    deactivateacc_form = DeactivateAccountForm()

    # Handle form submission
    if deactivateacc_form.validate_on_submit():
        email = deactivateacc_form.email.data.strip()
        password = deactivateacc_form.password.data.strip()
        explanation = deactivateacc_form.explanation.data
        email_option_out = deactivateacc_form.email_option_out.data

        # Validate email
        if email != current_user.email:
            flash('The email entered does not match your account email.', 'danger')
            return render_template(
                'accountsettings.html',
                active_tab='deactivate',
                user=current_user,
                changepassword_form=changepassword_form,
                accountinfo_form=accountinfo_form,
                deactivateacc_form=deactivateacc_form,
            )

        # Validate password
        if not current_user.verify_password(password):
            flash('Incorrect password. Please try again.', 'danger')
            return render_template(
                'accountsettings.html',
                active_tab='deactivate',
                user=current_user,
                changepassword_form=changepassword_form,
                accountinfo_form=accountinfo_form,
                deactivateacc_form=deactivateacc_form,
            )

        try:
            # Start database transaction
            with db.session.begin_nested():
                # Update user status
                current_user.is_active = False
                current_user.is_deactivated = True
                current_user.explanation = explanation
                current_user.email_option_out = email_option_out
                current_user.updated_at = datetime.utcnow()

                # Log explanation and email opt-out
                if explanation:
                    current_app.logger.info(f"User {current_user.id} deactivation explanation: {explanation}")
                if email_option_out:
                    current_app.logger.info(f"User {current_user.id} opted out of future emails.")

                # Commit changes to the database
                db.session.commit()

            # Log out the user securely
            logout_user()
            session.clear()

            # Notify user of successful deactivation
            flash(
                'Your account has been successfully deactivated. '
                'To reactivate, request a password reset or contact support.',
                'success'
            )
            return redirect(url_for('auth.login'))

        except Exception as e:
            # Roll back changes if an error occurs
            db.session.rollback()
            current_app.logger.error(f"Error during account deactivation for user {current_user.id}: {e}")
            flash('An error occurred while deactivating your account. Please try again later.', 'danger')

            return render_template(
                'accountsettings.html',
                active_tab='deactivate',
                user=current_user,
                changepassword_form=changepassword_form,
                accountinfo_form=accountinfo_form,
                deactivateacc_form=deactivateacc_form,
            )

    # Render the template with all forms passed in the context
    return render_template(
        'accountsettings.html',
        active_tab='deactivate',
        user=current_user,
        changepassword_form=changepassword_form,
        accountinfo_form=accountinfo_form,
        deactivateacc_form=deactivateacc_form,
    )