from extensions import db
from models.notification import Notification, NotificationType
from models.user import User, GenderEnum
from flask import current_app
from sqlalchemy.orm.exc import NoResultFound
from flask import current_app
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import ProgrammingError
from sqlalchemy import text
from datetime import datetime

def create_system_user_if_not_exists():
    """
    Creates a system user with predefined credentials if it does not already exist.
    """
    try:
        with current_app.app_context():
            with db.engine.connect() as connection:
                connection.execute(text("SELECT 1 FROM users LIMIT 1"))

            system_user = User.query.filter_by(email="system@example.com").first()

            if not system_user:
                system_user = User(
                    email="system@example.com",
                    username="Fuse",
                    firstname="Fuse",
                    lastname="Fuse",
                    gender=GenderEnum.other,
                    age=30,
                    country="N/A",
                    role="admin",
                    is_active=True
                )
                system_user.set_password("SecureSystemPassword123")  # Replace with a strong password
                system_user.set_profile_pic("default_sysprofile_pic.jpg")
                system_user.set_cover_pic("default_syscover_pic.png")
                system_user.is_verified = True
                system_user.is_active = True
                system_user.is_admin = True
                db.session.add(system_user)
                db.session.commit()
                current_app.logger.info("System user created successfully.")
            else:
                current_app.logger.info("System user already exists. No action taken.")
            
            return system_user  # Return the system user

    except ProgrammingError as e:
        current_app.logger.error("Users table does not exist. Ensure migrations are applied: %s", str(e))
    except OperationalError as e:
        current_app.logger.error("Database connection issue: %s", str(e))
    except Exception as e:
        current_app.logger.error("An unexpected error occurred: %s", str(e))
    return None

class NotificationManager:
    @staticmethod
    def create_notification(recipient_id, type, message, actor_id=None):
        """Create and save a notification."""
        system_user = create_system_user_if_not_exists()  # Ensure system user exists
        if actor_id is None:
            if system_user:
                actor_id = system_user.id  # Use system user for system-generated notifications
            else:
                raise ValueError("System user could not be created or retrieved.")
        
        notification = Notification(
            recipient_id=recipient_id,
            actor_id=actor_id,
            type=type,
            message=message
        )
        db.session.add(notification)
        db.session.commit()
        return notification

    # #
    # Function to send account creation notification
    def send_account_creation_notification(user):
        """Notification sent by system to user on account creation."""
        message = f"Welcome {user.firstname}! Your account has been successfully created."
        NotificationManager.create_notification(
            recipient_id=user.id,
            type=NotificationType.ACCOUNT_CREATED,
            message=message,
            actor_id=None  # System user
        )


    # Function to send account verification notification
    def send_account_verified_notification(user):
        """Notification sent by system to user when account is verified."""
        message = f"Congratulations {user.firstname}, your account has been verified!"
        NotificationManager.create_notification(
            recipient_id=user.id,
            type=NotificationType.ACCOUNT_VERIFIED,
            message=message,
            actor_id=None  # System user
        )


    # Function to send friend request notification
    def send_friend_request_notification(recipient_id, actor_id):
        """Notification sent to recipient when a friend request is sent."""
        recipient = User.query.get(recipient_id)
        actor = User.query.get(actor_id)
        message = f"{actor.firstname} {actor.lastname} has sent you a friend request."
        NotificationManager.create_notification(
            recipient_id=recipient_id,
            type=NotificationType.FRIEND_REQUEST,
            message=message,
            actor_id=actor_id
        )


    # Function to send birthday reminder notification
    def send_birthday_reminder(user):
        """Notification sent by system to user every birthday."""
        message = f"Happy Birthday {user.firstname}! Wishing you a great year ahead!"
        NotificationManager.create_notification(
            recipient_id=user.id,
            type=NotificationType.BIRTHDAY_REMINDER,
            message=message,
            actor_id=None  # System user
        )


    # Function to send friend request accepted notification
    def send_friend_request_accepted_notification(recipient_id, actor_id):
        """Notification sent to the user when their friend request is accepted."""
        recipient = User.query.get(recipient_id)
        actor = User.query.get(actor_id)
        message = f"Your friend request to {recipient.firstname} {recipient.lastname} has been accepted!"
        NotificationManager.create_notification(
            recipient_id=actor_id,
            type=NotificationType.FRIEND_REQUEST_ACCEPTED,
            message=message,
            actor_id=actor_id
        )

    def get_notifications(user_id, limit=10):
        """
        Fetch notifications for a user.
        :param user_id: ID of the user.
        :param limit: Number of notifications to fetch.
        :return: List of notifications.
        """
        notifications = NotificationManager.get_widget_notifications(user_id, limit)
        return [notification.to_dict() for notification in notifications]

    # Function to send post liked notification
    def send_post_liked_notification(post, user):
        """Notification sent to user when their post is liked."""
        message = f"{user.firstname} {user.lastname} liked your post."
        NotificationManager.create_notification(
            recipient_id=post.user_id,  # The post owner
            type=NotificationType.POST_LIKED,
            message=message,
            actor_id=user.id  # User who liked the post
        )


    # Function to send comment added notification
    def send_comment_added_notification(post, comment, user):
        """Notification sent to user when a comment is added to their post."""
        message = f"{user.firstname} {user.lastname} commented on your post: {comment.text}"
        NotificationManager.create_notification(
            recipient_id=post.user_id,  # The post owner
            type=NotificationType.COMMENT_ADDED,
            message=message,
            actor_id=user.id  # User who commented
        )
    
    def send_data_reset_request_notification(user):
        """Notification sent by system to admin when a user requests a data reset."""
        # Prepare the message
        message = f"User {user.firstname} {user.lastname} (ID: {user.id}) has requested a data reset."

        # Send the notification to the system admin (or another admin role)
        system_user = create_system_user_if_not_exists()  # Ensure system user exists
        if system_user:
            NotificationManager.create_notification(
                recipient_id=system_user.id,  # System user or admin
                type=NotificationType.DATA_RESET_REQUEST,  # Assuming you have an enum for this type
                message=message,
                actor_id=user.id  # The user who requested the reset
            )
        else:
            current_app.logger.error("System user could not be created or retrieved. Notification not sent.")

    def send_account_reset_notification(user):
        """Notification sent by system to user when their account info or password is reset."""
        message = f"Hello {user.firstname}, your account information has been successfully updated."
        NotificationManager.create_notification(
            recipient_id=user.id,
            type=NotificationType.ACCOUNT_RESET,
            message=message,
            actor_id=None
        )

    @staticmethod
    def get_recent_notifications(user_id, limit=3):
        """
        Fetch the most recent notifications for a user.
        :param user_id: ID of the recipient user.
        :param limit: Number of notifications to fetch.
        :return: List of recent notifications.
        """
        notifications = (
            Notification.query
            .filter_by(recipient_id=user_id)
            .order_by(Notification.created_at.desc())
            .limit(limit)
            .all()
        )
        return [notification.to_dict() for notification in notifications]
    
    # @staticmethod
    # def get_widget_notifications(user_id, limit=5):
    #     """
    #     Fetch the most recent notifications for a user.
    #     :param user_id: ID of the recipient user.
    #     :param limit: Number of notifications to fetch.
    #     :return: List of recent notifications.
    #     """
    #     notifications = (
    #         Notification.query
    #         .filter_by(recipient_id=user_id)
    #         .order_by(Notification.created_at.desc())
    #         .limit(limit)
    #         .all()
    #     )
    #     return [notification.to_dict() for notification in notifications]

    @staticmethod
    def get_widget_notifications(user_id, limit=5):
        """
        Fetch the most recent notifications for a user.
        :param user_id: ID of the recipient user.
        :param limit: Number of notifications to fetch.
        :return: List of recent notifications.
        """
        notifications = (
            Notification.query
            .filter_by(recipient_id=user_id)
            .order_by(Notification.created_at.desc())
            .limit(limit)
            .all()
        )
        return notifications  # Return model instances, not dictionaries.

    @staticmethod
    def notify_friends_of_new_post(user_id, post_id):
        """Notify user's friends about a new post."""
        user = User.query.get(user_id)
        friends = user.get_friends()

        for friend in friends:
            message = f"{user.firstname} has created a new post!"
            NotificationManager.create_notification(
                recipient_id=friend.id,
                type=NotificationType.POST_LIKED,
                message=message,
                actor_id=user_id
            )