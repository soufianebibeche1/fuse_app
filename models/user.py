from sqlalchemy import (
    Column, Integer, String, DateTime, Enum, Boolean, CheckConstraint, Text,
    ForeignKey, Index, UniqueConstraint, func
)
from sqlalchemy.orm import validates, relationship
from flask_login import UserMixin
from extensions import db, bcrypt, mail
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import enum
import os
from flask_mail import Message
from flask import current_app, request
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import random
import logging
from models.notification import Notification
from models.friendship import Friendship, FriendshipStatusEnum


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Default images
DEFAULT_PROFILE_PIC = "default_profile_pic.jpg"
DEFAULT_COVER_PIC = "default_cover_pic.jpg"

class GenderEnum(enum.Enum):
    male = 'Male'
    female = 'Female'
    other = 'Other'

    @classmethod
    def choices(cls):
        return [(gender.name, gender.value) for gender in cls]

    @classmethod
    def get_value(cls, gender):
        if isinstance(gender, cls):
            return gender.value
        return cls[gender.lower()].value if isinstance(gender, str) else None

# Enum for Auth Providers
class AuthProviderEnum(enum.Enum):
    local = 'Local'
    facebook = 'Facebook'
    google = 'Google'
    github = 'Github'


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    # Basic User Information
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    firstname = Column(String(50), nullable=True)
    lastname = Column(String(50), nullable=True)
    phone = Column(String(15), nullable=True)
    password_hash = Column(String(255), nullable=True)
    role = Column(String(50), default='user')
    
    # Personal Details
    gender = Column(Enum(GenderEnum), nullable=False)
    age = Column(Integer, CheckConstraint('age >= 16 AND age <= 66'), nullable=True)
    country = Column(String(50), nullable=True)
    city = Column(String(50), nullable=True)
    address = Column(String(100), nullable=True)
    profilepic = Column(String(256), nullable=True, default=DEFAULT_PROFILE_PIC)
    coverpic = Column(String(256), nullable=True, default=DEFAULT_COVER_PIC)
    bio = Column(String(256), nullable=True)
    job_title = Column(String(100), nullable=True)
    hobbies = Column(String(256), nullable=True)
    
    # Account Status and Options
    is_active = Column(Boolean, default=True, index=True)
    is_deactivated = Column(Boolean, default=False, index=True)
    email_option_out = Column(Boolean, default=False)
    is_online = Column(Boolean, default=False, index=True)
    is_verified = Column(Boolean, default=False, index=True)
    
    # Password and Authentication
    temp_password = Column(String(255), nullable=True)
    verification_token = Column(String(255), nullable=True)
    temp_password_expiration = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    lockout_until = Column(DateTime, nullable=True)
    
    # Two-Factor Authentication
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_backup_code = Column(String(10), nullable=True)

    # Social Media OAuth
    auth_provider = Column(Enum(AuthProviderEnum), default=AuthProviderEnum.local)
    social_id = Column(String(255), nullable=True, unique=True)
    access_token = Column(String(255), nullable=True)
    refresh_token = Column(String(255), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime, nullable=True)
    last_login = db.Column(db.DateTime)

    # New fields
    explanation = db.Column(Text, nullable=True)  # Reason for deactivation
    email_option_out = db.Column(Boolean, default=False)  # Email opt-out flag


    # Relationships
    posts = db.relationship('Post', back_populates='user')
    login_activities = db.relationship(
        'LoginActivity', 
        back_populates='user', 
        cascade='all, delete-orphan', 
        lazy='dynamic'
    )
    user_activities = db.relationship('UserActivity', back_populates='user')
    # Add this relationship for notifications
    notifications = relationship(
        'Notification',
        back_populates='recipient',
        foreign_keys='Notification.recipient_id'  # Explicitly specify the foreign key
    )
    notification_settings = relationship('NotificationSettings', back_populates='user')
    likes = db.relationship('Like', back_populates='user', cascade='all, delete-orphan')
    comments = db.relationship('Comment', back_populates='user', cascade='all, delete-orphan')

    # Index for commonly queried fields
    __table_args__ = (
        Index('ix_user_verification', 'is_verified', 'is_active'),
    )

    def __init__(self, email, username, firstname, lastname, gender, age, country, role='user'):
        """
        Custom __init__ method to handle default values and additional logic.
        """
        self.email = email
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.role = role

        # Handle gender assignment, ensuring it's a valid value from GenderEnum
        if isinstance(gender, GenderEnum):
            self.gender = gender  # If gender is already an instance of GenderEnum, assign directly
        else:
            try:
                self.gender = GenderEnum[gender.lower()]  # Convert string to GenderEnum
            except KeyError:
                self.gender = None  # Set to None if the gender value is invalid
        self.age = age
        self.country = country

        # Default profile and cover pictures
        self.profilepic = DEFAULT_PROFILE_PIC
        self.coverpic = DEFAULT_COVER_PIC

        # Optional fields with default values
        self.is_verified = False
        self.is_active = True
        self.is_deactivated = False
        self.is_online = False
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.last_login = datetime.utcnow()
        self.email_option_out = False

    def set_profile_pic(self, filename):
        """Sets the profile picture filename for the user."""
        self.profilepic = filename if filename else DEFAULT_PROFILE_PIC

    def set_cover_pic(self, filename):
        """Sets the cover picture filename for the user."""
        self.coverpic = filename if filename else DEFAULT_COVER_PIC

    def get_profile_pic_url(self):
        """Returns the full URL or path to the profile picture."""
        base_path = "/static/uploads/profile_pics/"
        return f"{base_path}{self.profilepic}"

    def get_cover_pic_url(self):
        """Returns the full URL or path to the cover picture."""
        base_path = "/static/uploads/cover_pics/"
        return f"{base_path}{self.coverpic}"

    def set_password(self, password):
        """Sets the hashed password for the user."""
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """Verifies the user's password."""
        return check_password_hash(self.password_hash, password)
    
    def verify_temp_password(self, temp_password):
        """
        Verifies the provided temporary password against the stored hashed password.
        
        :param temp_password: The plain-text temporary password to verify.
        :return: True if the password is correct, otherwise False.
        """
        return check_password_hash(self.temp_password, temp_password)

    def generate_verification_token(self, email):
        """Generates a token for email verification."""
        serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
        return serializer.dumps(email, salt=os.getenv('SECURITY_PASSWORD_SALT'))

    @staticmethod
    def verify_verification_token(token, expiration=3600):
        """
        Verifies the email verification token.
        Args:
            token (str): The token to verify.
            expiration (int): Token expiration time in seconds.
        Returns:
            str: The email if token is valid.
        Raises:
            ValueError: If token is invalid or expired.
        """
        serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
        try:
            email = serializer.loads(
                token,
                salt=os.getenv('SECURITY_PASSWORD_SALT'),
                max_age=expiration
            )
            return email
        except SignatureExpired:
            raise ValueError("The token has expired.")
        except BadSignature:
            raise ValueError("The token signature is invalid.")
        except Exception as e:
            raise ValueError(f"An unexpected error occurred: {e}")

    def generate_temp_password(self):
        """Generate a temporary password (you can customize this logic)."""
        temp_password = os.urandom(8).hex()
        self.temp_password = generate_password_hash(temp_password)
        return temp_password

    @staticmethod
    def get_serializer():
        """Returns a URLSafeTimedSerializer instance."""
        return URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'profilepic': self.profilepic,
            'coverpic': self.coverpic
        }
    
    def send_friend_request(self, friend):
        """Send a friend request to another user."""
        friendship = Friendship(user_id=self.id, friend_id=friend.id, status=FriendshipStatusEnum.pending)
        db.session.add(friendship)
        db.session.commit()

    def accept_friend_request(self, friend):
        """Accept a friend request."""
        friendship = Friendship.query.filter_by(user_id=friend.id, friend_id=self.id, status=FriendshipStatusEnum.pending).first()
        if friendship:
            friendship.status = FriendshipStatusEnum.accepted
            db.session.commit()

    def reject_friend_request(self, friend):
        """Reject a friend request."""
        friendship = Friendship.query.filter_by(user_id=friend.id, friend_id=self.id, status=FriendshipStatusEnum.pending).first()
        if friendship:
            friendship.status = FriendshipStatusEnum.rejected
            db.session.commit()

    def get_friends(self):
        """Get all accepted friends for the user."""
        friends = Friendship.query.filter(
            ((Friendship.user_id == self.id) | (Friendship.friend_id == self.id)) & 
            (Friendship.status == FriendshipStatusEnum.accepted)
        ).all()
        return [f.friend if f.user_id == self.id else f.user for f in friends]

    def get_friends_with_mutual_count(self):
        """Get all friends along with mutual friends count and friendship status."""
        friends = self.get_friends()
        for friend in friends:
            friend.mutual_count = self.get_mutual_friends(friend)
            friend.is_friend = True  # Add this property for easy button state management
        return friends
    
    def get_mutual_friends(self, other_user):
        """Get mutual friends count between self and another user."""
        my_friends = {friend.id for friend in self.get_friends()}
        other_friends = {friend.id for friend in other_user.get_friends()}
        mutual_friends = my_friends.intersection(other_friends)
        return len(mutual_friends)
    

    def __repr__(self):
        return f'<User {self.username}>'