from extensions import db
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Boolean, Index, func, Enum as SQLAlchemyEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ActivityType(enum.Enum):
    LOGIN = "Login"
    LOGOUT = "Logout"

# Enum for Login Status
class LoginStatus(enum.Enum):
    SUCCESS = "Success"
    FAILED = "Failed"
    SUSPICIOUS = "Suspicious"
    ACCOUNT_LOCKED = "Account Locked"

class LoginActivity(db.Model):
    __tablename__ = 'login_activities'

    # Primary Key
    id = db.Column(db.Integer, primary_key=True)

    # Foreign Key linking to User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Login Details
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 compatible
    user_agent = db.Column(db.String(255), nullable=True)
    device_type = db.Column(db.String(50), nullable=True)  # E.g., Mobile, Desktop, Tablet
    operating_system = db.Column(db.String(50), nullable=True)  # E.g., Windows, iOS, Android
    browser = db.Column(db.String(50), nullable=True)  # E.g., Chrome, Safari
    activity_type = db.Column(SQLAlchemyEnum(ActivityType), nullable=False)  # New field for type

    # Authentication Details
    auth_method = db.Column(db.String(50), nullable=True)  # Password, OAuth, Two-Factor
    login_time = db.Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    logout_time = db.Column(DateTime(timezone=True), nullable=True)
    session_duration = db.Column(db.Integer, nullable=True)  # Duration in seconds
    successful_login = db.Column(db.Boolean, default=True, nullable=False)
    status = db.Column(SQLAlchemyEnum(LoginStatus), default=LoginStatus.FAILED, nullable=False)

    # Security and Analytics
    failure_reason = db.Column(db.String(255), nullable=True)  # E.g., Incorrect Password
    city = db.Column(db.String(100), nullable=True)  # Geolocation data
    country = db.Column(db.String(100), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    isp = db.Column(db.String(100), nullable=True)  # Internet Service Provider
    organization = db.Column(db.String(100), nullable=True)  # Organization from IP data
    login_source = db.Column(db.String(50), nullable=True)  # Web, Mobile, API

    # Flags for Enhanced Security
    suspicious_activity = db.Column(db.Boolean, default=False)  # Marked suspicious by system
    is_audited = db.Column(db.Boolean, default=False)  # Indicates if reviewed by admin/moderator

    # Relationship to User model
    user = relationship('User', back_populates='login_activities', lazy="joined")

    # Index for efficient querying
    __table_args__ = (
        Index('ix_login_user_time', 'user_id', 'login_time'),
        Index('ix_login_status', 'status'),
        Index('ix_activity_type', 'activity_type'),
    )

    def __init__(self, user_id, ip_address, user_agent, successful_login, activity_type, **kwargs):
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.successful_login = successful_login
        self.activity_type = activity_type

        # Optional fields with default values
        self.device_type = kwargs.get("device_type", "Unknown")
        self.operating_system = kwargs.get("operating_system", "Unknown")
        self.browser = kwargs.get("browser", "Unknown")
        self.auth_method = kwargs.get("auth_method", "Unknown")
        self.city = kwargs.get("city", "Unknown")
        self.country = kwargs.get("country", "Unknown")
        self.latitude = kwargs.get("latitude")
        self.longitude = kwargs.get("longitude")
        self.isp = kwargs.get("isp", "Unknown")
        self.organization = kwargs.get("organization", "Unknown")
        self.login_source = kwargs.get("login_source", "Unknown")
        self.failure_reason = kwargs.get("failure_reason")
        self.suspicious_activity = kwargs.get("suspicious_activity", False)

    def mark_logout(self):
        """
        Marks the logout time and calculates the session duration.
        """
        self.logout_time = datetime.utcnow()
        if self.login_time:
            self.session_duration = (self.logout_time - self.login_time).total_seconds()
        db.session.commit()
        logger.info(f"User {self.user_id} logged out. Session duration: {self.session_duration}s.")

    def log_activity(self):
        """
        Logs the login activity for auditing.
        """
        status = "successful" if self.successful_login else "failed"
        logger.info(
            f"User {self.user_id} login attempt at {self.login_time}. "
            f"IP: {self.ip_address}, Status: {status}, Suspicious: {self.suspicious_activity}."
        )

    def flag_suspicious(self):
        """
        Flags the login activity as suspicious.
        """
        self.suspicious_activity = True
        db.session.commit()
        logger.warning(f"Suspicious login activity flagged for User {self.user_id} at {self.login_time}.")

    def to_dict(self):
        """
        Returns a dictionary representation of the login activity.
        """
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "activity_type": self.activity_type.value,
            "login_time": self.login_time,
            "logout_time": self.logout_time,
            "session_duration": self.session_duration,
            "successful_login": self.successful_login,
            "status": self.status.value,
            "auth_method": self.auth_method,
            "device_type": self.device_type,
            "operating_system": self.operating_system,
            "browser": self.browser,
            "city": self.city,
            "country": self.country,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "isp": self.isp,
            "organization": self.organization,
            "suspicious_activity": self.suspicious_activity,
            "login_source": self.login_source,
        }
    
    def __repr__(self):
        return (
            f"<LoginActivity user_id={self.user_id}, activity_type={self.activity_type}, "
            f"login_time={self.login_time}, ip_address={self.ip_address}, status={self.status}, "
            f"suspicious={self.suspicious_activity}>"
        )


    