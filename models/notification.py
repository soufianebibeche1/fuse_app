from datetime import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime, Enum, Index
from sqlalchemy.orm import relationship
from enum import Enum as PyEnum
from extensions import db

# Enum for notification types
class NotificationType(PyEnum):
    ACCOUNT_CREATED = "ACCOUNT_CREATED"
    ACCOUNT_VERIFIED = "ACCOUNT_VERIFIED"
    FRIEND_REQUEST = "FRIEND_REQUEST"
    BIRTHDAY_REMINDER = "BIRTHDAY_REMINDER"
    FRIEND_REQUEST_ACCEPTED = "FRIEND_REQUEST_ACCEPTED"
    POST_LIKED = "POST_LIKED"
    COMMENT_ADDED = "COMMENT_ADDED"
    ACCOUNT_RESET = "ACCOUNT_RESET"
    DATA_RESET_REQUEST = "DATA_RESET_REQUEST"

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = Column(Integer, primary_key=True)
    recipient_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    actor_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=True)
    type = Column(Enum(NotificationType), nullable=False)
    message = Column(String(500), nullable=False)  # Increased to 500 characters
    is_read = Column(Boolean, default=False)  # Read/unread status
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="notifications")
    actor = relationship("User", foreign_keys=[actor_id])

    # Index for faster queries
    __table_args__ = (
        Index('ix_notifications_recipient_is_read', 'recipient_id', 'is_read'),
        Index('ix_notifications_recipient_created_at', 'recipient_id', 'created_at')  # Optimized for recent notifications
    )

    def __init__(self, recipient_id, type, message, actor_id=None):
        if not isinstance(type, NotificationType):
            raise ValueError(f"Invalid notification type: {type}")
        self.recipient_id = recipient_id
        self.type = type
        self.message = message
        self.actor_id = actor_id

    def mark_as_read(self):
        """Mark the notification as read."""
        self.is_read = True

    def to_dict(self):
        """Convert notification to a dictionary."""
        return {
            "id": self.id,
            "type": self.type.value,
            "message": self.message,
            "is_read": self.is_read,
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "image": self.actor.get_profile_pic_url(),
            "actor_name": f"{self.actor.username}" if self.actor else "Fuse"
        }

    def __repr__(self):
        return f"<Notification {self.type} to User {self.recipient_id}>"