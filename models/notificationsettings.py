from sqlalchemy import Column, Integer, ForeignKey, Boolean
from extensions import db
from sqlalchemy.orm import relationship

class NotificationSettings(db.Model):
    __tablename__ = 'notification_settings'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    email_notifications = Column(Boolean, default=True)  # Email notifications
    push_notifications = Column(Boolean, default=True)  # Push notifications
    friend_request_notifications = Column(Boolean, default=True)  # Friend request notifications
    comment_notifications = Column(Boolean, default=True)  # Comment notifications
    like_notifications = Column(Boolean, default=True)  # Post like notifications
    birthday_notifications = Column(Boolean, default=True)  # Birthday reminders

    user = relationship("User", back_populates="notification_settings", uselist=False)

    def to_dict(self):
        """Convert notification settings to a dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email_notifications": self.email_notifications,
            "push_notifications": self.push_notifications,
            "friend_request_notifications": self.friend_request_notifications,
            "comment_notifications": self.comment_notifications,
            "like_notifications": self.like_notifications,
            "birthday_notifications": self.birthday_notifications,
        }

    def __repr__(self):
        return f"<NotificationSettings for User {self.user_id}>"