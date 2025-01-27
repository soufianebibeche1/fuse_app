from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Index, func
from sqlalchemy.orm import relationship
from extensions import db

class UserActivity(db.Model):
    __tablename__ = 'user_activities'

    # Primary Key
    id = db.Column(db.Integer, primary_key=True)

    # Foreign Key linking to User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Action Type and Description
    action_type = Column(String(50), nullable=False)  # E.g., 'login', 'logout', 'post_created', 'comment_added'
    description = Column(String(255), nullable=True)  # Extra details about the action

    # Timestamp for activity occurrence
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    # Relationship with User
    user = relationship('User', back_populates='user_activities', lazy="joined")

    # Index for optimized queries on common fields
    __table_args__ = (
        Index('ix_user_activity_user_action', 'user_id', 'action_type', 'timestamp'),
    )

    def record_activity(self, action_type: str, description: str = None) -> None:
        """
        Record a new activity for the user with validation on action type.
        """
        if len(action_type) > 50:
            raise ValueError("Action type must be 50 characters or fewer.")
        if description and len(description) > 255:
            raise ValueError("Description must be 255 characters or fewer.")
        self.action_type = action_type
        self.description = description
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return (
            f"<UserActivity id={self.id} user_id={self.user_id} action_type={self.action_type} "
            f"timestamp={self.timestamp}>"
        )