from sqlalchemy import ForeignKey, Column, Integer, DateTime, Enum, Boolean, func
from sqlalchemy.orm import relationship
from extensions import db
import enum

class FriendshipStatusEnum(enum.Enum):
    pending = "pending"
    accepted = "accepted"
    rejected = "rejected"

class Friendship(db.Model):
    __tablename__ = 'friendships'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    friend_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    status = Column(Enum(FriendshipStatusEnum), default=FriendshipStatusEnum.pending)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User", foreign_keys=[user_id], backref="initiated_friendships")
    friend = relationship("User", foreign_keys=[friend_id], backref="received_friendships")

    
    # @staticmethod
    # def get_pending_friend_requests(user_id):
    #     pending_requests = Friendship.query.filter_by(
    #         friend_id=user_id, status=FriendshipStatusEnum.pending
    #     ).all()
    #     return [{
    #         "id": req.id,
    #         "username": req.user.username,
    #         "profile_pic": req.user.get_profile_pic_url(),
    #         "job_title": req.user.job_title
    #     } for req in pending_requests]
    
    @staticmethod
    def get_pending_friend_requests(user_id, page=1, per_page=6):
        pending_requests = Friendship.query.filter_by(
            friend_id=user_id, status=FriendshipStatusEnum.pending
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        return {
            "requests": [{
                "id": req.id,
                "username": req.user.username,
                "profile_pic": req.user.get_profile_pic_url(),
                "job_title": req.user.job_title
            } for req in pending_requests.items],
            "total_pages": pending_requests.pages,
            "current_page": pending_requests.page
        }
    
    @classmethod
    def get_allpending_friend_requests(cls, user_id):
        from models.user import User
        pending_requests = (
            db.session.query(User)
            .join(Friendship, User.id == Friendship.user_id)
            .filter(Friendship.friend_id == user_id, Friendship.status == FriendshipStatusEnum.pending)
            .all()
        )
        return [
            {
                "username": request.username,
                "profile_pic": request.get_profile_pic_url(),
                "id": request.id
            }
            for request in pending_requests
        ]
    
    @staticmethod
    def get_friends(user_id):
        """Fetch all accepted friends for a user."""
        friendships = Friendship.query.filter(
            ((Friendship.user_id == user_id) | (Friendship.friend_id == user_id)) &
            (Friendship.status == FriendshipStatusEnum.accepted)
        ).all()
        return [{
            "id": friend.id,
            "username": friend.username,
            "profile_pic": friend.get_profile_pic_url(),
            "job_title": friend.job_title
        } for f in friendships for friend in [f.friend if f.user_id == user_id else f.user]]
    
    @staticmethod
    def get_friends_limited(user_id, limit=4):
        """Fetch up to `limit` accepted friends for a user."""
        # Lazy import to avoid circular dependency
        from models.user import User

        # Fetch friendships involving the user
        friendships = Friendship.query.filter(
            ((Friendship.user_id == user_id) | (Friendship.friend_id == user_id)) &
            (Friendship.status == FriendshipStatusEnum.accepted)
        ).limit(limit).all()

        # Get the current user object
        user = User.query.get(user_id)
        if not user:
            return []

        # Construct the result with mutual friend counts
        return [{
            "id": friend.id,
            "username": friend.username,
            "profile_pic": friend.get_profile_pic_url(),
            "job_title": friend.job_title,
            "mutual_count": user.get_mutual_friends(friend)  # Calculate mutual friends
        } for f in friendships for friend in [f.friend if f.user_id == user_id else f.user]]