from sqlalchemy import (
    Column, Integer, String, ForeignKey, DateTime, Enum, Index, func
)
from sqlalchemy.orm import relationship, validates
from extensions import db
import enum
import logging
from datetime import datetime
import json
from models.friendship import Friendship, FriendshipStatusEnum
from sqlalchemy.orm import joinedload
from models.like import Like

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    caption = db.Column(db.String(550), nullable=True)
    # media_urls = db.Column(db.Text, nullable=True)  # Store JSON array of media URLs
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=func.now())
    likes_count = db.Column(db.Integer, default=0)  # Add this field
    
    user = relationship('User', back_populates='posts', lazy="joined")
    media = db.relationship('Media', back_populates='post', cascade='all, delete-orphan')
    likes = db.relationship('Like', back_populates='post', cascade='all, delete-orphan')
    comments = db.relationship('Comment', back_populates='post', cascade='all, delete-orphan')

    def to_dict(self):
        # Fetch media URLs from the Media model
        media_urls = [media.media_url for media in self.media]
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username,  # Include the username
            "profile_pic": self.user.get_profile_pic_url(),  # Include the profile picture URL
            "caption": self.caption,
            "media_urls": media_urls,  # Use the media URLs from the Media model
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "likes_count": len(self.likes),
            "comments_count": len(self.comments),
        }


class PostManager:

    @staticmethod
    def fetch_friends_posts(user_id, limit=20, page=1):
        """Fetch posts from the user and their friends."""
        from models.friendship import Friendship, FriendshipStatusEnum
        from models.post import Post

        # Get friends' IDs
        friendships = Friendship.query.filter(
            ((Friendship.user_id == user_id) | (Friendship.friend_id == user_id)) &
            (Friendship.status == FriendshipStatusEnum.accepted)
        ).all()

        friend_ids = [f.friend_id if f.user_id == user_id else f.user_id for f in friendships]

        # Include the user's own ID
        relevant_ids = friend_ids + [user_id]

        # Fetch posts from user and their friends
        posts = Post.query.filter(
            Post.user_id.in_(relevant_ids)
        ).options(joinedload(Post.media), joinedload(Post.user)).order_by(Post.created_at.desc()).paginate(page=page, per_page=limit, error_out=False)

        return posts.items  # Return list of Post objects