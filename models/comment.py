# models/comment.py

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship
from extensions import db

class Comment(db.Model):
    __tablename__ = 'comments'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    post_id = Column(Integer, ForeignKey('posts.id', ondelete='CASCADE'), nullable=False, index=True)
    text = Column(String(500), nullable=False)  # Comment text
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship('User', back_populates='comments')
    post = relationship('Post', back_populates='comments')

    def __repr__(self):
        return f'<Comment user_id={self.user_id}, post_id={self.post_id}, text={self.text[:20]}>'