from sqlalchemy import Column, Integer, String, Enum, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship
from extensions import db
import enum

class MediaTypeEnum(enum.Enum):
    image = 'image'
    video = 'video'

class Media(db.Model):
    __tablename__ = 'media'

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False, index=True)
    media_url = db.Column(db.String(255), nullable=False)
    media_type = db.Column(db.Enum(MediaTypeEnum), nullable=False)  # image or video
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    post = db.relationship('Post', back_populates='media')

    def __repr__(self):
        return f'<Media {self.media_url}>'
