# seed.py
from extensions import db
from models.user import User
from models.post import Post

def seed():
    # Example: Creating sample users and posts
    user1 = User(username="sampleuser", email="user@example.com", password="password")
    post1 = Post(content="Hello, this is a sample post!", user_id=user1.id)

    db.session.add(user1)
    db.session.add(post1)
    db.session.commit()

if __name__ == "__main__":
    db.create_all()  # Ensure database tables exist
    seed()