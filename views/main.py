from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, current_app
from flask_login import current_user
from forms import LoginForm  # Import your LoginForm
from flask_login import login_required, current_user
from extensions import redis_client
from flask import send_from_directory
import os
from extensions import db, mail, csrf, limiter,oauth
from sqlalchemy.sql import func
from models.user import User
from models.notification import Notification
from models.notificationmanager import NotificationManager, NotificationType
from models.notificationsettings import NotificationSettings
from models.friendship import Friendship, FriendshipStatusEnum
from models.post import Post, PostManager
import random
import json
from datetime import datetime
from flask_wtf.csrf import CSRFError, CSRFProtect
from flask import Blueprint, jsonify, abort
from sqlalchemy import and_, or_
from utils import *
import logging

bp = Blueprint('main', __name__)
app = Flask(__name__)



@bp.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notifications = Notification.query.filter_by(recipient_id=current_user.id).order_by(Notification.created_at.desc()).limit(5).all()
        return dict(notifications=notifications)
    return dict(notifications=[])

@bp.route('/login')
def login_redirect():
    return redirect(url_for('auth.login'))

@bp.route('/sign_up')
def sign_up_redirect():
    return redirect(url_for('auth.sign_up'))

# @bp.route('/')
# def index():
#     # Get the current user's ID
#     user = current_user  # Assuming you're using Flask-Login for user management

#     # Fetch the recent notifications for the current user
#     notifications = NotificationManager.get_widget_notifications(user.id, limit=5)
    
#     # Convert notifications to a list of dictionaries for the template
#     notifications_data = [notification.to_dict() for notification in notifications]
    
#     # Fetch posts for the user and their friends
#     posts = PostManager.fetch_friends_posts(user.id)
#     posts_data = [post.to_dict() for post in posts]  # Convert Post objects to dicts for easy rendering
    
#     return render_template('index.html', user =current_user, posts=posts_data, notifications=notifications_data)

@bp.route('/')
@login_required  # Add this decorator to ensure the user is logged in
def index():
    # Get the current user's ID
    user = current_user  # Assuming you're using Flask-Login for user management

    # Fetch the recent notifications for the current user
    notifications = NotificationManager.get_widget_notifications(user.id, limit=5)
    
    # Convert notifications to a list of dictionaries for the template
    notifications_data = [notification.to_dict() for notification in notifications]
    
    # Fetch posts for the user and their friends
    posts = PostManager.fetch_friends_posts(user.id)
    posts_data = [post.to_dict() for post in posts]  # Convert Post objects to dicts for easy rendering
    
    return render_template('index.html', user=current_user, posts=posts_data, notifications=notifications_data)

@bp.route('/profilepic/<filename>')
def profile_pic(filename):
    # Ensure the file exists in the profile pictures directory
    profile_pics_path = os.path.join(current_app.root_path, 'static', 'uploads', 'prfl')
    return send_from_directory(profile_pics_path, filename)

# Route for serving cover pictures
@bp.route('/coverpic/<filename>')
def cover_pic(filename):
    # Ensure the file exists in the cover pictures directory
    cover_pics_path = os.path.join(current_app.root_path, 'static', 'uploads', 'cvr')
    return send_from_directory(cover_pics_path, filename)

# @bp.route('/profile/<int:user_id>')
# @login_required
# def user_profile(user_id):
#     # Fetch the user by their ID
#     user = User.query.get_or_404(user_id)
    
#     # Render the profile page and pass the user object
#     return render_template('profile.html', user=user)
#     # return "this user name and id " + str(user.id) + " " + user.username


@bp.route('/inbox')
@login_required
def inbox():
    return render_template('messages.html',user=current_user)


@bp.route('/widget_notifications', methods=['GET'])
def fetch_widget_notifications():
    # Ensure the user is authenticated
    if not current_user.is_authenticated:
        return jsonify({'error': 'Unauthorized'}), 401

    # Fetch recent notifications (e.g., limit 5)
    notifications = NotificationManager.get_widget_notifications(current_user.id, limit=5)
    
    # Convert notifications to a JSON-serializable format
    notifications_data = [
        {
            "message": notification.message,
            "created_at": notification.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "actor_name": notification.actor.username if notification.actor else "System",
            "image": notification.actor.get_profile_pic_url() if notification.actor else "/static/default_profile_pic.jpg"
        }
        for notification in notifications
    ]
    
    return jsonify(notifications_data)
    
@bp.route('/notifications', methods=['GET'])
@login_required
def get_notifications():
    """Fetch the recent notifications for the current user."""
    try:
        limit = request.args.get('limit', 3, type=int)  # Fetch 3 notifications by default
        notifications = NotificationManager.get_recent_notifications(user_id=current_user.id, limit=limit)
        return jsonify({"status": "success", "notifications": notifications})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# @bp.route('/suggested_users', methods=['GET'])
# @login_required
# def get_suggested_users():
#     current_user = User.query.get(session['user_id'])  # Replace with your session logic
#     friends = Friendship.get_friends(current_user.id)
#     friend_ids = {friend['id'] for friend in friends}
#     friend_ids.add(current_user.id)  # Exclude the logged-in user
#     friend_ids.add(User.query.filter_by(email='system@example.com').first().id)  # Exclude "system" user

#     # Query 5 random users excluding friends and current user
#     suggestions = User.query.filter(User.id.notin_(friend_ids)).order_by(func.random()).limit(5).all()

#     # Serialize suggestions
#     response = [{'id': user.id, 'username': user.username, 'profilepic': user.get_profile_pic_url(), 'job_title': user.job_title or ""} for user in suggestions]
#     return jsonify(response)

# @bp.route('/toggle_friend_request', methods=['POST'])
# @login_required
# def toggle_friend_request():
#     data = request.json
#     target_user_id = data.get('user_id')
#     current_user = User.query.get(session['user_id'])

#     friendship = Friendship.query.filter_by(user_id=current_user.id, friend_id=target_user_id).first()
#     if friendship:
#         if friendship.status == FriendshipStatusEnum.pending:
#             db.session.delete(friendship)
#             action = "cancelled"
#         else:
#             return jsonify({'error': 'Invalid action'}), 400
#     else:
#         friendship = Friendship(user_id=current_user.id, friend_id=target_user_id, status=FriendshipStatusEnum.pending)
#         db.session.add(friendship)
#         action = "requested"

#     db.session.commit()
#     return jsonify({'status': 'success', 'action': action})

@bp.errorhandler(400)
def bad_request_error(e):
    return jsonify({'status': 'error', 'message': 'Bad Request'}), 400

@bp.before_request
def log_csrf_token():
    print(f"CSRF Token from Request Headers: {request.headers.get('X-CSRFToken')}")

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({"message": "CSRF token missing or incorrect"}), 400


# INDEX RANDOM:

# @bp.route('/get_random_users', methods=['GET'])
# def get_random_users():
#     current_user_id = request.args.get('current_user_id')
#     page = request.args.get('page', 1, type=int)
#     per_page = request.args.get('per_page', 5, type=int)

#     # Fetch the system user
#     system_user = User.query.filter_by(email="system@example.com").first()
#     if not system_user:
#         return jsonify([])

#     # Get the current user
#     current_user = User.query.get(current_user_id)
#     if not current_user:
#         return jsonify([])

#     # Get the current user's friends (accepted friendships)
#     friendships = Friendship.query.filter(
#         ((Friendship.user_id == current_user_id) | (Friendship.friend_id == current_user_id)) &
#         (Friendship.status == FriendshipStatusEnum.accepted)
#     ).all()
#     friend_ids = {f.friend_id if f.user_id == current_user_id else f.user_id for f in friendships}

#     # Fetch users who are not friends, not the system user, and not the current user
#     users = User.query.filter(
#         User.id != system_user.id,
#         User.id != current_user_id,
#         ~User.id.in_(friend_ids)
#     ).paginate(page=page, per_page=per_page, error_out=False)

#     # Prepare the response
#     user_list = [{
#         'id': user.id,
#         'username': user.username,
#         'profile_pic': user.get_profile_pic_url(),
#         'job_title': user.job_title if user.job_title else user.hobbies  # Use hobbies if job_title is null
#     } for user in users.items]

#     return jsonify(user_list)

@bp.route('/get_random_users', methods=['GET'])
def get_random_users():
    current_user_id = request.args.get('current_user_id')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 5, type=int)

    # Fetch the system user
    system_user = User.query.filter_by(email="system@example.com").first()
    if not system_user:
        return jsonify([])

    # Get the current user
    current_user = User.query.get(current_user_id)
    if not current_user:
        return jsonify([])

    # Get the current user's friends (accepted friendships)
    accepted_friendships = Friendship.query.filter(
        ((Friendship.user_id == current_user_id) | (Friendship.friend_id == current_user_id)) &
        (Friendship.status == FriendshipStatusEnum.accepted)
    ).all()
    accepted_friend_ids = {f.friend_id if f.user_id == current_user_id else f.user_id for f in accepted_friendships}

    # Get users who have sent pending friend requests to the current user
    pending_friendships = Friendship.query.filter(
        Friendship.friend_id == current_user_id,
        Friendship.status == FriendshipStatusEnum.pending
    ).all()
    pending_friend_ids = {f.user_id for f in pending_friendships}

    # Get users to whom the current user has sent pending friend requests
    sent_friendships = Friendship.query.filter(
        Friendship.user_id == current_user_id,
        Friendship.status == FriendshipStatusEnum.pending
    ).all()
    sent_friend_ids = {f.friend_id for f in sent_friendships}

    # Combine all excluded user IDs
    excluded_user_ids = accepted_friend_ids.union(pending_friend_ids, sent_friend_ids, {system_user.id, current_user_id})

    # Fetch users who are not in the excluded list
    users = User.query.filter(
        ~User.id.in_(excluded_user_ids)
    ).paginate(page=page, per_page=per_page, error_out=False)

    # Prepare the response
    user_list = [{
        'id': user.id,
        'username': user.username,
        'profile_pic': user.get_profile_pic_url(),
        'job_title': user.job_title if user.job_title else user.hobbies  # Use hobbies if job_title is null
    } for user in users.items]

    return jsonify(user_list)

@bp.route('/send_friend_request', methods=['POST'])
def send_friend_request():
    data = request.get_json()
    user_id = data.get('user_id')
    friend_id = data.get('friend_id')

    # Check if a friend request already exists
    existing_request = Friendship.query.filter_by(user_id=user_id, friend_id=friend_id).first()
    if existing_request:
        return jsonify({'status': 'error', 'message': 'Friend request already sent.'}), 400

    # Create a new friend request
    friendship = Friendship(user_id=user_id, friend_id=friend_id, status=FriendshipStatusEnum.pending)
    db.session.add(friendship)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Friend request sent successfully.'})

@bp.route('/cancel_friend_request', methods=['POST'])
def cancel_friend_request():
    data = request.get_json()
    user_id = data.get('user_id')
    friend_id = data.get('friend_id')

    # Find and delete the friend request
    friendship = Friendship.query.filter_by(user_id=user_id, friend_id=friend_id).first()
    if friendship:
        db.session.delete(friendship)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Friend request cancelled successfully.'})
    else:
        return jsonify({'status': 'error', 'message': 'Friend request not found.'}), 404
    

    # FRIENDS ZONE
@bp.route('/api/fetch_friends', methods=['GET'])
def fetch_friends():
    user_id = current_user.id  # Get the current user's ID
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 5, type=int)

    # Fetch accepted friendships for the current user
    friendships = Friendship.query.filter(
        ((Friendship.user_id == user_id) | (Friendship.friend_id == user_id)) &
        (Friendship.status == FriendshipStatusEnum.accepted)
    ).paginate(page=page, per_page=per_page, error_out=False)

    # Prepare the list of friends
    friends = []
    for f in friendships.items:
        friend = f.friend if f.user_id == user_id else f.user
        friends.append({
            "id": friend.id,
            "username": friend.username,
            "profile_pic": friend.get_profile_pic_url(),
            "mutual_count": User.query.get(user_id).get_mutual_friends(friend)
        })

    return jsonify({
        "friends": friends,
        "total_pages": friendships.pages,
        "current_page": friendships.page
    })

@bp.route('/api/manage_friend', methods=['POST'])
def manage_friend():
    data = request.get_json()
    friend_id = data.get('friend_id')
    action = data.get('action')
    user_id = current_user.id  # Get the current user's ID

    if action == 'remove':
        friendship = Friendship.query.filter(
            ((Friendship.user_id == user_id) & (Friendship.friend_id == friend_id)) |
            ((Friendship.user_id == friend_id) & (Friendship.friend_id == user_id))
        ).first()
        if friendship:
            db.session.delete(friendship)
            db.session.commit()
            return jsonify({"message": "Friend removed successfully"})
        else:
            return jsonify({"error": "Friendship not found"}), 404

    elif action == 'resend':
        friendship = Friendship(user_id=user_id, friend_id=friend_id, status=FriendshipStatusEnum.pending)
        db.session.add(friendship)
        db.session.commit()
        return jsonify({"message": "Friend request sent successfully"})

    return jsonify({"error": "Invalid action"}), 400

@bp.route('/friends/all')
@login_required
def all_friends():
    # Fetch all accepted friends for the current user
    friends = Friendship.get_friends(current_user.id)
    return render_template('friends_list.html', friends=friends)

@bp.route('/accounts/suggestions')
@login_required
def may_liked_accounts():
    # Get all users except the current user and system user
    all_accounts = User.query.filter(User.email != 'system@example.com', User.id != current_user.id).all()

    # Get the list of friends for the current user
    friends = {friend.id for friend in current_user.get_friends()}

    # Filter the accounts to exclude friends
    accounts_to_display = [account for account in all_accounts if account.id not in friends]

    return render_template('mayliked_accounts_list.html', liked_accounts=accounts_to_display)

# FRIENDS PAGE

@bp.route('/friends')
@login_required
def friends():
    user = current_user  # Replace with the actual user ID (e.g., from session or request)
    friends_count = len(Friendship.get_friends(user.id))  # Get the count of friends
    # Get the count of accepted friends
    friends_count = Friendship.query.filter(and_(or_(Friendship.user_id == user.id, Friendship.friend_id == user.id),Friendship.status == FriendshipStatusEnum.accepted)).count()
    
    if not user:
        return "User not found", 404
    return render_template('friends.html', user=user, friends_count=friends_count)


@bp.route('/get_friends', methods=['GET'])
@login_required
def get_friends():
    # Get the logged-in user's ID
    user_id = current_user.id  # Assuming `current_user` is provided by Flask-Login

    # Fetch accepted friends for the logged-in user
    accepted_friends = Friendship.query.filter(
        ((Friendship.user_id == user_id) | (Friendship.friend_id == user_id)) &
        (Friendship.status == FriendshipStatusEnum.accepted)
    ).all()

    # Format the response
    friends = []
    for friendship in accepted_friends:
        # Determine which user is the friend (the one who is not the logged-in user)
        friend = friendship.friend if friendship.user_id == user_id else friendship.user
        friends.append({
            "id": friend.id,
            "username": friend.username,
            "profile_pic": friend.get_profile_pic_url(),
            "job_title": friend.job_title,
            "mutual_count": current_user.get_mutual_friends(friend)  # Optional: Include mutual friends count
        })

    return jsonify({"friends": friends})


@bp.route('/get_pending_requests', methods=['GET'])
@login_required
def get_pending_requests():
    # Get the logged-in user's ID
    user_id = current_user.id  # Assuming `current_user` is provided by Flask-Login

    # Fetch pending friend requests that the logged-in user has sent
    pending_requests_sent = Friendship.query.filter_by(
        user_id=user_id, status=FriendshipStatusEnum.pending
    ).all()

    # Format the response
    requests_sent = [{
        "id": req.id,
        "friend_id": req.friend_id,
        "friend_username": req.friend.username,
        "friend_profile_pic": req.friend.get_profile_pic_url(),
        "created_at": req.created_at.isoformat() if req.created_at else None
    } for req in pending_requests_sent]

    return jsonify({"requests_sent": requests_sent})


# My Profile Page

@bp.route('/user/<encoded_user_id>', methods=['GET'], endpoint='profile')
def profile(encoded_user_id):
    """Fetch and display user profile."""
    try:
        # Decode the user ID
        user_id = decode_user_id(encoded_user_id)
        if not user_id:
            logging.error(f"Invalid encoded user ID: {encoded_user_id}")
            abort(404)  # Invalid ID

        # Fetch the user or raise 404 if not found
        user = User.query.filter_by(id=user_id).first_or_404()

        # Fetch the user's friends
        friends = Friendship.get_friends_limited(user_id, limit=12)  # Fetch up to 12 friends

        # Fetch the user's posts (shared by the user)
        user_posts = Post.query.filter_by(user_id=user_id).order_by(Post.created_at.desc()).limit(6).all() 

        # Render the profile template with the user data
        return render_template('profile.html', user=user, friends=friends, posts=user_posts)

    except Exception as e:
        # Log the exception and return a 500 error
        logging.error(f"Error fetching profile for user ID {encoded_user_id}: {e}")
        abort(500)

@bp.route('/post/<int:post_id>', methods=['GET'], endpoint='post')
def view_post(post_id):
    """Fetch and display a single post."""
    try:
        # Fetch the post or raise 404 if not found
        post = Post.query.filter_by(id=post_id).first_or_404()

        # Render the post template with the post data
        return render_template('post.html', post=post)

    except Exception as e:
        # Log the exception and return a 500 error
        logging.error(f"Error fetching post with ID {post_id}: {e}")
        abort(500)

@bp.route('/api/profile_info')
@login_required
def profile_info():
    # Fetch the logged-in user's profile info
    user = current_user
    profile_info = {
        'username': user.username,
        'firstname': user.firstname,
        'lastname': user.lastname,
        'profile_pic': user.get_profile_pic_url(),
        'cover_pic': user.get_cover_pic_url(),
        'bio': user.bio,
        'job_title': user.job_title,
        'hobbies': user.hobbies
    }
    return jsonify(profile_info)



@bp.route('/api/posts')
@login_required
def posts():
    # Fetch the logged-in user's posts
    posts = PostManager.fetch_friends_posts(current_user.id)
    posts_data = [{
        'id': post.id,
        'caption': post.caption,
        'media_urls': [media.media_url for media in post.media],
        'created_at': post.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'likes_count': len(post.likes),
        'comments_count': len(post.comments)
    } for post in posts]
    return jsonify(posts_data)


#####

@bp.route('/reset_account')
def reset_account_redirect():
    return redirect(url_for('auth.reset_account'))

@bp.route('/about')
def about():
    return render_template('about.html')


@bp.route('/account_settings')
@login_required
def account_settings():
    # Fetch notifications for the current user
    notifications = get_notifications(current_user.id)
    print(notifications)  # Debugging: Print notifications to the console
    return render_template('accountsettings.html', notifications=notifications)








@bp.route('/photos')
def photos():
    return render_template('photos.html')

# @bp.route('/profile')
# def profile():
#     return render_template('profile.html')

@bp.route('/profiles')
def profiles():
    return render_template('profiles.html')


## SEARCH
@bp.route('/search', methods=['GET'])
def search_profiles():
    search_query = request.args.get('query', '')  # Get the search query from the request
    if search_query:
        # Perform a case-insensitive search for users whose username, firstname, or lastname contains the query
        results = User.query.filter(
            (User.username.ilike(f'%{search_query}%')) |
            (User.firstname.ilike(f'%{search_query}%')) |
            (User.lastname.ilike(f'%{search_query}%'))
        ).all()
        
        # Convert the results to a list of dictionaries
        search_results = [{
            'id': user.id,
            'username': user.username,
            'firstname': user.firstname,
            'lastname': user.lastname,
            'profilepic': user.profilepic,
            'job_title': user.job_title
        } for user in results]
        
        return jsonify(search_results)
    return jsonify([])