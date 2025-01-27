from flask import Blueprint, request, jsonify
from models.post import Post,PostManager
from models.media import Media
from extensions import db
from utils import *
import os
import json
from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, current_app
from flask_login import login_user, login_required, logout_user, current_user
from models.notification import Notification,NotificationType
from models.notificationmanager import NotificationManager
from models.notificationsettings import NotificationSettings
from models.like import Like
from models.comment import Comment
from models.user import User
from flask import send_from_directory
import logging

bp = Blueprint('post', __name__)

@bp.route('/posts')
def posts():
    return "Posts Page"

@bp.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notifications = Notification.query.filter_by(recipient_id=current_user.id).order_by(Notification.created_at.desc()).limit(5).all()
        return dict(notifications=notifications)
    return dict(notifications=[])

# Add more routes related to posts here


# Route to share a post
# @bp.route('/share_post', methods=['POST'])
# def share_post():
#     user_id = current_user.id  # Get the logged-in user's ID
#     caption = request.form.get('caption')
#     media_files = request.files.getlist('files[]')  # List of media files

#     try:
#         # Save the media files using the file handler
#         media_urls = []
#         for media in media_files:
#             file_path = handle_file_upload(media, 'post_media', current_app)  # Store file path
#             media_urls.append(file_path)

#         # Create a new post in the database
#         new_post = Post(
#             user_id=user_id,
#             caption=caption,
#             media_urls=json.dumps(media_urls)  # Save the media URLs as a JSON string
#         )
#         db.session.add(new_post)
#         db.session.commit()

#         # Notify the user's friends about the new post
#         NotificationManager.notify_friends_of_new_post(user_id, new_post.id)

#         # Flash a success message
#         flash('Post shared successfully!', 'success')

#         return jsonify({
#             'status': 'success',
#             'post_id': new_post.id
#         })

#     except Exception as e:
#         # Flash an error message
#         flash('An error occurred while sharing your post. Please try again.', 'error')
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500


@bp.route('/uploads/post_media/<path:filename>')
def uploaded_post_media(filename):
    return send_from_directory(current_app.config['POST_MEDIA_FOLDER'], filename)

@bp.route('/share_post', methods=['POST'])
def share_post():
    user_id = current_user.id  # Get the logged-in user's ID
    caption = request.form.get('caption')
    media_files = request.files.getlist('files[]')  # List of media files

    try:
        # Save the media files using the file handler
        media_urls = []
        for media in media_files:
            file_path = handle_file_upload(media, 'post_media', current_app)  # Store file path
            media_urls.append(file_path)

        # Create a new post in the database
        new_post = Post(
            user_id=user_id,
            caption=caption,
        )
        db.session.add(new_post)
        db.session.commit()

        # Save media files in the Media model
        for media_url in media_urls:
            media = Media(
                post_id=new_post.id,
                media_url=media_url,
                media_type='image' if media_url.split('.')[-1] in ['png', 'jpg', 'jpeg', 'gif'] else 'video'
            )
            db.session.add(media)
        db.session.commit()

        # Notify the user's friends about the new post
        NotificationManager.notify_friends_of_new_post(user_id, new_post.id)

        # Flash a success message
        flash('Post shared successfully!', 'success')

        return jsonify({
            'status': 'success',
            'post_id': new_post.id
        })

    except Exception as e:
        # Flash an error message
        flash('An error occurred while sharing your post. Please try again.', 'error')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500



# Route to fetch posts from the user's feed and friends' feeds
# @bp.route('/fetch_feed', methods=['GET'])
# def fetch_feed():
#     user_id = current_user.id  # Get the logged-in user's ID
#     page = request.args.get('page', 1, type=int)  # Page number for pagination

#     # Fetch posts from the user's friends and the user
#     posts = PostManager.fetch_friends_posts(user_id, page=page)

#     # If no posts found, return a message
#     if not posts:
#         return jsonify({'message': 'No more posts available.'}), 200

#     posts_data = []
#     for post in posts:
#         posts_data.append({
#             'id': post.id,
#             'user_id': post.user_id,
#             'username': post.user.username,
#             'profile_pic': post.user.get_profile_pic_url(),
#             'caption': post.caption,
#             'media_urls': post.media_urls,  # Assuming this stores URLs of the media
#             'created_at': post.created_at.strftime('%Y-%m-%d %H:%M:%S'),
#             'likes_count': len(post.likes),
#             'comments_count': len(post.comments),
#         })

#     return jsonify(posts_data)

@bp.route('/fetch_feed', methods=['GET'])
def fetch_feed():
    user_id = current_user.id  # Get the logged-in user's ID
    page = request.args.get('page', 1, type=int)  # Page number for pagination

    # Fetch posts from the user's friends and the user
    posts = PostManager.fetch_friends_posts(user_id, page=page)

    # If no posts found, return a message
    if not posts:
        return jsonify({'message': 'No more posts available.'}), 200

    posts_data = []
    for post in posts:
        post_dict = post.to_dict()
        # Construct full URLs for media files
        post_dict['media_urls'] = [url_for('post.uploaded_post_media', filename=media_url) for media_url in post_dict['media_urls']]
        posts_data.append(post_dict)

    return jsonify(posts_data)

# @bp.route('/like', methods=['POST'])
# def like_post():
#     data = request.get_json()
#     user_id = data.get('user_id')
#     post_id = data.get('post_id')

#     # Check if the like already exists
#     like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()

#     if like:
#         # Unlike the post
#         db.session.delete(like)
#         db.session.commit()
#         # Update likes count
#         post = Post.query.get(post_id)
#         post.likes_count -= 1
#         db.session.commit()
#         return jsonify({'status': 'unliked', 'likes_count': post.likes_count})
#     else:
#         # Like the post
#         new_like = Like(user_id=user_id, post_id=post_id)
#         db.session.add(new_like)
#         db.session.commit()
#         # Update likes count
#         post = Post.query.get(post_id)
#         post.likes_count += 1
#         db.session.commit()
#         return jsonify({'status': 'liked', 'likes_count': post.likes_count})

# @bp.route('/like', methods=['POST'])
# def like_post():
#     data = request.get_json()
#     if not data:
#         logging.error("No data provided in the request")
#         return jsonify({'error': 'No data provided'}), 400

#     user_id = data.get('user_id')
#     post_id = data.get('post_id')

#     if not user_id or not post_id:
#         logging.error(f"Missing user_id or post_id: user_id={user_id}, post_id={post_id}")
#         return jsonify({'error': 'Missing user_id or post_id'}), 400

#     try:
#         # Check if the post exists
#         post = Post.query.get(post_id)
#         if not post:
#             logging.error(f"Post not found: post_id={post_id}")
#             return jsonify({'error': 'Post not found'}), 404

#         # Ensure likes_count is not None
#         if post.likes_count is None:
#             logging.warning(f"likes_count was None for post_id={post_id}. Setting it to 0.")
#             post.likes_count = 0

#         like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()

#         if like:
#             # Unlike the post
#             db.session.delete(like)
#             db.session.commit()
#             # Update likes count
#             post.likes_count -= 1
#             db.session.commit()
#             logging.info(f"Post unliked: post_id={post_id}, user_id={user_id}, likes_count={post.likes_count}")
#             return jsonify({'status': 'unliked', 'likes_count': post.likes_count})
#         else:
#             # Like the post
#             new_like = Like(user_id=user_id, post_id=post_id)
#             db.session.add(new_like)
#             db.session.commit()
#             # Update likes count
#             post.likes_count += 1
#             db.session.commit()
#             logging.info(f"Post liked: post_id={post_id}, user_id={user_id}, likes_count={post.likes_count}")
#             return jsonify({'status': 'liked', 'likes_count': post.likes_count})
#     except Exception as e:
#         db.session.rollback()
#         logging.error(f"Error in like_post: {str(e)}")
#         return jsonify({'error': str(e)}), 500

@bp.route('/like', methods=['POST'])
def like_post():
    data = request.get_json()
    if not data:
        logging.error("No data provided in the request")
        return jsonify({'error': 'No data provided'}), 400

    user_id = data.get('user_id')
    post_id = data.get('post_id')

    if not user_id or not post_id:
        logging.error(f"Missing user_id or post_id: user_id={user_id}, post_id={post_id}")
        return jsonify({'error': 'Missing user_id or post_id'}), 400

    try:
        # Check if the post exists
        post = Post.query.get(post_id)
        if not post:
            logging.error(f"Post not found: post_id={post_id}")
            return jsonify({'error': 'Post not found'}), 404

        # Ensure likes_count is not None
        if post.likes_count is None:
            logging.warning(f"likes_count was None for post_id={post_id}. Setting it to 0.")
            post.likes_count = 0

        # Check if the like already exists
        like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()

        if like:
            # Unlike the post
            db.session.delete(like)
            db.session.commit()
            # Update likes count (ensure it doesn't go below 0)
            post.likes_count = max(0, post.likes_count - 1)  # Ensure likes_count doesn't go below 0
            db.session.commit()
            logging.info(f"Post unliked: post_id={post_id}, user_id={user_id}, likes_count={post.likes_count}")
            return jsonify({'status': 'unliked', 'likes_count': post.likes_count})
        else:
            # Like the post
            new_like = Like(user_id=user_id, post_id=post_id)
            db.session.add(new_like)
            db.session.commit()
            # Update likes count
            post.likes_count += 1
            db.session.commit()
            logging.info(f"Post liked: post_id={post_id}, user_id={user_id}, likes_count={post.likes_count}")
            return jsonify({'status': 'liked', 'likes_count': post.likes_count})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in like_post: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route to comment on a post
# TO NEXT VERSION
# @bp.route('/post/comment', methods=['POST'])
# def comment_on_post():
#     post_id = request.json.get('post_id')
#     comment_text = request.json.get('comment_text')

#     post = Post.query.get(post_id)
#     if not post:
#         return jsonify({'message': 'Post not found'}), 404

#     # Add new comment
#     new_comment = Comment(user_id=current_user.id, post_id=post_id, text=comment_text)
#     db.session.add(new_comment)
#     db.session.commit()

#     # Update comment count in the post object
#     post.comments_count = len(post.comments) + 1
#     db.session.commit()

#     return jsonify({'comments_count': post.comments_count})

# TO NEXT VERSION
# @bp.route('/post/share', methods=['POST'])
# def share_post():
#     post_id = request.json.get('post_id')
#     post = Post.query.get(post_id)
#     if not post:
#         return jsonify({'message': 'Post not found'}), 404

#     # Placeholder action for sharing the post
#     # You can implement actual sharing logic here, such as logging shares or notifying others

#     return jsonify({'message': 'Post shared successfully'})