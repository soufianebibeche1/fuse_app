from functools import wraps
from flask_login import current_user
from flask import redirect, url_for, flash, request, jsonify
import time

def require_password(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.temp_password:  # Check if the user has a temporary password
            flash('Please set your password before proceeding.', 'danger')
            return redirect(url_for('user.change_password'))  # Redirect to change password route
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(limit, per):
    def decorator(f):
        cache = {}

        @wraps(f)
        def wrapped(*args, **kwargs):
            user_ip = request.remote_addr
            current_time = time.time()

            if user_ip not in cache:
                cache[user_ip] = []

            cache[user_ip] = [timestamp for timestamp in cache[user_ip] if current_time - timestamp < per]

            if len(cache[user_ip]) >= limit:
                return jsonify({'error': 'Too many requests, please try again later.'}), 429

            cache[user_ip].append(current_time)
            return f(*args, **kwargs)

        return wrapped
    return decorator