# extensions.py

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth
from flask import current_app
from redis import Redis
import redis
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
mail = Mail()
bcrypt = Bcrypt()
oauth = OAuth()
# redis_client = None  # Placeholder for Redis instance
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)
# Initialize the Limiter instance globally
limiter = Limiter(key_func=get_remote_address, default_limits=["10 per minute"])

def initialize_extensions(app):
    global redis_client  # Ensure global is properly set up
    redis_client = Redis(
        host=app.config['REDIS_HOST'],
        port=app.config['REDIS_PORT'],
        db=app.config['REDIS_DB'],
        password=app.config.get('REDIS_PASSWORD'),
    )
    app.config['SESSION_REDIS'] = redis_client  # Assign Redis client
    # Create the Limiter object and specify Redis as storage
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[app.config['RATE_LIMIT_DEFAULT']],
        storage_uri=f"redis://{app.config['REDIS_HOST']}:{app.config['REDIS_PORT']}/{app.config['REDIS_DB']}"
    )
    limiter.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    bcrypt.init_app(app)
    oauth.init_app(app)

    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        access_token_url='https://accounts.google.com/o/oauth2/token',
        refresh_token_url=None,
        client_kwargs={'scope': 'openid profile email'},
    )

    oauth.register(
        name='github',
        client_id=app.config['GITHUB_CLIENT_ID'],
        client_secret=app.config['GITHUB_CLIENT_SECRET'],
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        access_token_url='https://github.com/login/oauth/access_token',
        refresh_token_url=None,
        client_kwargs={'scope': 'user'},
    )

    oauth.register(
        name='facebook',
        client_id=app.config['FACEBOOK_CLIENT_ID'],
        client_secret=app.config['FACEBOOK_CLIENT_SECRET'],
        authorize_url='https://www.facebook.com/v12.0/dialog/oauth',
        authorize_params=None,
        access_token_url='https://graph.facebook.com/v12.0/oauth/access_token',
        refresh_token_url=None,
        client_kwargs={'scope': 'email'},
    )


    login_manager.login_view = 'auth.login'
    # login_manager.login_message = "Please log in to access this page."


    from models.user import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))