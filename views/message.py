from flask import Blueprint

bp = Blueprint('message', __name__)

@bp.route('/message')
def message():
    return "Message Page"



# Add other routes and logic here