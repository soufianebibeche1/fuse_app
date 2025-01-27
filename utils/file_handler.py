import os
import random
import string
from werkzeug.utils import secure_filename

def ensure_upload_folders(app):
    """Ensure that the required folders for uploads exist."""
    os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['COVER_PICS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['POST_MEDIA_FOLDER'], exist_ok=True)  # New folder for post media

def allowed_file(filename, app):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_random_filename(extension):
    """Generate a random filename to avoid naming conflicts."""
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    return f'{random_string}.{extension}'

def handle_file_upload(file, file_type, app):
    """
    Handle the file upload process for profile, cover, or post media.
    :param file: The uploaded file object.
    :param file_type: Either 'profile', 'cover', or 'post_media' to indicate file type.
    :param app: The Flask app instance for accessing config values.
    :return: The filename of the saved file.
    """
    if file and allowed_file(file.filename, app):
        # Ensure upload folders exist
        ensure_upload_folders(app)

        # Secure filename and generate a random one
        filename = secure_filename(file.filename)
        extension = filename.rsplit('.', 1)[1].lower()
        new_filename = generate_random_filename(extension)

        # Determine the target folder
        if file_type == 'profile':
            target_folder = app.config['PROFILE_PICS_FOLDER']
        elif file_type == 'cover':
            target_folder = app.config['COVER_PICS_FOLDER']
        elif file_type == 'post_media':  # New logic for post media
            target_folder = app.config['POST_MEDIA_FOLDER']
        else:
            raise ValueError("Invalid file type. Must be 'profile', 'cover', or 'post_media'.")

        # Save file to the correct folder
        file_path = os.path.join(target_folder, new_filename)
        file.save(file_path)

        # Return just the filename (e.g., "xqTssQc8Bg.jpg")
        return new_filename
    else:
        raise ValueError("Invalid file or unsupported file type.")
