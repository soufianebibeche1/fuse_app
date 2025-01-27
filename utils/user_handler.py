import base64

def encode_user_id(user_id):
    """Encodes the user ID into a URL-safe format."""
    try:
        return base64.urlsafe_b64encode(str(user_id).encode()).decode()
    except Exception as e:
        return None  # Or handle the error as needed

def decode_user_id(encoded_id):
    """Decode a user ID using Base64."""
    try:
        return int(base64.urlsafe_b64decode(encoded_id).decode())
    except (ValueError, TypeError):
        return None