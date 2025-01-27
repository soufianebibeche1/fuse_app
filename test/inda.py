from werkzeug.security import generate_password_hash
import secrets

password = 'password1'  # Replace this with the actual password
hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
print(hashed_password)
print('test')
print(secrets.token_hex(16))  # Generates a 32-character hexadecimal string
