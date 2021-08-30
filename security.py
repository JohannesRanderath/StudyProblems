from flask import url_for
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer

from database import get_user_hash


ts = URLSafeTimedSerializer("b\"\xf5;\xb7\x92\x1f'\xacvT\xf5\xe5x6\xb2\xc4\xe4\"")

# Setting up passlib to hash passwords
# Using argon2 as hashing algorithm
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


def generate_password_hash(password: str):
    """
    Hash password using CryptContext and argon2
    :param password: password to encrypt
    :return: encrypted password
    """
    hashed_pwd = pwd_context.hash(password)
    return hashed_pwd


def verify_password(username: str, password: str):
    """
    Check if given password is correct for user with given username
    :param username: username of account to verify password
    :param password: plain text password to verify
    :return: False if the password is incorrect
    :return: True if the password is correct
    """
    correct_hash = get_user_hash(username)
    if not correct_hash or not pwd_context.verify(password, correct_hash):
        return False
    return True


def generate_email_confirmation_link(email: str, salt: str):
    """
    Generate link to send in email to confirm email address
    :param email: email to verify
    :param salt: function specific salt from app.config
    :return: link to confirm email
    """
    token = ts.dumps(email, salt=salt)
    return url_for('confirm', token=token, _external=True)


def generate_change_email_link(old_email: str, new_email: str, salt: str):
    """
    Generate link to send in email to confirm changed email address
    :param old_email: email saved in database associated with account
    :param new_email: email to verify
    :param salt: function specific salt from app.config
    :return: link to confirm changed email
    """
    token = ts.dumps({"old_email": old_email, "new_email": new_email}, salt=salt)
    return url_for("change_email", token=token, _external=True)


def generate_password_reset_link(username: str, salt: str):
    """
    Generate link to send in email to reset password
    :param username: username of user to reset password
    :param salt: function specific salt from app.config
    :return: link to reset password
    """
    token = ts.dumps(username, salt=salt)
    return url_for("reset_password", token=token, _external=True)


def decrypt_token(token: str, salt: str):
    """
    Decrypt itsdangerous token
    :param token: Token to decrypt
    :param salt: Salt specific to functionality
    :return: decrypted token
    """
    return ts.loads(token, salt=salt, max_age=3600)
