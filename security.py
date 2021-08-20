from flask import url_for
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer

from database import get_user_hash


ts = URLSafeTimedSerializer("CS50")

# Setting up passlib to hash passwords
# Using argon2 as hashing algorithm
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


def generate_password_hash(password):
    hashed_pwd = pwd_context.hash(password)
    return hashed_pwd


def verify_password(username, password):
    correct_hash = get_user_hash(username)
    if not correct_hash or not pwd_context.verify(password, correct_hash):
        return False
    return True


def generate_email_confirmation_link(email):
    token = ts.dumps(email, salt="email-confirmation-key")
    return url_for('confirm', token=token, _external=True)


def generate_change_email_link(old_email, new_email):
    token = ts.dumps({"old_email": old_email, "new_email": new_email}, salt="change-email-key")
    return url_for("change_email", token=token, _external=True)


def generate_password_reset_link(username):
    token = ts.dumps(username, salt="reset-password-key")
    return url_for("reset_password", token=token, _external=True)


def decrypt_token(token, salt):
    return ts.loads(token, salt=salt, max_age=3600)
