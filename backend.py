from flask import render_template, redirect, session, url_for
from flask_mail import Message

import re
import sqlite3
from functools import wraps

from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer

ts = URLSafeTimedSerializer("CS50")

# Setting up passlib to hash passwords
# Using argon2 as hashing algorithm
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


def is_logged_in(route_function):
    """Lock pages with login"""

    @wraps(route_function)
    def do_the_magic(*args, **kwargs):
        if "username" not in session.keys():
            return redirect("/login")
        else:
            return route_function(*args, **kwargs)

    return do_the_magic


def check_password_requirements(new_password):
    """Check if password meets requirements"""
    """Requirements are:
        a length of 8 or more characters, of which at least
         one uppercase letter,
         one lowercase letter 
         and one digit"""

    if len(new_password) >= 8 and re.search("[a-z]", new_password) and re.search("[A-Z]", new_password) \
            and re.search("[0-9]", new_password):
        return True
    return False


def generate_password_hash(password):
    hashed_pwd = pwd_context.hash(password)
    return hashed_pwd


def verify_password(username, password):
    db_connection = sqlite3.Connection("database.db")
    db = db_connection.cursor()
    correct_hash = db.execute("SELECT hash FROM users WHERE username=?;", (username,)).fetchone()[0]
    if not correct_hash or not pwd_context.verify(password, correct_hash):
        return False
    return True


def generate_email_confirmation_link(email):
    token = ts.dumps(email, salt="email-confirmation-key")
    return url_for('confirm', token=token, _external=True)


def html_confirmation_email(confirmation_link):
    return render_template("emails/confirm_email.html", confirmation_link=confirmation_link)


def is_email(email):
    return re.match("^.+@.+[.].+", email)


def get_mail_from_token(token):
    return ts.loads(token, salt="email-confirmation-key", max_age=3600)
