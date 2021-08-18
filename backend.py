from flask import render_template, redirect, session, url_for

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


def generate_change_email_link(old_email, new_email):
    token = ts.dumps({"old_email": old_email, "new_email": new_email}, salt="change-email-key")
    return url_for("change_email", token=token, _external=True)


def generate_password_reset_link(username):
    token = ts.dumps(username, salt="reset-password-key")
    return url_for("reset_password", token=token, _external=True)


def html_confirmation_email(confirmation_link):
    return render_template("emails/confirm_email.html", confirmation_link=confirmation_link)


def html_change_mail_email(confirm_new_email_link):
    return render_template("emails/confirm_new_email.html", confirm_new_email_link=confirm_new_email_link)


def html_reset_password_mail(password_reset_link):
    return render_template("emails/password_reset_email.html", password_reset_link=password_reset_link)


def is_email(email):
    return re.match("^.+@.+[.].+", email)


def decrypt_token(token, salt):
    return ts.loads(token, salt=salt, max_age=3600)
