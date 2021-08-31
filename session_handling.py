from flask import session, redirect, url_for
from functools import wraps


def is_logged_in(route_function):
    """
    Lock pages with login
    :param route_function: flask route function from app to be secured by login
    :return: function that redirects to /login if not logged in and the original route function if logged in
    """
    @wraps(route_function)
    def do_the_magic(*args, **kwargs):
        if "username" not in session.keys():
            return redirect(url_for("login"))
        else:
            return route_function(*args, **kwargs)

    return do_the_magic


def current_user():
    """
    Get username of logged in user if one is logged in
    :return: username of logged in user if logged in
    :return: None if not logged in
    """
    if "username" in session.keys():
        return session["username"]
    else:
        return None


def logout_from_session():
    """
    Delete session and de facto log out user
    :return: True if successful
    :return: False if an Exception was raised
    """
    try:
        session.clear()
        return True
    except Exception as e:
        print(e)
        return False


def login_to_session(username: str):
    """
    Add username to session and de facto log in user
    :param username: username of user to log in
    :return: True if successful
    :return: False if an Exception was raised
    """
    try:
        session["username"] = username
        session.permanent = False
        return True
    except Exception as e:
        print(e)
        return False
