from flask import session, redirect
from functools import wraps


def is_logged_in(route_function):
    """Lock pages with login"""

    @wraps(route_function)
    def do_the_magic(*args, **kwargs):
        if "username" not in session.keys():
            return redirect("/login")
        else:
            return route_function(*args, **kwargs)

    return do_the_magic


def current_user():
    return session["username"]


def logout_from_session():
    try:
        session.clear()
        return True
    except Exception as e:
        print(e)
        return False


def login_to_session(username):
    try:
        session["username"] = username
        return True
    except Exception as e:
        print(e)
        return False
