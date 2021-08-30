import re
from datetime import datetime


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


def is_email(email):
    return re.match("^.+@.+[.].+", email)