import re


def check_password_requirements(new_password: str):
    """
    Check if password meets requirements
    Requirements are:
    - a length of 8 or more characters, of which at least
        - one uppercase letter,
        - one lowercase letter
        - and one digit
    :param new_password: Password string to check against requirements
    :return: True if password meets requirements
    :return: False if the password does not meet the requirements
    """

    if len(new_password) >= 8 and re.search("[a-z]", new_password) and re.search("[A-Z]", new_password) \
            and re.search("[0-9]", new_password):
        return True
    return False


def is_email(email: str):
    """
    Check if a string seems to be an email address
    :param email: string to check
    :return: True if the string looks like an email address
    :return: False if it does not
    """
    return bool(re.match("^.+@.+[.].+", email))
