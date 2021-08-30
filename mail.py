from flask import render_template, current_app, flash, redirect
from flask_mail import Mail, Message
from database import get_user_email


def send_email(recipient, subject, html):
    mail = Mail(current_app)
    recipients = [recipient]
    msg = Message(recipients=recipients, subject=subject, html=html)
    try:
        mail.send(msg)
    except Exception as e:
        print(e)
        return False
    return True


def send_user_email(username, subject, html):
    email = get_user_email(username)
    if not email:
        return False
    if not send_email(email, subject, html):
        return False
    return True


def html_confirmation_email(confirmation_link):
    return render_template("emails/confirm_email.html", confirmation_link=confirmation_link)


def html_change_mail_email(confirm_new_email_link):
    return render_template("emails/confirm_new_email.html", confirm_new_email_link=confirm_new_email_link)


def html_reset_password_mail(password_reset_link):
    return render_template("emails/password_reset_email.html", password_reset_link=password_reset_link)


def html_friend_request_mail(username):
    return render_template("emails/friend_request_email.html", username=username)


def html_accepted_friend_mail(username):
    return render_template("emails/accepted_friend_email.html", username=username)


def html_new_question_mail(username):
    return render_template("emails/new_question_email.html", username=username)


def html_question_answered(username):
    return render_template("emails/question_answered_email.html", username=username)
