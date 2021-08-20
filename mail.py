from flask import render_template, current_app
from flask_mail import Mail, Message


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


def html_confirmation_email(confirmation_link):
    return render_template("emails/confirm_email.html", confirmation_link=confirmation_link)


def html_change_mail_email(confirm_new_email_link):
    return render_template("emails/confirm_new_email.html", confirm_new_email_link=confirm_new_email_link)


def html_reset_password_mail(password_reset_link):
    return render_template("emails/password_reset_email.html", password_reset_link=password_reset_link)
