from flask import Flask, render_template, redirect, request, flash
from flask_session import Session

from session_handling import is_logged_in, current_user, logout_from_session, login_to_session
from regex import check_password_requirements, is_email
from security import generate_password_hash, verify_password, decrypt_token, generate_password_reset_link, \
    generate_change_email_link, generate_email_confirmation_link
from mail import html_confirmation_email, html_change_mail_email, html_reset_password_mail, send_email
from database import create_new_user, update_user_hash, update_user_email, update_email_confirmed, get_user_email,\
    get_username_by_email, close_connection

app = Flask(__name__)
app.config.from_object("config.Config")

Session(app)


@app.route('/')
@is_logged_in
def home():
    return render_template("index.html")


@app.route("/account", methods=["POST", "GET"])
@is_logged_in
def account():
    if request.method == "POST":
        if request.form.get("type") == "change_password":
            old_password = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirmation = request.form.get("confirmation")
            if not old_password:
                flash("Old password required", "warning")
                return render_template("account.html")
            if not new_password:
                flash("New password required", "warning")
                return render_template("account.html")
            if not confirmation:
                flash("Please confirm password", "warning")
                return render_template("account.html")
            if not verify_password(current_user(), old_password):
                flash("Wrong password", "warning")
                return render_template("account.html")
            if not new_password == confirmation:
                flash("Passwords do not match", "warning")
                return render_template("account.html")
            if not update_user_hash(generate_password_hash(new_password), current_user()):
                flash("An unexpected error occurred. Please try again later", "danger")
                return render_template("account.html")
            flash("Password changed", "success")
            return render_template("account.html")
        if request.form.get("type") == "change_email":
            new_email = request.form.get("new_email")
            if not new_email:
                flash("new email required", "warning")
                return render_template("account.html")
            old_email = get_user_email(current_user())
            if not old_email:
                if not update_user_email(current_user(), new_email):
                    flash("An unexpected error occurred. Please try again later", "danger")
                    return render_template("account.html")
                flash("Email set", "success")
                return render_template("account.html")
            else:
                if not send_email(new_email, "Confirm new email",
                                  html_change_mail_email(generate_change_email_link(old_email, new_email))):
                    flash("An error occurred. Please try again later.", "danger")
                    return redirect("/")
                flash("Confirmation link sent", "success")
                return render_template("account.html")
    else:
        return render_template("account.html")


@app.route("/logout")
@is_logged_in
def logout():
    if not logout_from_session():
        flash("An error occurred, please try again", "danger")
        return redirect("/")
    flash("You are now logged out", "success")
    return redirect("/")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            flash("Username required", "warning")
            return render_template("login.html")
        if not request.form.get("password"):
            flash("Password required", "warning")
            return render_template("login.html")
        if not verify_password(username, request.form.get("password")):
            flash("Wrong username or password", "danger")
            return render_template("login.html")
        if not login_to_session(username):
            flash("An error occurred, please try again.", "danger")
            return render_template("login.html")
        flash("Login successful", "success")
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        if not username:
            flash("Username required", "warning")
            return render_template("register.html")
        if not password:
            flash("Password required", "warning")
            return render_template("register.html")
        if not request.form.get("confirmation"):
            flash("Please confirm password", "warning")
            return render_template("register.html")
        if get_user_email(username):
            flash("Username already exists", "danger")
            return render_template("register.html")
        if not password == request.form.get("confirmation"):
            flash("Passwords do not match", "warning")
            return render_template("register.html")
        if not check_password_requirements(password):
            flash("Password does not meet requirements")
            return render_template("register.html")

        if not create_new_user(username, password):
            flash("An unexpected error occurred. Please try again later", "danger")
            return render_template("register.html")
        if email and is_email(email):
            update_user_email(username, email)
            if not send_email(email, "Please confirm your email",
                              html_confirmation_email(generate_email_confirmation_link(email))):
                flash("An error occurred. Please try again later.", "danger")
                return redirect("/")

        if not login_to_session(username):
            flash("An error occurred, please try again", "danger")
            return render_template("register.html")
        flash("You are successfully registered", "success")
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/confirm/<token>")
def confirm(token):
    try:
        email = decrypt_token(token, "email-confirmation-key")
    except Exception as e:
        print(e)
        return render_template("bad_confirmation_link.html")
    if not update_email_confirmed(email):
        flash("An error occurred, please try again", "danger")
        return render_template("register.html")
    flash("Email confirmed. Thank you", "success")
    return redirect("/")


@app.route("/change_email/<token>")
def change_email(token):
    try:
        data = decrypt_token(token, "change-email-key")
        old_email = data["old_email"]
        new_email = data["new_email"]

        if not update_user_email(get_username_by_email(old_email), new_email):
            flash("An error occurred, please try again", "danger")
            return redirect("/")

        flash("Email updated!", "success")
        return redirect("/")
    except Exception as e:
        print(e)
        return render_template("bad_change_email_link.html")


@app.route("/reset_password/<token>", methods=["POST", "GET"])
def reset_password(token):
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        if not username:
            flash("Username required", "warning")
            return render_template("reset_password.html")
        if not password:
            flash("Password required")
            return render_template("reset_password.html")
        if not confirmation:
            flash("Please confirm password", "warning")
            return render_template("reset_password.html")
        if not password == confirmation:
            flash("Passwords do not match", "warning")
            return render_template("reset_password.html")
        if not check_password_requirements(password):
            flash("Password does not meet criteria", "warning")
            return render_template("reset_password.html")

        if not update_user_hash(generate_password_hash(password), username):
            flash("An error occurred, please try again", "danger")
            return render_template("reset_password.html")

        flash("Password reset successfully", "success")
        return redirect("/login")
    else:
        try:
            username = decrypt_token(token, "reset-password-key")
            return render_template("reset_password.html", username=username)
        except Exception as e:
            print(e)
            return render_template("bad_password_reset_link.html")


@app.route("/request_password_reset", methods=["POST", "GET"])
def request_password_reset():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            flash("Username required", "warning")
            return render_template("request_password_reset.html")
        if not get_user_email(username):
            flash("Username doesn't exist or no email is associated with it.", "danger")
            return render_template("request_password_reset.html")
        email = get_user_email(username)
        if not send_email(email, "Reset password", html_reset_password_mail(generate_password_reset_link(username))):
            flash("An error occurred. Please try again later.", "danger")
            return redirect("/")
        flash("Reset link sent", "success")
        return render_template("request_password_reset.html")
    else:
        return render_template("request_password_reset.html")


@app.teardown_appcontext
def close_db(exception):
    close_connection(exception)


if __name__ == '__main__':
    app.run()
