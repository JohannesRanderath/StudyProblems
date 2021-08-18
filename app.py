from flask import Flask, render_template, redirect, request, session, flash
from flask_session import Session

import sqlite3

from backend import is_logged_in, check_password_requirements, generate_password_hash, is_email, \
    verify_password, generate_email_confirmation_link, html_confirmation_email, decrypt_token, \
    html_change_mail_email, generate_change_email_link, html_reset_password_mail, generate_password_reset_link, \
    send_email

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
            if not verify_password(session["username"], generate_password_hash(old_password)):
                flash("Wrong password", "warning")
                return render_template("account.html")
            if not new_password == confirmation:
                flash("Passwords do not match", "warning")
                return render_template("account.html")
            db_con = sqlite3.connect("database.db")
            db = db_con.cursor()
            db.execute("UPDATE users SET hash=? WHERE username=?;",
                       (generate_password_hash(new_password), session["username"]))
            db_con.commit()
            db_con.close()
            flash("Password changed", "success")
            return render_template("account.html")
        if request.form.get("type") == "change_email":
            db_con = sqlite3.connect("database.db")
            db = db_con.cursor()
            new_email = request.form.get("new_email")
            if not new_email:
                db_con.close()
                flash("new email required", "warning")
                return render_template("account.html")
            old_email = db.execute("SELECT email FROM users WHERE username=?;", (session["username"], )).fetchone()[0]
            if not old_email:
                db.execute("UPDATE users SET email=? WHERE username=?", (new_email, session["username"]))
                db_con.commit()
                db_con.close()
                flash("Email set", "success")
                return render_template("account.html")
            else:
                db_con.close()
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
    session.clear()
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
        session["username"] = username
        flash("Login successful", "success")
        return redirect("/")
    else:
        return render_template("login.html", messages=[])


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        db_connection = sqlite3.connect("database.db")
        db = db_connection.cursor()

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
        if db.execute("SELECT username FROM users WHERE username=?;", (username,)).fetchone():
            flash("Username already exists", "danger")
            return render_template("register.html")
        if not password == request.form.get("confirmation"):
            flash("Passwords do not match", "warning")
            return render_template("register.html")
        if not check_password_requirements(password):
            flash("Password does not meet requirements")
            return render_template("register.html")

        db.execute("INSERT INTO users (username, hash) VALUES (?,?)", (username, generate_password_hash(password)))
        if email and is_email(email):
            db.execute("UPDATE users SET email=?, email_confirmed=? WHERE username=?;", (email, 0, username))
            db_connection.commit()
            db_connection.close()
            if not send_email(email, "Please confirm your email",
                       html_confirmation_email(generate_email_confirmation_link(email))):
                flash("An error occurred. Please try again later.", "danger")
                return redirect("/")

        session["username"] = username
        flash("You are successfully registered", "success")
        return redirect("/login")
    else:
        return render_template("register.html", messages=[])


@app.route("/confirm/<token>")
def confirm(token):
    try:
        email = decrypt_token(token, "email-confirmation-key")
    except Exception as e:
        print(e)
        return render_template("bad_confirmation_link.html")
    db_con = sqlite3.connect("database.db")
    db = db_con.cursor()
    if db.execute("SELECT email FROM users WHERE email=?;", (email, )):
        db.execute("UPDATE users SET email_confirmed=1 WHERE email=?;", (email, ))
    db_con.commit()
    db_con.close()
    flash("Email confirmed. Thank you", "success")
    return redirect("/")


@app.route("/change_email/<token>")
def change_email(token):
    try:
        data = decrypt_token(token, "change-email-key")
        old_email = data["old_email"]
        new_email = data["new_email"]
        db_con = sqlite3.connect("database.db")
        db = db_con.cursor()
        db.execute("UPDATE users SET email=? WHERE email=?;", (new_email, old_email))
        db_con.commit()
        db_con.close()
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
        db_con = sqlite3.connect("database.db")
        db = db_con.cursor()
        db.execute("UPDATE users SET hash=? WHERE username=?;", (generate_password_hash(password), username))
        db_con.commit()
        db_con.close()
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
        db_con = sqlite3.connect("database.db")
        db = db_con.cursor()
        if not db.execute("SELECT email FROM users WHERE username=?;", (username, )):
            db_con.close()
            flash("Username doesn't exist or no email is associated with it.", "danger")
            return render_template("request_password_reset.html")
        email = db.execute("SELECT email FROM users WHERE username=?;", (username,)).fetchone()[0]
        if not send_email(email, "Reset password", html_reset_password_mail(generate_password_reset_link(username))):
            flash("An error occurred. Please try again later.", "danger")
            return redirect("/")
        flash("Reset link sent", "success")
        return render_template("request_password_reset.html")
    else:
        return render_template("request_password_reset.html")


if __name__ == '__main__':
    app.run()
