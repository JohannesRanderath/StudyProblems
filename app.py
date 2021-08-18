from flask import Flask, render_template, redirect, request, session
from flask_session import Session
from flask_mail import Mail, Message

import sqlite3

from backend import is_logged_in, check_password_requirements, generate_password_hash, is_email, \
    verify_password, generate_email_confirmation_link, html_confirmation_email, decrypt_token, \
    html_change_mail_email, generate_change_email_link, html_reset_password_mail, generate_password_reset_link

# TODO: Change message mode to comply with redirects -> GET?
# TODO: Add messages to redirects
# TODO: Add labels to form elements

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = "joranderathsg@gmail.com"
app.config["MAIL_PASSWORD"] = "hgtyawsgcnvsfpnm"
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_DEFAULT_SENDER"] = "joranderathsg@gmail.com"
mail = Mail(app)

def send_email(recipient, subject, html):
    recipients = [recipient]
    msg = Message(recipients=recipients, subject=subject, html=html)
    try:
        mail.send(msg)
    except:
        return False
    return True


@app.route('/')
@is_logged_in
def home():
    return render_template("index.html", messages=[])


@app.route("/account", methods=["POST", "GET"])
@is_logged_in
def account():
    if request.method == "POST":
        if request.form.get("type") == "change_password":
            old_password = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirmation = request.form.get("confirmation")
            if not old_password:
                return render_template("account.html", messages=[{"type": "danger", "text": "Old password required"}])
            if not new_password:
                return render_template("account.html", messages=[{"type": "danger", "text": "New password required"}])
            if not confirmation:
                return render_template("account.html", messages=[{"type": "danger", "text": "Please confirm password"}])
            if not verify_password(session["username"], generate_password_hash(old_password)):
                return render_template("account.html", messages=[{"type": "danger", "text": "Wrong password"}])
            if not new_password == confirmation:
                return render_template("account.html", messages=[{"type": "danger", "text": "Passwords do not match"}])
            db_con = sqlite3.connect("database.db")
            db = db_con.cursor()
            db.execute("UPDATE users SET hash=? WHERE username=?;",
                       (generate_password_hash(new_password), session["username"]))
            db_con.commit()
            db_con.close()
            return render_template("account.html", messages=[{"type": "success", "text": "Password changed!"}])
        if request.form.get("type") == "change_email":
            db_con = sqlite3.connect("database.db")
            db = db_con.cursor()
            new_email = request.form.get("new_email")
            if not new_email:
                db_con.close()
                return render_template("account.html", messages=[{"type": "danger", "text": "New email required"}])
            old_email = db.execute("SELECT email FROM users WHERE username=?;", (session["username"], )).fetchone()[0]
            if not old_email:
                db.execute("UPDATE users SET email=? WHERE username=?", (new_email, session["username"]))
                db_con.commit()
                db_con.close()
                return render_template("account.html", messages=[{"type": "success", "text": "Email set."}])
            else:
                send_email(new_email, "Confirm new email", html_change_mail_email(generate_change_email_link(old_email, new_email)))
                db_con.close()
                return render_template("account.html", messages=[{"type": "success", "text": "Confirmation link sent!"}])
    else:
        return render_template("account.html")


@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    return redirect("/")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return render_template("login.html",
                                   messages=[{"type": "danger", "text": "Username required"}])
        if not request.form.get("password"):
            return render_template("login.html",
                                   messages=[{"type": "danger", "text": "Password required"}])
        if not verify_password(username, request.form.get("password")):
            return render_template("login.html",
                                   messages=[{"type": "danger", "text": "Wrong username or password"}])
        session["username"] = username
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
            return render_template("register.html", messages=[{"type": "danger", "text": "Username required."}])
        if not password:
            return render_template("register.html", messages=[{"type": "danger", "text": "Password required"}])
        if not request.form.get("confirmation"):
            return render_template("register.html",
                                   messages=[{"type": "danger", "text": "Please confirm password"}])
        if db.execute("SELECT username FROM users WHERE username=?;", (username,)).fetchone():
            return render_template("register.html",
                                   messages=[{"type": "danger", "text": "Username already exists."}])
        if not password == request.form.get("confirmation"):
            return render_template("register.html",
                                   messages=[{"type": "danger", "text": "Passwords do not match"}])
        if not check_password_requirements(password):
            return render_template("register.html",
                                   messages=[{"type": "danger", "text": "Password does not meet requirements."}])

        db.execute("INSERT INTO users (username, hash) VALUES (?,?)", (username, generate_password_hash(password)))
        if email and is_email(email):
            db.execute("UPDATE users SET email=?, email_confirmed=? WHERE username=?;", (email, 0, username))
            print("hi")
            print(send_email(email, "Please confirm your email",
                             html_confirmation_email(generate_email_confirmation_link(email))))
        db_connection.commit()
        db_connection.close()

        session["username"] = username
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
        print(0)
        if not username:
            print(1)
            return render_template("reset_password.html",
                                   messages=[{"type": "danger", "text": "Username required"}])
        if not password:
            print(2)
            return render_template("reset_password.html",
                                   messages=[{"type": "danger", "text": "Password required"}])
        if not confirmation:
            print(3)
            return render_template("reset_password.html",
                                   messages=[{"type": "danger", "text": "Please confirm password."}])
        if not password == confirmation:
            print(4)
            return render_template("reset_password.html",
                                   messages=[{"type": "danger", "text": "Passwords do not match."}])
        if not check_password_requirements(password):
            print(5)
            return render_template("reset_password.html",
                                   messages=[{"type": "danger", "text": "Password does not meet criteria."}])
        db_con = sqlite3.connect("database.db")
        db = db_con.cursor()
        db.execute("UPDATE users SET hash=? WHERE username=?;", (generate_password_hash(password), username))
        db_con.commit()
        db_con.close()
        print(6)
        return redirect("/login")
    else:
        try:
            username = decrypt_token(token, "reset-password-key")
            print(username)
            print(7)
            return render_template("reset_password.html", username=username)
        except Exception as e:
            print(e)
            return render_template("bad_password_reset_link.html")


@app.route("/request_password_reset", methods=["POST", "GET"])
def request_password_reset():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return render_template("request_password_reset.html",
                            messages=[{"type": "danger", "text": "Username required"}])
        db_con = sqlite3.connect("database.db")
        db = db_con.cursor()
        if not db.execute("SELECT email FROM users WHERE username=?;", (username, )):
            db_con.close()
            return render_template("request_password_reset.html",
                                   messages=[{"type": "danger", "text": "Username doesn't exist or no email is associated with it."}])
        email = db.execute("SELECT email FROM users WHERE username=?;", (username,)).fetchone()[0]
        send_email(email, "Reset password", html_reset_password_mail(generate_password_reset_link(username)))
        return render_template("request_password_reset.html", messages=[{"type": "success", "text": "Reset link sent."}])
    else:
        return render_template("request_password_reset.html")


if __name__ == '__main__':
    app.run()
