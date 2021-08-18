from flask import Flask, render_template, redirect, request, session
from flask_session import Session
from flask_mail import Mail, Message

import sqlite3

from backend import is_logged_in, check_password_requirements, generate_password_hash, is_email, \
    verify_password, generate_email_confirmation_link, html_confirmation_email, get_mail_from_token

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


@app.route('/')
@is_logged_in
def home():
    return render_template("index.html", messages=[])


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
        email = get_mail_from_token(token)
    except:
        return render_template("bad_confirmation_link.html")
    db_con = sqlite3.connect("database.db")
    db = db_con.cursor()
    if db.execute("SELECT email FROM users WHERE email=?;", (email, )):
        db.execute("UPDATE users SET email_confirmed=1 WHERE email=?;", (email, ))
    db_con.commit()
    db_con.close()
    return redirect("/")


def send_email(recipient, subject, html):
    recipients = [recipient]
    msg = Message(recipients=recipients, subject=subject, html=html)
    try:
        mail.send(msg)
    except:
        return False
    return True


if __name__ == '__main__':
    app.run()
