import re

from flask import Flask, render_template, redirect, request, session
from flask_session import Session
from backend import is_logged_in, check_password_requirements, generate_password_hash, verify_password
import sqlite3

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


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
        if email and re.match("^.+@.+[.].+", email):
            db.execute("UPDATE users SET email=? WHERE username=?;", (email, username))
        db_connection.commit()
        db_connection.close()

        session["username"] = username
        return redirect("/login")
    else:
        return render_template("register.html", messages=[])


if __name__ == '__main__':
    app.run()
