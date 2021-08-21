from flask import g, current_app
import sqlite3


def get_db():
    db = getattr(g, '_database', None)
    if not db:
        db = g._database = sqlite3.connect(current_app.config["DB_NAME"])
    return db


def close_connection(exception):
    if exception:
        print(exception)
    db = getattr(g, '_database', None)
    if db:
        db.close()


def create_new_user(username, password):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO users (username, hash, email_confirmed) VALUES (?, ?, 0)",
                    (username, password))
        db.commit()
        return True
    except Exception as e:
        print(e)
        return False


def update_user_hash(new_hash, username):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE users SET hash=? WHERE username=?;",
                    (new_hash, username))
        db.commit()
        return True
    except Exception as e:
        print(e)
        return False


def update_user_email(username, new_email):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE users SET email=? WHERE username=?;", (new_email, username))
        db.commit()
        return True
    except Exception as e:
        print(e)
        return False


def update_email_confirmed(email):
    try:
        db = get_db()
        cur = db.cursor()
        if cur.execute("SELECT email FROM users WHERE email=?;", (email, )):
            cur.execute("UPDATE users SET email_confirmed=1 WHERE email=?;", (email, ))
            db.commit()
        else:
            return False
    except Exception as e:
        print(e)
        return False


def get_user_email(username):
    try:
        db = get_db()
        cur = db.cursor()
        return cur.execute("SELECT email FROM users WHERE username=?;", (username,)).fetchone()[0]
    except Exception as e:
        print(e)
        return False


def get_user_hash(username):
    try:
        db = get_db()
        cur = db.cursor()
        return cur.execute("SELECT hash FROM users WHERE username=?;", (username,)).fetchone()[0]
    except Exception as e:
        print(e)
        return False


def get_username_by_email(email):
    try:
        db = get_db()
        cur = db.cursor()
        return cur.execute("SELECT username FROM users WHERE email=?;", (email,)).fetchone()[0]
    except Exception as e:
        print(e)
        return False
