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
        print("In db.create_new_user", e)
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
        print("In db.update_user_hash", e)
        return False


def update_user_email(username, new_email):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE users SET email=? WHERE username=?;", (new_email, username))
        db.commit()
        return True
    except Exception as e:
        print("In db.update_user_email", e)
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
        print("In db.update_email_confirmed", e)
        return False


def get_user_email(username):
    try:
        db = get_db()
        cur = db.cursor()
        return cur.execute("SELECT email FROM users WHERE username=?;", (username,)).fetchone()[0]
    except Exception as e:
        print("In db.get_user_email", e)
        return False


def get_user_hash(username):
    try:
        db = get_db()
        cur = db.cursor()
        return cur.execute("SELECT hash FROM users WHERE username=?;", (username,)).fetchone()[0]
    except Exception as e:
        print("In db.get_user_hash", e)
        return False


def get_username_by_email(email):
    try:
        db = get_db()
        cur = db.cursor()
        return cur.execute("SELECT username FROM users WHERE email=?;", (email,)).fetchone()[0]
    except Exception as e:
        print("In db.get_username_by_email", e)
        return False


def get_usernames_starting_with(string):
    try:
        db = get_db()
        cur = db.cursor()
        string += '%'
        usernames = cur.execute("SELECT username FROM users WHERE username LIKE ? LIMIT 10;", (string, )).fetchall()
        return usernames
    except Exception as e:
        print("In db.get_usernames_starting_with", e)
        return []


def user_exists(username):
    try:
        db = get_db()
        cur = db.cursor()
        user = cur.execute("SELECT username FROM users WHERE username = ?;", (username, )).fetchone()
        return bool(user)
    except Exception as e:
        print("In db.user_exists", e)
        return False


def question_exists(question_id):
    try:
        db = get_db()
        cur = db.cursor()
        question = cur.execute("SELECT * FROM questions WHERE id=?;", (question_id, )).fetchone()
        return bool(question)
    except Exception as e:
        print("In db.question_exists: ", e)
        return False


def add_friend_request(user1, user2):
    try:
        db = get_db()
        cur = db.cursor()
        user1_id = cur.execute("SELECT id FROM users WHERE username = ?;", (user1, )).fetchone()[0]
        user2_id = cur.execute("SELECT id FROM users WHERE username = ?;", (user2,)).fetchone()[0]
        cur.execute("INSERT INTO friends (user1, user2) VALUES (?, ?)", (user1_id, user2_id))
        db.commit()
        return True
    except Exception as e:
        print("In db.add_friend_request", e)
        return False


def add_message(sender, recipient, message_type):
    try:
        db = get_db()
        cur = db.cursor()
        sender_id = cur.execute("SELECT id FROM users WHERE username=?;", (sender, )).fetchone()[0]
        recipient_id = cur.execute("SELECT id FROM users WHERE username=?;", (recipient,)).fetchone()[0]
        print(sender_id)
        if not sender_id or not recipient_id:
            print("In db.add_message: User not found")
            return False
        cur.execute("INSERT INTO messages (sender, recipient, type) VALUES (?, ?, ?);",
                    (sender_id, recipient_id, message_type))
        db.commit()
        return True
    except Exception as e:
        print("In db.add_message", e)
        return False


def get_user_messages(username):
    try:
        db = get_db()
        cur = db.cursor()
        user_id = cur.execute("SELECT id FROM users WHERE username=?;", (username, )).fetchone()[0]
        if not user_id:
            print("In db.get_user_messages: User not found")
            return []
        messages = cur.execute("SELECT id, sender, type FROM messages WHERE recipient=?;", (user_id, )).fetchall()
        messages = [{"id": user_message[0], "type": user_message[2],
                     "sender": cur.execute("SELECT username FROM users WHERE id=?;", (user_message[1], )).fetchone()[0]}
                    for user_message in messages]
        return messages
    except Exception as e:
        print("In db.get_user_messages", e)
        return []


def confirm_friend(user1, user2):
    try:
        db = get_db()
        cur = db.cursor()
        user1_id = cur.execute("SELECT id FROM users WHERE username=?;", (user1, )).fetchone()[0]
        user2_id = cur.execute("SELECT id FROM users WHERE username=?;", (user2, )).fetchone()[0]
        cur.execute("UPDATE friends SET confirmed=1 WHERE user1=? AND user2=?;", (user1_id, user2_id))
        db.commit()
        return True
    except Exception as e:
        print("In db.confirm_friend: ", e)
        return False


def exists_friend_or_request(user1, user2):
    try:
        db = get_db()
        cur = db.cursor()
        user1_id = cur.execute("SELECT id FROM users WHERE username=?;", (user1, )).fetchone()[0]
        user2_id = cur.execute("SELECT id FROM users WHERE username=?;", (user2, )).fetchone()[0]
        request = cur.execute("SELECT * FROM friends WHERE (user1=? AND user2=?) OR (user1=? AND user2=?);",
                              (user1_id, user2_id, user2_id, user1_id)).fetchone()
        if not request:
            return False
        return True
    except Exception as e:
        print("In db.exists_friend_or_request: ", e)
        return False


def delete_message(message_id):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("DELETE FROM messages WHERE id=?;", (message_id,))
        db.commit()
        return True
    except Exception as e:
        print("In db.delete_message: ", e)
        return False


def delete_all_messages_asked_question(username):
    try:
        db = get_db()
        cur = db.cursor()
        user_id = cur.execute("SELECT id FROM users WHERE username=?;", (username, )).fetchone()[0]
        cur.execute("DELETE FROM messages WHERE type='asked_question' AND recipient=?", (user_id, ))
        db.commit()
        return True
    except Exception as e:
        print("In db.delete_all_messages_asked_question: ", e)
        return False


def delete_all_messages_answered_question(username):
    try:
        db = get_db()
        cur = db.cursor()
        user_id = cur.execute("SELECT id FROM users WHERE username=?;", (username, )).fetchone()[0]
        cur.execute("DELETE FROM messages WHERE type='answered_question' AND recipient=?", (user_id, ))
        db.commit()
        return True
    except Exception as e:
        print("In db.delete_all_messages_answered_question: ", e)
        return False


def get_friends(username):
    try:
        db = get_db()
        cur = db.cursor()
        user_id = cur.execute("SELECT id FROM users WHERE username=?;", (username, )).fetchone()[0]
        friends = cur.execute("SELECT user1, user2 FROM friends WHERE (user1=? OR user2=?) AND confirmed=1;",
                              (user_id, user_id)).fetchall()
        friends = [friend[0] if not friend[0] == user_id else friend[1] for friend in friends]
        friends = [cur.execute("SELECT username FROM users WHERE id=?;", (friend, )).fetchone()[0] for friend in friends]
        return friends
    except Exception as e:
        print("In db.get_friends: ", e)
        return []


def delete_friends_from_db(user1, user2):
    try:
        db = get_db()
        cur = db.cursor()
        user1_id = cur.execute("SELECT id FROM users WHERE username=?;", (user1, )).fetchone()[0]
        user2_id = cur.execute("SELECT id FROM users WHERE username=?;", (user2, )).fetchone()[0]
        cur.execute("DELETE FROM friends WHERE (user1=? AND user2=?) OR (user1=? AND user2=?)",
                    (user1_id, user2_id, user2_id, user1_id))
        db.commit()
        return True
    except Exception as e:
        print("In db.delete_friends_from_db: ", e)
        return False


def get_questions_from_user(username):
    try:
        db = get_db()
        cur = db.cursor()
        user_id = cur.execute("SELECT id FROM users WHERE username=?;", (username, )).fetchone()[0]
        questions = cur.execute("SELECT id, recipient, question_text, answer FROM questions WHERE sender=?;",
                                (user_id, )).fetchall()
        questions = [{"id": question[0], "recipient": cur.execute("SELECT username FROM users WHERE id=?;",
                     (question[1], )).fetchone()[0], "question": question[2], "answer": question[3]}
                     for question in questions]
        return questions
    except Exception as e:
        print("In db.get_questions_for_user: ", e)
        return []


def get_questions_for_user(username):
    try:
        db = get_db()
        cur = db.cursor()
        user_id = cur.execute("SELECT id FROM users WHERE username=?;", (username, )).fetchone()[0]
        questions = cur.execute("SELECT id, sender, question_text, answer FROM questions WHERE recipient=?;",
                                (user_id, )).fetchall()
        questions = [{"id": question[0], "sender": cur.execute("SELECT username FROM users WHERE id=?;",
                     (question[1],)).fetchone()[0], "question": question[2], "answer": question[3]}
                     for question in questions]
        return questions
    except Exception as e:
        print("In db.get_questions_for_user: ", e)
        return []


def add_question(sender, recipient, question):
    try:
        db = get_db()
        cur = db.cursor()
        sender_id = cur.execute("SELECT id FROM users WHERE username=?;", (sender, )).fetchone()[0]
        recipient_id = cur.execute("SELECT id FROM users WHERE username=?;", (recipient, )).fetchone()[0]
        cur.execute("INSERT INTO questions (sender, recipient, question_text) VALUES (?, ?, ?)",
                    (sender_id, recipient_id, question))
        db.commit()
        return True
    except Exception as e:
        print("In db.add_question: ", e)
        return False


def get_question(question_id):
    try:
        db = get_db()
        cur = db.cursor()
        q = cur.execute("SELECT id, sender, recipient, question_text, answer FROM questions WHERE id=?;",
                        (question_id, )).fetchone()
        question = {"id": q[0], "sender": cur.execute("SELECT username FROM users WHERE id=?;", (q[1], )).fetchone()[0], "recipient": cur.execute("SELECT username FROM users WHERE id=?;", (q[2], )).fetchone()[0], "question": q[3], "answer": q[4]}
        return question
    except Exception as e:
        print("In db.get_question: ", e)
        return False


def add_answer(question_id, answer):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE questions SET answer=? WHERE id=?;", (answer, question_id))
        db.commit()
        return True
    except Exception as e:
        print("In db.add_answer: ", e)
        return False
