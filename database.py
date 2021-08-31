from flask import g, current_app
import sqlite3


# do all database handling in this separate .py


def get_db():
    """
    Setup database connection if it wasn't established yet and return it.
    If there is already an active db connection, return that
    :return: An active sqlite3 database connection
    """
    db = getattr(g, '_database', None)
    if not db:
        db = g._database = sqlite3.connect(current_app.config["DB_NAME"])
    return db


def close_connection(exception):
    """
    Close database when the app is closed.
    :param exception: from app.teardown_appcontext
    :return:
    """
    if exception:
        print(exception)
    db = getattr(g, '_database', None)
    if db:
        db.close()


def create_new_user(username: str, password_hash: str):
    """
    Add user account in database
    :param username: New username. Has to be unique
    :param password_hash: hashed password, clear text password meets requirements, hash is stored
    :return: True if successful
    :return: False if an Excption was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO users (username, hash, email_confirmed) VALUES (?, ?, 0)",
                    (username, password_hash))
        db.commit()
        return True
    except Exception as e:
        print("In db.create_new_user", e)
        return False


def update_user_hash(new_hash: str, username: str):
    """
    Change user password.
    :param new_hash: hashed password to substitute old hash in table. Clear password meets requirements.
    :param username: username, account has to exist.
    :return: True if successful
    :return: False if an Exception was raised
    """
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


def update_user_email(username: str, new_email: str):
    """
    Update email associated with user account
    :param username: username, must exist
    :param new_email: email to substitute email associated with account. Should comply with email requirements
    :return: True if successful
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE users SET email=? WHERE username=?;", (new_email, username))
        db.commit()
        return True
    except Exception as e:
        print("In db.update_user_email", e)
        return False


def update_email_confirmed(email: str):
    """
    Save to database that user confirmed their email.
    :param email: email associated with an account in the database
    :return: True if successful
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        if cur.execute("SELECT email FROM users WHERE email=?;", (email, )).fetchone()[0]:
            cur.execute("UPDATE users SET email_confirmed=1 WHERE email=?;", (email, ))
            db.commit()
            return True
        else:
            return False
    except Exception as e:
        print("In db.update_email_confirmed", e)
        return False


def get_user_email(username:str):
    """
    Get email if one is associated with the given account
    :param username: username, must exist in database
    :return: email associated with username if successful
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        print(cur.execute("SELECT email_confirmed FROM users WHERE username=?;", (username, )).fetchone()[0])
        print(cur.execute("SELECT email_confirmed FROM users WHERE username=?;", (username,)).fetchone()[0] == 1)
        if cur.execute("SELECT email_confirmed FROM users WHERE username=?;", (username, )).fetchone()[0] == 1:
            return cur.execute("SELECT email FROM users WHERE username=?;", (username,)).fetchone()[0]
        else:
            return False
    except Exception as e:
        print("In db.get_user_email", e)
        return False


def get_user_hash(username: str):
    """
    get hashed password to given account
    :param username: username, must exist in database
    :return: hashed password of given user
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        user_hash = cur.execute("SELECT hash FROM users WHERE username=?;", (username,)).fetchone()[0]
        if user_hash:
            return user_hash
        return None
    except Exception as e:
        print("In db.get_user_hash", e)
        return False


def get_username_by_email(email: str):
    """
    Get username to given email, if it exists in database. Theoretically there
    could be more than one account associated with a given email. In this case return the first one
    :param email: email to get username associated with it if it exists
    :return: first username found, that is associated with the given email, None if not found
    """
    try:
        db = get_db()
        cur = db.cursor()
        return cur.execute("SELECT username FROM users WHERE email=?;", (email,)).fetchone()[0]
    except Exception as e:
        print("In db.get_username_by_email", e)
        return False


def get_usernames_starting_with(string: str):
    """
    Get all usernames in database starting with given substring.
    :param string: Substring the username must start with.
    :return: All usernames starting with <string>, an empty list if no match
    """
    try:
        db = get_db()
        cur = db.cursor()
        string += '%'
        usernames = cur.execute("SELECT username FROM users WHERE username LIKE ? LIMIT 10;", (string, )).fetchall()
        return usernames
    except Exception as e:
        print("In db.get_usernames_starting_with", e)
        return []


def user_exists(username: str):
    """
    Check if username has a match in database.
    :param username:
    :return: True if username exists in database
    :return: False if no match
    :return: False if an Exception was raised.
    """
    try:
        db = get_db()
        cur = db.cursor()
        user = cur.execute("SELECT username FROM users WHERE username = ?;", (username, )).fetchone()
        return bool(user)
    except Exception as e:
        print("In db.user_exists", e)
        return False


def question_exists(question_id: int):
    """
    Check if a question with the given id exists in database
    :param question_id: id to look up
    :return: True if question exists
    :return: False if question does not exist
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        question = cur.execute("SELECT * FROM questions WHERE id=?;", (question_id, )).fetchone()
        return bool(question)
    except Exception as e:
        print("In db.question_exists: ", e)
        return False


def add_friend_request(user1: str, user2: str):
    """
    Add unconfirmed friendship to friends table in database
    :param user1: username of user sending the request
    :param user2: username of user receiving the request
    :return: True if successful
    :return: False if an Exception was raised
    """
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


def add_message(sender: str, recipient: str, message_type: str):
    """
    Add message to messages table. Messages entries have a sender, a recipient and a type.
    :param sender: username of user invoking function
    :param recipient: username of user the message should be displayed to
    :param message_type: Action provoking message
    :return: True if successful
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        sender_id = cur.execute("SELECT id FROM users WHERE username=?;", (sender, )).fetchone()[0]
        recipient_id = cur.execute("SELECT id FROM users WHERE username=?;", (recipient,)).fetchone()[0]
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


def get_user_messages(username: str):
    """
    Get messages with user with given username as recipient.
    :param username: username of user of which to which the messages are sent
    :return: list of messages if successful
    :return: An empty list if an Exception was raised.
    """
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


def confirm_friend(user1: str, user2: str):
    """
    Update table to confirm friendship.
    :param user1: username of user who sent friend request
    :param user2: username of user who received friend request
    :return: True if successful
    :return: False if an Exception was raised
    """
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


def exists_friend_or_request(user1: str, user2: str):
    """
    Check if a confirmed or unconfirmed friendship exists in database
    :param user1: username of one of the users the friendship should exist between
    :param user2: username of the other of the users the friendship should exist between
    :return: True if a confirmed or unconfirmed friendship exists
    :return: False if no friendship exists
    :return: False if an Exception was raised
    """
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


def delete_message(message_id: int):
    """
    Delete row from messages table with given id
    :param message_id: id of message that should be deleted
    :return: True if successful
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("DELETE FROM messages WHERE id=?;", (message_id,))
        db.commit()
        return True
    except Exception as e:
        print("In db.delete_message: ", e)
        return False


def delete_all_messages_asked_question(username: str):
    """
    Delete all messages notifying that someone asked the user a new question
    :param username: username of user to whom the messages, that should be deleted, are
    :return: True if successful
    :return: False if an Exception was raised
    """
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


def delete_all_messages_answered_question(username: str):
    """
    Delete all messages notifying that someone answered a question the user asked
    :param username: username of user to whom the messages, that should be deleted, are
    :return: True if successful
    :return: False if an Exception was raised
    """
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


def get_friends(username: str):
    """
    Get all confirmed friends of the given user
    :param username: username whose friends are to be returned
    :return: list of confirmed friends of a given user if successful
    :return: An empty list if an Exception was raised or no friends where found
    """
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


def delete_friends_from_db(user1: str, user2: str):
    """
    Delete friendship from database
    :param user1: One of the users between which the friendship is
    :param user2: The other one of the users between which the friendship is
    :return: True if successful
    :return: False if an Exception was raised
    """
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


def get_questions_from_user(username: str):
    """
    Get questions the user with given username asked
    :param username: username of user who asked the question
    :return: list of questions if successful
    :return: An empty list if an Exception was raised or no question was found
    """
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


def get_questions_for_user(username: str):
    """
    Get questions the user with given username WAS asked
    :param username: username of user who was assigned to the question
    :return: list of questions if successful
    :return: An empty list if an Exception was raised or no question was found
    """
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


def add_question(sender: str, recipient: str, question: str):
    """
    Add new question from given sender to given recipient with given text to database
    :param sender: username of user who asked the question
    :param recipient: username of user who was assigned to the question
    :param question: text of the question
    :return: True if successful
    :return: False if an Exception was raised
    """
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


def get_question(question_id: int):
    """
    Get question row of question with given id.
    :param question_id: id of question to be returned
    :return: id, sender, recipient, text and answer to question with given id
    :return: False if an Exception was raised
    """
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


def add_answer(question_id: int, answer: str):
    """
    Update answer of question with given id
    :param question_id: id of question the answer should be updated of
    :param answer: Answer to question with given id
    :return: True if successful
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE questions SET answer=? WHERE id=?;", (answer, question_id))
        db.commit()
        return True
    except Exception as e:
        print("In db.add_answer: ", e)
        return ""


def get_email_preferences_not(username: str):
    """
    Get opt out preferences for email notification of user with given username
    :param username: username of user with to get opt out preferences
    :return: list of events the users does not want to receive notifications for if successful
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        email_preferences_not = cur.execute("SELECT email_preferences_not FROM users WHERE username=?;",
                                            (username, )).fetchone()[0].split(",")
        return email_preferences_not
    except Exception as e:
        print("In db.get_email_preferences_not: ", e)
        return False


def update_email_preferences(username: str, email_preferences_not: list):
    """
    Update opt out email preferences
    :param username: username of user to update opt out preferences for
    :param email_preferences_not: list of events the user does not want to get notifications for
    :return: True if successful
    :return: False if an Exception was raised
    """
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE users SET email_preferences_not=? WHERE username=?;",
                    (",".join(email_preferences_not), username))
        db.commit()
        return True
    except Exception as e:
        print("In db.update_email_preferences: ", e)
        return False
