from flask import Flask, render_template, redirect, request, flash, send_from_directory, jsonify
from flask_session import Session

from session_handling import is_logged_in, current_user, logout_from_session, login_to_session
from patterns_and_types import check_password_requirements, is_email
from security import generate_password_hash, verify_password, decrypt_token, generate_password_reset_link, \
    generate_change_email_link, generate_email_confirmation_link
from mail import html_confirmation_email, html_change_mail_email, html_reset_password_mail, html_friend_request_mail,\
    send_email, send_user_email
from database import create_new_user, update_user_hash, update_user_email, update_email_confirmed, get_user_email,\
    get_username_by_email, close_connection, get_usernames_starting_with, user_exists, add_friend_request, add_message,\
    get_user_messages, confirm_friend, delete_message, get_friends, exists_friend_or_request, delete_friends_from_db, \
    get_questions_from_user, get_questions_for_user, add_question, get_question, question_exists, add_answer, \
    delete_all_messages_asked_question, delete_all_messages_answered_question

app = Flask(__name__)
app.config.from_object("config.Config")

Session(app)


def render_my_template(template: str, **kwargs):
    user = current_user()
    if user:
        num_of_messages = len(get_user_messages(user))
        questions_to_me = get_questions_for_user(user)
        num_of_questions_to_me = len(questions_to_me)
        num_of_unanswered_questions_to_me = len([question for question in questions_to_me if not question["answer"]])
        questions_from_me = get_questions_from_user(user)
        num_of_questions_from_me = len(questions_from_me)
        num_of_unanswered_questions_from_me = len([question for question in questions_from_me if not question["answer"]])
    else:
        num_of_messages = None
        num_of_questions_to_me = None
        num_of_unanswered_questions_to_me = None
        num_of_questions_from_me = None
        num_of_unanswered_questions_from_me = None
    return render_template(template, num_of_messages=num_of_messages, num_of_questions_to_me=num_of_questions_to_me,
                           num_of_questions_from_me=num_of_questions_from_me,
                           num_of_unanswered_questions_to_me=num_of_unanswered_questions_to_me,
                           num_of_unanswered_questions_from_me=num_of_unanswered_questions_from_me,  **kwargs)


@app.route("/robots.txt")
@app.route("/styles.css")
def get_static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])


@app.route("/")
@is_logged_in
def home():
    messages = get_user_messages(current_user())
    return render_my_template("index.html", messages=messages)


@app.route("/my_questions")
@is_logged_in
def my_questions():
    questions = get_questions_from_user(current_user())
    return render_my_template("my_questions.html",  questions=questions)


@app.route("/to_answer", methods=["POST", "GET"])
@is_logged_in
def to_answer():
    questions = get_questions_for_user(current_user())
    unanswered_questions = [question for question in questions if not question["answer"]]
    answered_questions = [question for question in questions if question["answer"]]
    return render_my_template("to_answer.html", unanswered_questions=unanswered_questions,
                           answered_questions=answered_questions)


@app.route("/manage_friends")
@is_logged_in
def manage_friends():
    friends = get_friends(current_user())
    num_of_friends = len(friends)
    return render_my_template("friends.html", friends=friends, numOfFriends=num_of_friends)


@app.route("/get_usernames_list")
@is_logged_in
def get_usernames_list():
    startswith = request.args.get("startswith")
    if not startswith:
        return jsonify([])
    else:
        usernames = get_usernames_starting_with(startswith)
        usernames = [username[0] for username in usernames]
        usernames.remove(current_user())
        return jsonify(usernames)


@app.route("/add_friend", methods=["POST"])
@is_logged_in
def add_friend():
    username = request.form.get("username")
    user = current_user()
    if not username or username == user or not user_exists(username):
        flash("User not found", "danger")
        return redirect("/manage_friends")
    if exists_friend_or_request(username, user):
        flash("You already are friends with that user or it exists a friend request.", "warning")
        return redirect("/manage_friends")
    if not add_friend_request(user, username):
        flash("An unexpected error occurred. Try again later.")
        return redirect("/manage_friends")
    send_user_email(username, "New friend request", html_friend_request_mail(user))
    if not add_message(user, username, "friend_request"):
        flash("An unexpected error occurred. Try again later.", "danger")
        return redirect("/manage_friends")
    flash("Friend request sent", "success")
    return redirect("/manage_friends")


@app.route("/accept_friend_request", methods=["POST"])
@is_logged_in
def accept_friend_request():
    if not confirm_friend(request.form.get("username"), current_user()) \
            or not delete_message(request.form.get("message_id")):
        flash("An error occurred. Please try again later", "danger")
        return redirect("/")
    add_message(current_user(), request.form.get("username"), "accepted_friend_request")
    flash("Friend request accepted.", "success")
    return redirect("/")


@app.route("/decline_friend_request", methods=["POST"])
@is_logged_in
def decline_friend_request():
    if not delete_message(request.form.get("message_id")):
        flash("An error occurred. Please try again later", "danger")
        return redirect("/")
    add_message(current_user(), request.form.get("username"), "declined_friend_request")
    flash("Friend request declined.", "important")
    return redirect("/")


@app.route("/remove_friend",  methods=["POST"])
@is_logged_in
def remove_friend():
    username = request.form.get("username")
    if not username or not delete_friends_from_db(current_user(), username) \
            or not delete_message(request.form.get("message_id")):
        flash("An error occurred, please try again later", "danger")
        return redirect("/manage_friends")
    add_message(current_user(), username, "removed_friend")
    flash("Friend removed", "success")
    return redirect("/manage_friends")


@app.route("/discard_message", methods=["POST"])
@is_logged_in
def discard_message():
    if not delete_message(request.form.get("message_id")):
        flash("An error occurred, please try again.", "danger")
        return redirect("/")
    flash("Message deleted.", "success")
    return redirect("/")


@app.route("/ask_question", methods=["POST", "GET"])
@is_logged_in
def ask_question():
    if request.method == "POST":
        friend = request.form.get("friend")
        question = request.form.get("question")
        if not friend or not question:
            flash("Please supply all required parameters", "danger")
            return redirect("/ask_question")
        if not user_exists(friend):
            flash("User does not exist", "danger")
            return redirect("/ask_question")
        if not add_question(current_user(), friend, question):
            flash("An error occurred, please try again later", "danger")
            return redirect("/ask_question")
        add_message(current_user(), friend, "asked_question")
        flash("Question asked", "success")
        return redirect("/my_questions")
    else:
        friends = get_friends(current_user())
        friend = request.args.get("friend")
        return render_my_template("ask_question.html", friends=friends, ask_friend=friend)


@app.route("/answer_question", methods=["POST", "GET"])
@is_logged_in
def answer_question():
    if request.method == "POST":
        question_id = request.form.get("id")
        question = get_question(question_id)
        answer = request.form.get("answer")
        if not question_id or not answer:
            flash("Please supply all required parameters", "danger")
            return redirect("/")
        if not question_exists(question_id) or not question:
            flash("Question not found", "danger")
            return redirect("/")
        if not add_answer(question_id, answer):
            flash("An error occurred, please try again.", "danger")
            redirect("/")
        print(add_message(current_user(), question["sender"], "answered_question"))
        flash("Question answered", "success")
        return redirect("/")
    else:
        question_id = request.args.get("id")
        if not question_id:
            flash("Illegal parameters", "danger")
            return redirect("/")
        question = get_question(question_id)
        if not question:
            flash("Question not found", "danger")
            return redirect("/")
        if question["answer"]:
            flash("Question already answered.", "warning")
            return redirect("/")
        return render_my_template("answer_question.html", question=question)


@app.route("/message_asked_question", methods=["POST"])
@is_logged_in
def message_asked_question():
    delete_all_messages_asked_question(current_user())
    return redirect("/to_answer")


@app.route("/message_answered_question", methods=["POST"])
@is_logged_in
def message_answered_question():
    delete_all_messages_answered_question(current_user())
    return redirect("/my_questions")


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
                return redirect("account.html")
            if not new_password:
                flash("New password required", "warning")
                return redirect("account.html")
            if not confirmation:
                flash("Please confirm password", "warning")
                return redirect("account.html")
            if not verify_password(current_user(), old_password):
                flash("Wrong password", "warning")
                return redirect("account.html")
            if not new_password == confirmation:
                flash("Passwords do not match", "warning")
                return redirect("account.html")
            if not update_user_hash(generate_password_hash(new_password), current_user()):
                flash("An unexpected error occurred. Please try again later", "danger")
                return redirect("account.html")
            flash("Password changed", "success")
            return redirect("account.html")
        if request.form.get("type") == "change_email":
            new_email = request.form.get("new_email")
            if not new_email:
                flash("new email required", "warning")
                return redirect("account.html")
            old_email = get_user_email(current_user())
            if not old_email:
                if not update_user_email(current_user(), new_email):
                    flash("An unexpected error occurred. Please try again later", "danger")
                    return render_my_template("account.html")
                flash("Email set", "success")
                return redirect("account.html")
            else:
                if not send_email(new_email, "Confirm new email",
                                  html_change_mail_email(generate_change_email_link(old_email, new_email))):
                    flash("An error occurred. Please try again later.", "danger")
                    return redirect("/")
                flash("Confirmation link sent", "success")
                return redirect("account.html")
    else:
        return render_my_template("account.html", username=current_user())


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
            return render_my_template("login.html")
        if not request.form.get("password"):
            flash("Password required", "warning")
            return render_my_template("login.html")
        if not verify_password(username, request.form.get("password")):
            flash("Wrong username or password", "danger")
            return render_my_template("login.html")
        if not login_to_session(username):
            flash("An error occurred, please try again.", "danger")
            return render_my_template("login.html")
        flash("Login successful", "success")
        return redirect("/")
    else:
        return render_my_template("login.html")


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        if not username:
            flash("Username required", "warning")
            return render_my_template("register.html")
        if not password:
            flash("Password required", "warning")
            return render_my_template("register.html")
        if not request.form.get("confirmation"):
            flash("Please confirm password", "warning")
            return render_my_template("register.html")
        if get_user_email(username):
            flash("Username already exists", "danger")
            return render_my_template("register.html")
        if not password == request.form.get("confirmation"):
            flash("Passwords do not match", "warning")
            return render_my_template("register.html")
        if not check_password_requirements(password):
            flash("Password does not meet requirements")
            return render_my_template("register.html")

        if not create_new_user(username, generate_password_hash(password)):
            flash("An unexpected error occurred. Please try again later", "danger")
            return render_my_template("register.html")
        if email and is_email(email):
            update_user_email(username, email)
            if not send_email(email, "Please confirm your email",
                              html_confirmation_email(generate_email_confirmation_link(email))):
                flash("An error occurred. Please try again later.", "danger")
                return redirect("/")
        if not login_to_session(username):
            flash("An error occurred, please try again", "danger")
            return render_my_template("register.html")
        flash("You are successfully registered", "success")
        return redirect("/login")
    else:
        return render_my_template("register.html")


@app.route("/confirm/<token>")
def confirm(token):
    try:
        email = decrypt_token(token, "email-confirmation-key")
    except Exception as e:
        print(e)
        return render_my_template("bad_confirmation_link.html")
    if not update_email_confirmed(email):
        flash("An error occurred, please try again", "danger")
        return render_my_template("register.html")
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
        return render_my_template("bad_change_email_link.html")


@app.route("/reset_password/<token>", methods=["POST", "GET"])
def reset_password(token):
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        if not username:
            flash("Username required", "warning")
            return render_my_template("reset_password.html")
        if not password:
            flash("Password required")
            return render_my_template("reset_password.html")
        if not confirmation:
            flash("Please confirm password", "warning")
            return render_my_template("reset_password.html")
        if not password == confirmation:
            flash("Passwords do not match", "warning")
            return render_my_template("reset_password.html")
        if not check_password_requirements(password):
            flash("Password does not meet criteria", "warning")
            return render_my_template("reset_password.html")

        if not update_user_hash(generate_password_hash(password), username):
            flash("An error occurred, please try again", "danger")
            return render_my_template("reset_password.html")

        flash("Password reset successfully", "success")
        return redirect("/login")
    else:
        try:
            username = decrypt_token(token, "reset-password-key")
            return render_my_template("reset_password.html", username=username)
        except Exception as e:
            print(e)
            return render_my_template("bad_password_reset_link.html")


@app.route("/request_password_reset", methods=["POST", "GET"])
def request_password_reset():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            flash("Username required", "warning")
            return render_my_template("request_password_reset.html")
        if not send_user_email(username, "Reset password", html_reset_password_mail(generate_password_reset_link(username))):
            flash("An error occurred. Probably the username doesn't exist or no email is associated with it.", "danger")
            return render_my_template("request_password_reset.html")
        flash("Reset link sent", "success")
        return render_my_template("request_password_reset.html")
    else:
        return render_my_template("request_password_reset.html")


@app.teardown_appcontext
def close_db(exception):
    close_connection(exception)


if __name__ == '__main__':
    app.run()
