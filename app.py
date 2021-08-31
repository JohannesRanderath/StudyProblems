from flask import Flask, render_template, redirect, request, flash, send_from_directory, jsonify, url_for
from flask_session import Session

from session_handling import is_logged_in, current_user, logout_from_session, login_to_session
from patterns_and_types import check_password_requirements, is_email
from security import generate_password_hash, verify_password, decrypt_token, generate_password_reset_link, \
    generate_change_email_link, generate_email_confirmation_link
from mail import html_confirmation_email, html_change_mail_email, html_reset_password_mail, html_friend_request_mail, \
    html_accepted_friend_mail, html_new_question_mail, html_question_answered, send_email, send_user_email
from database import create_new_user, update_user_hash, update_user_email, update_email_confirmed, get_user_email,\
    get_username_by_email, close_connection, get_usernames_starting_with, user_exists, add_friend_request, add_message,\
    get_user_messages, confirm_friend, delete_message, get_friends, exists_friend_or_request, delete_friends_from_db, \
    get_questions_from_user, get_questions_for_user, add_question, get_question, question_exists, add_answer, \
    delete_all_messages_asked_question, delete_all_messages_answered_question, get_email_preferences_not, \
    update_email_preferences

app = Flask(__name__)
app.config.from_object("config.Config")

Session(app)


# TODO: Try to preserve form content when providing illegal parameters
# TODO: Project video
# TODO: Remove email password from config before submitting
# TODO: Remove debug print statements
# TODO: Clear database before submitting


def render_my_template(template: str, **kwargs):
    """
    For the badges indicating the number of messages and questions to update with every refresh, we need to calculate
    them every time we render a template. This function does these calculations and passes them as parameters to the
    desired template.
    :param template: html template the route function wants to render
    :param kwargs: parameters given by the route function
    :return: rendered template from flask.render_template with all required parameters
    """
    user = current_user()
    if user:
        # If the user is logged in, we can calculate the values by getting the values from the database
        num_of_messages = len(get_user_messages(user))
        questions_to_me = get_questions_for_user(user)
        num_of_questions_to_me = len(questions_to_me)
        num_of_unanswered_questions_to_me = len([question for question in questions_to_me
                                                 if not question["answer"]])
        questions_from_me = get_questions_from_user(user)
        num_of_questions_from_me = len(questions_from_me)
        num_of_unanswered_questions_from_me = len([question for question in questions_from_me
                                                   if not question["answer"]])
    else:
        # If no user is logged in, we don't need the values
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
@app.route("/favicon.ico")
def get_static_from_root():
    """
    Make robots.txt available to crawlers and styles.css as well as favicon.ico to browsers.
    :return: desired static file
    """
    return send_from_directory(app.static_folder, request.path[1:])


@app.route("/")
@is_logged_in
def home():
    """
    Home page displaying the messages.
    :return: index.html
    """
    messages = get_user_messages(current_user())
    # Display messages oldest to newest
    messages = list(reversed(messages))
    return render_my_template("index.html", messages=messages)


@app.route("/my_questions")
@is_logged_in
def my_questions():
    """
    Overview of all questions the user asked and their answers if available.
    :return: my_questions.html
    """
    questions = get_questions_from_user(current_user())
    # Display questions oldest to newest
    if questions:
        questions = list(reversed(questions))
    message_answered_question()
    return render_my_template("my_questions.html",  questions=questions)


@app.route("/to_answer", methods=["POST", "GET"])
@is_logged_in
def to_answer():
    """
    Overview of all questions assigned to the user, grouped by questions they haven't answered and those,
    they already answered.
    From this view they can choose which question to answer next and do so.
    :return: to_answer.html
    """
    questions = get_questions_for_user(current_user())
    # Display in oldest to newest
    if questions:
        questions = list(reversed(questions))
    unanswered_questions = [question for question in questions if not question["answer"]]
    answered_questions = [question for question in questions if question not in unanswered_questions]
    message_asked_question()
    return render_my_template("to_answer.html", unanswered_questions=unanswered_questions,
                              answered_questions=answered_questions)


@app.route("/manage_friends")
@is_logged_in
def manage_friends():
    """
    Overview of friends, functionality to remove some of them, ask them questions and send new friend requests.
    :return: friends.html
    """
    friends = get_friends(current_user())
    num_of_friends = len(friends)
    return render_my_template("friends.html", friends=friends, numOfFriends=num_of_friends)


@app.route("/get_usernames_list")
@is_logged_in
def get_usernames_list():
    """
    NO VIEW
    AJAX call to get usernames starting with a given substring.
    Used in user search to send friend requests
    :return: json list of usernames starting with substring <startswith> or an empty list if no substring given
    """
    startswith = request.args.get("startswith")
    if not startswith:
        # Do not expose all usernames. Return an empty list when no substring given
        return jsonify([])
    else:
        usernames = get_usernames_starting_with(startswith)
        usernames = [username[0] for username in usernames]
        if current_user() in usernames:
            usernames.remove(current_user())
        return jsonify(usernames)


@app.route("/add_friend", methods=["POST"])
@is_logged_in
def add_friend():
    """
    NO VIEW
    Logic function to add friend request to library and send notifications to other user.
    :return: redirect back to /manage_friends
    """
    username = request.form.get("username")
    user = current_user()
    # other user has to be given, must exist and can't be the same as the user logged in.
    if not username or username == user or not user_exists(username):
        flash("User not found", "danger")
        return redirect(url_for("manage_friends"))
    # There can be no more than one friend request / friend relationship between the same users
    if exists_friend_or_request(username, user):
        flash("You already are friends with that user or it exists a friend request.", "warning")
        return redirect(url_for("manage_friends"))
    if not add_friend_request(user, username):
        flash("An unexpected error occurred. Try again later.")
        return redirect(url_for("manage_friends"))
    # Send email notification if user wishes so and has a confirmed email.
    if "friend_request" not in get_email_preferences_not(username):
        send_user_email(username, "New friend request", html_friend_request_mail(user))
    if not add_message(user, username, "friend_request"):
        flash("An unexpected error occurred. Try again later.", "danger")
        return redirect(url_for("manage_friends"))
    flash("Friend request sent", "success")
    return redirect(url_for("manage_friends"))


@app.route("/accept_friend_request", methods=["POST"])
@is_logged_in
def accept_friend_request():
    """
    NO VIEW
    Logic function to confirm friend request in database and send notifications.
    :return: redirect to home (/)
    """
    username = current_user()
    if not confirm_friend(request.form.get("username"), username) \
            or not delete_message(request.form.get("message_id")):
        flash("An error occurred. Please try again later", "danger")
        return redirect(url_for("home"))
    add_message(username, request.form.get("username"), "accepted_friend_request")
    # if they didn't opt out and confirmed their email, send them an email.
    if "accepted_friend" not in get_email_preferences_not(request.form.get("username")):
        send_user_email(request.form.get("username"), "New friend", html_accepted_friend_mail(username))
    flash("Friend request accepted.", "success")
    return redirect(url_for("home"))


@app.route("/decline_friend_request", methods=["POST"])
@is_logged_in
def decline_friend_request():
    """
    NO VIEW
    Logic function to remove friend request and message from database and notify user.
    :return: redirect back to home (/)
    """
    if not delete_message(request.form.get("message_id")) \
            or not delete_friends_from_db(current_user(), request.form.get("username")):
        flash("An error occurred. Please try again later", "danger")
        return redirect(url_for("home"))
    add_message(current_user(), request.form.get("username"), "declined_friend_request")
    # No email is sent for declined requests
    flash("Friend request declined.", "important")
    return redirect(url_for("home"))


@app.route("/remove_friend",  methods=["POST"])
@is_logged_in
def remove_friend():
    """
    NO VIEW
    Logic function to remove friendship from database and notify former friend.
    :return: redirect back to /manage_friends
    """
    username = request.form.get("username")
    if not username or not delete_friends_from_db(current_user(), username) \
            or not delete_message(request.form.get("message_id")):
        flash("An error occurred, please try again later", "danger")
        return redirect(url_for("manage_friends"))
    add_message(current_user(), username, "removed_friend")
    # No email is sent for removed friends
    flash("Friend removed", "success")
    return redirect(url_for("manage_friends"))


@app.route("/discard_message", methods=["POST"])
@is_logged_in
def discard_message():
    """
    NO VIEW
    Logic function to remove read messages from database
    :return: redirect back to home (/)
    """
    if not delete_message(request.form.get("message_id")):
        flash("An error occurred, please try again.", "danger")
        return redirect(url_for("home"))
    flash("Message deleted.", "success")
    return redirect(url_for("home"))


@app.route("/ask_question", methods=["POST", "GET"])
@is_logged_in
def ask_question():
    """
    View to create new question and assign it to a friend.
    Adds question to database and notifies assigned friend.
    :return: redirect to all asked questions (/my_questions) if successful and back to ask_question if not.
    """
    if request.method == "POST":
        friend = request.form.get("friend")
        question = request.form.get("question")
        if not friend or not question:
            flash("Please supply all required parameters", "danger")
            return redirect(url_for("ask_question"))
        if not user_exists(friend):
            flash("User does not exist", "danger")
            return redirect(url_for("ask_question"))
        if not add_question(current_user(), friend, question):
            flash("An error occurred, please try again later", "danger")
            return redirect(url_for("ask_question"))
        add_message(current_user(), friend, "asked_question")
        if "new_question" not in get_email_preferences_not(friend):
            send_user_email(friend, "New question", html_new_question_mail(current_user()))
        flash("Question asked", "success")
        return redirect(url_for("my_questions"))
    else:
        # Get friends for dropdown with all friends to choose one to assign the question to
        # If clicked to ask a specific friend, preselect them.
        friends = get_friends(current_user())
        friend = request.args.get("friend")
        return render_my_template("ask_question.html", friends=friends, ask_friend=friend)


@app.route("/answer_question", methods=["POST", "GET"])
@is_logged_in
def answer_question():
    """
    View to answer question the user was assigned to by a friend.
    Adds answer to database and notifies friend
    :return: answer_question.html from get
    :return: redirect to /to_answer from post
    """
    if request.method == "POST":
        question_id = request.form.get("id")
        question = get_question(question_id)
        answer = request.form.get("answer")
        if not question_id or not answer:
            flash("Please supply all required parameters", "danger")
            return redirect(url_for("to_answer"))
        if not question_exists(question_id) or not question:
            flash("Question not found", "danger")
            return redirect(url_for("to_answer"))
        if not add_answer(question_id, answer):
            flash("An error occurred, please try again.", "danger")
            redirect(url_for("to_answer"))
        add_message(current_user(), question["sender"], "answered_question")
        # send email if user didn't opt out and confirmed their email.
        if "question_answered" not in get_email_preferences_not(question["sender"]):
            send_user_email(question["sender"], "Question answered", html_question_answered(current_user()))
        flash("Question answered", "success")
        return redirect(url_for("to_answer"))
    else:
        question_id = request.args.get("id")
        if not question_id:
            flash("Illegal parameters", "danger")
            return redirect(url_for("to_answer"))
        question = get_question(int(question_id))
        if not question:
            flash("Question not found", "danger")
            return redirect(url_for("to_answer"))
        if question["answer"]:
            flash("Question already answered.", "warning")
            return redirect(url_for("to_answer"))
        return render_my_template("answer_question.html", question=question)


@app.route("/message_asked_question", methods=["POST"])
@is_logged_in
def message_asked_question():
    """
    When clicked on message informing about a new question the user got assigned to,
    showing all questions they were assigned to. And deleting messages informing about
    new questions as they saw all of them now
    :return: redirect to /to_answer
    """
    delete_all_messages_asked_question(current_user())
    return redirect(url_for("to_answer"))


@app.route("/message_answered_question", methods=["POST"])
@is_logged_in
def message_answered_question():
    """
    When clicked on message informing about a new answer to a question the user asked,
    showing all questions they asked. And deleting messages informing about
    new answers as they saw all of them now
    :return: redirect to /my_questions
    """
    delete_all_messages_answered_question(current_user())
    return redirect(url_for("my_questions"))


@app.route("/account", methods=["POST", "GET"])
@is_logged_in
def account():
    """
    View to manage account related details
    1. Change password
    2. Change email or add new email if the user didn't add one before
    3. Update preferences for email notifications
    :return: account.html
    """
    if request.method == "POST":

        # 1. Change password
        if request.form.get("type") == "change_password":
            old_password = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirmation = request.form.get("confirmation")
            # Check given data and perform password change
            if not old_password:
                flash("Old password required", "warning")
                return redirect(url_for("account"))
            if not new_password:
                flash("New password required", "warning")
                return redirect(url_for("account"))
            if not confirmation:
                flash("Please confirm password", "warning")
                return redirect(url_for("account"))
            if not verify_password(current_user(), old_password):
                flash("Wrong password", "warning")
                return redirect(url_for("account"))
            if not new_password == confirmation:
                flash("Passwords do not match", "warning")
                return redirect(url_for("account"))
            if not update_user_hash(generate_password_hash(new_password), current_user()):
                flash("An unexpected error occurred. Please try again later", "danger")
                return redirect(url_for("account"))
            flash("Password changed", "success")
            return redirect(url_for("account"))

        # 2. Change account email
        if request.form.get("type") == "change_email":
            new_email = request.form.get("new_email")
            if not new_email:
                flash("new email required", "warning")
                return redirect(url_for("account"))
            old_email = get_user_email(current_user())
            # if the user never had an email in their account, we confirm as in the registration process
            if not old_email:
                if not update_user_email(current_user(), new_email):
                    flash("An unexpected error occurred. Please try again later", "danger")
                    return redirect(url_for("account"))
                if not send_email(new_email, "Please confirm your email",
                                  html_confirmation_email(generate_email_confirmation_link(
                                      new_email, app.config["EMAIL_CONFIRMATION_SALT"]))):
                    flash("An error occurred. Please try again later.", "danger")
                    return redirect(url_for("home"))
                flash("Email set", "success")
                return redirect(url_for("account"))
            # if there is already an email assigned to their account, we don't update this before they
            # didn't confirm the email
            else:
                if not send_email(new_email, "Confirm new email",
                                  html_change_mail_email(generate_change_email_link(old_email, new_email,
                                                                                    app.config["CHANGE_EMAIL_SALT"]))):
                    flash("An error occurred. Please try again later.", "danger")
                    return redirect(url_for("home"))
                flash("Confirmation link sent", "success")
                return redirect(url_for("account"))

        # 3. Update email preferences
        if request.form.get("type") == "email_preferences":
            # Save preferences as comma separated list in string to database
            email_preferences_not = []
            if not request.form.get("friend_request"):
                email_preferences_not.append("friend_request")
            if not request.form.get("accepted_friend"):
                email_preferences_not.append("accepted_friend")
            if not request.form.get("new_question"):
                email_preferences_not.append("new_question")
            if not request.form.get("question_answered"):
                email_preferences_not.append("question_answered")
            if not update_email_preferences(current_user(), email_preferences_not):
                flash("An error occurred, please try again later.", "danger")
                return redirect(url_for("home"))
            flash("Email preferences updated", "success")
            return redirect(url_for("account"))

    else:
        # Show logged in user and email preferences in account view.
        username = current_user()
        email_preferences_not = get_email_preferences_not(username)
        return render_my_template("account.html", username=username, email_preferences_not=email_preferences_not)


@app.route("/logout")
@is_logged_in
def logout():
    """
    NO VIEW
    Logic function to log user out
    Removes session and redirects to / (which is redirected to /login as they are no longer logged in)
    :return: redirect to home (/)
    """
    if not logout_from_session():
        flash("An error occurred, please try again", "danger")
        return redirect(url_for("home"))
    flash("You are now logged out", "success")
    return redirect(url_for("home"))


@app.route("/login", methods=["POST", "GET"])
def login():
    """
    View for user to log in.
    :return: login.html from get
    :return: redirect to home (/) if successful
    :return: redirect back to /login if unsuccessful
    """
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            flash("Username required", "warning")
            return redirect(url_for("login"))
        if not request.form.get("password"):
            flash("Password required", "warning")
            return redirect(url_for("login"))
        if not verify_password(username, request.form.get("password")):
            flash("Wrong username or password", "danger")
            return redirect(url_for("login"))
        if not login_to_session(username):
            flash("An error occurred, please try again.", "danger")
            return redirect(url_for("login"))
        flash("Login successful", "success")
        return redirect(url_for("home"))
    else:
        return render_my_template("login.html")


@app.route("/register", methods=["POST", "GET"])
def register():
    """
    View to register user.
    Logs user in automatically when successful.
    :return: register.html from get
    :return: redirect to home (/) when successful
    :return: redirect back to /register when unsuccessful
    """
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        # Check given data
        if not username:
            flash("Username required", "warning")
            return redirect(url_for("register"))
        if not password:
            flash("Password required", "warning")
            return redirect(url_for("register"))
        if not request.form.get("confirmation"):
            flash("Please confirm password", "warning")
            return redirect(url_for("register"))
        if user_exists(username):
            flash("Username already exists", "danger")
            return redirect(url_for("register"))
        if not password == request.form.get("confirmation"):
            flash("Passwords do not match", "warning")
            return redirect(url_for("register"))
        if not check_password_requirements(password):
            flash("Password does not meet requirements")
            return redirect(url_for("register"))

        # Register user
        if not create_new_user(username, generate_password_hash(password)):
            flash("An unexpected error occurred. Please try again later", "danger")
            return redirect(url_for("register"))
        # email is optional
        if email and is_email(email):
            update_user_email(username, email)
            if not send_email(email, "Please confirm your email",
                              html_confirmation_email(generate_email_confirmation_link(
                                  email, app.config["EMAIL_CONFIRMATION_SALT"]))):
                flash("An error occurred. Please try again later.", "danger")
                return redirect(url_for("register"))
        # Log in automatically
        if not login_to_session(username):
            flash("An error occurred, please try again", "danger")
            return render_my_template(url_for("register"))
        flash("You are successfully registered", "success")
        return redirect(url_for("home"))
    else:
        return render_my_template("register.html")


@app.route("/confirm/<token>")
def confirm(token):
    """
    Confirm email with link given in email
    Update email confirmed in database
    :param token: Token generated by itsdangerous
    :return: redirect to home (/)
    :return: bad_confirmation_link.html when unsuccessful
    """
    try:
        email = decrypt_token(token, app.config["EMAIL_CONFIRMATION_SALT"])
    except Exception as e:
        print(e)
        return render_my_template("bad_confirmation_link.html")
    if not update_email_confirmed(email):
        flash("An error occurred, please try again", "danger")
        return redirect(url_for("home"))
    flash("Email confirmed. Thank you", "success")
    return redirect(url_for("home"))


@app.route("/change_email/<token>")
def change_email(token):
    """
    Confirm email change in account that already had an email assigned to it.
    Updates email in database
    :param token: Token generated by itsdangerous
    :return: redirect to home (/) when successful
    :return: bad_change_email_link.html when unsuccessful
    """
    try:
        data = decrypt_token(token, app.config["CHANGE_EMAIL_SALT"])
        old_email = data["old_email"]
        new_email = data["new_email"]

        if not update_user_email(get_username_by_email(old_email), new_email):
            flash("An error occurred, please try again", "danger")
            return redirect(url_for("home"))

        flash("Email updated!", "success")
        return redirect(url_for("home"))
    except Exception as e:
        print(e)
        return render_my_template("bad_change_email_link.html")


@app.route("/reset_password/<token>", methods=["POST", "GET"])
def reset_password(token):
    """
    Reset password with password reset link.
    :param token: token generated by itsdangerous
    :return: reset_password.html from get if link valid
    :return: bad_password_reset_link.html if link not valid
    :return: redirect to /login if successful
    :return: redirect back to reset_password if unsuccessful
    """
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        if not username:
            flash("Username required", "warning")
            return render_my_template("reset_password.html", username=username)
        if not password:
            flash("Password required")
            return render_my_template("reset_password.html", username=username)
        if not confirmation:
            flash("Please confirm password", "warning")
            return render_my_template("reset_password.html", username=username)
        if not password == confirmation:
            flash("Passwords do not match", "warning")
            return render_my_template("reset_password.html", username=username)
        if not check_password_requirements(password):
            flash("Password does not meet criteria", "warning")
            return render_my_template("reset_password.html", username=username)

        if not update_user_hash(generate_password_hash(password), username):
            flash("An error occurred, please try again", "danger")
            return render_my_template("reset_password.html", username=username)

        flash("Password reset successfully", "success")
        return redirect(url_for("login"))
    else:
        try:
            username = decrypt_token(token, app.config["RESET_PASSWORD_SALT"])
            return render_my_template("reset_password.html", username=username)
        except Exception as e:
            print(e)
            return render_my_template("bad_password_reset_link.html")


@app.route("/request_password_reset", methods=["POST", "GET"])
def request_password_reset():
    """
    View to enter username from forgot password? link.
    Sends password reset mail to user if there is an email associated with their account.
    :return: request_password_reset.html
    """
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            flash("Username required", "warning")
            return render_my_template("request_password_reset.html")
        if not send_user_email(username, "Reset password",
                               html_reset_password_mail(generate_password_reset_link(
                                   username, app.config["RESET_PASSWORD_SALT"]))):
            flash("An error occurred. Probably the username doesn't exist or no email is associated with it.", "danger")
            return render_my_template("request_password_reset.html")
        flash("Reset link sent", "success")
        return render_my_template("request_password_reset.html")
    else:
        return render_my_template("request_password_reset.html")


@app.teardown_appcontext
def close_db(exception):
    """
    Close database on app closing.
    :param exception: From app.teardown_appcontext, is passed to database.py
    :return: None
    """
    close_connection(exception)


if __name__ == '__main__':
    app.run()
