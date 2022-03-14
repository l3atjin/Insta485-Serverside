"""
Insta485 index (main) view.

URLs include:
/
"""
import flask
from flask import send_from_directory
import uuid
import hashlib
import pathlib
import insta485
import arrow
import os


@insta485.app.route('/uploads/<path:filename>')
def download_file(filename):
    return send_from_directory(insta485.app.config['UPLOAD_FOLDER'],
                               filename)


# Show Index
@insta485.app.route('/', methods=['POST', 'GET'])
def show_index():
    """Show A Page."""
    if "logname" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    logname = flask.session["logname"]
    connection = insta485.model.get_db()

    if flask.request.method == 'POST':
        postid = int(flask.request.form.get("postid").strip("/"))
        like = str(flask.request.form.get("like"))
        unlike = str(flask.request.form.get("unlike"))
        text = str(flask.request.form.get("text"))

        # Like Form
        if like == "like":
            connection.execute(
                "INSERT INTO likes(owner, postid) "
                "VALUES(?, ?) ",
                (logname, postid, )
            )

        # Unlike Form
        elif unlike == "unlike":
            connection.execute(
                "DELETE FROM likes "
                "WHERE owner=? AND postid=? ",
                (logname, postid, )
            )

        # Comment Form
        elif text:
            connection.execute(
                "INSERT INTO comments(owner, postid, text) "
                "VALUES(?, ?, ?) ",
                (logname, int(postid), text, )
            )

    # Get all users logname is following
    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 = ?",
        (logname, )
    )
    following = cur.fetchall()

    # JOIN users and posts
    cur = connection.execute(
        "SELECT users.fullname, posts.postid, posts.filename, "
        "posts.owner, users.filename AS profilename, posts.created "
        "FROM users "
        "INNER JOIN posts ON users.username=posts.owner "
    )
    posts = cur.fetchall()

    # Get Likes
    cur = connection.execute(
        "SELECT * "
        "FROM likes "
    )
    likes = cur.fetchall()

    # Get Likes
    cur = connection.execute(
        "SELECT postid "
        "FROM likes "
        "WHERE owner=? ",
        (logname, )
    )
    log_likes = cur.fetchall()
    log_likes_list = []

    for li in log_likes:
        log_likes_list.append(li["postid"])

    final_posts = []
    following_users = []

    for fol in following:
        following_users.append(fol["username2"])

    for post in posts:
        if post["owner"] == logname or post["owner"] in following_users:
            count = 0
            for like in likes:
                if like["postid"] == post["postid"]:
                    count += 1
            post["likes"] = count
            post["created"] = str(arrow.get(post["created"]).humanize())
            final_posts.append(post)

    cur = connection.execute(
        "SELECT postid, filename "
        "FROM posts "
        "WHERE owner = ? ",
        (logname, )
    )
    logposts = cur.fetchall()

    # Get comments
    cur = connection.execute(
        "SELECT * "
        "FROM comments "
    )
    comments = cur.fetchall()

    # Add database info to context
    context = {"logposts": logposts, "posts": final_posts,
               "following": following, "comments": comments,
               "likes": likes, "logname": logname, "log_likes": log_likes_list}

    return flask.render_template("index.html", **context)


# Show User
@insta485.app.route('/u/<username>/', methods=['POST', 'GET'])
def show_user(username):
    """Show A Page."""
    if "logname" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    else:
        logname = flask.session["logname"]
        connection = insta485.model.get_db()

    if flask.request.method == 'POST':
        follow = str(flask.request.form.get("follow"))
        profname = str(flask.request.form.get("username"))
        unfollow = str(flask.request.form.get("unfolow"))
        logout = str(flask.request.form.get("logout"))
        filename = str(flask.request.form.get("file"))

        if flask.request.files["file"]:
            # Unpack flask object
            fileobj = flask.request.files["file"]

            # Compute base name (filename without directory).
            # clashes with existing files, and
            # filesystem.
            uuid_basename = "{stem}{suffix}".format(
                stem=uuid.uuid4().hex,
                suffix=pathlib.Path(filename).suffix
            )
            # Save to diskd
            path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
            fileobj.save(path)

            # Delete old Profile Picture !

            # Post New Post
            connection.execute(
                "INSERT INTO posts(owner, filename) "
                "VALUES(?, ?) ",
                (logname, str(uuid_basename),)
            )

        # Follow Form
        if follow == "follow":
            connection.execute(
                "INSERT INTO following(username1, username2) "
                "VALUES(?, ?) ",
                (logname, profname,)
            )

        # Unfollow Form
        elif unfollow == "unfollow":
            connection.execute(
                "REMOVE * FROM following "
                "WHERE username1=?, username2=? ",
                (logname, profname, )
            )
        # Logout Form
        elif logout == "Logout":
            return flask.redirect(flask.url_for('show_logout'))

    # Check if User exists
    cur = connection.execute(
        "SELECT * "
        "FROM users "
        "WHERE username = ?",
        (username, )
    )
    if not cur:
        return flask.abort(404)

    # Get all users logname is following
    cur = connection.execute(
        "SELECT * "
        "FROM posts "
        "WHERE owner = ?",
        (username, )
    )
    posts = cur.fetchall()
    total_posts = len(posts)

    cur = connection.execute(
        "SELECT * "
        "FROM following "
        "WHERE username1 = ?",
        (username, )
    )
    following = cur.fetchall()
    following_num = len(following)

    cur = connection.execute(
        "SELECT * "
        "FROM following "
        "WHERE username2 = ?",
        (username, )
    )
    followers = cur.fetchall()
    followers_num = len(followers)

    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 = ? ",
        (logname, )
    )
    log_followers = cur.fetchall()

    # Add database info to context
    context = {"log_followers": log_followers, "username": username,
               "logname": logname, "total_posts": total_posts, "posts": posts,
               "following": following_num, "followers": followers_num}

    return flask.render_template("user.html", **context)


# Show Followers
@insta485.app.route('/u/<username>/followers/', methods=['POST', 'GET'])
def show_followers(username):
    """Show A Page."""
    if "logname" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    else:
        logname = flask.session["logname"]
        connection = insta485.model.get_db()

    if flask.request.method == 'POST':
        follow = str(flask.request.form.get("follow"))
        profname = str(flask.request.form.get("username"))
        unfollow = str(flask.request.form.get("unfollow"))
        print(follow, unfollow, profname)
        # Follow Form
        if follow == "follow":
            print("HERE")
            connection.execute(
                "INSERT INTO following(username1, username2) "
                "VALUES(?, ?) ",
                (logname, profname, )
            )

        # Unfollow Form
        elif unfollow == "unfollow":
            print("HERE")
            connection.execute(
                "DELETE FROM following "
                "WHERE username1=? AND username2=? ",
                (logname, profname, )
            )

    # Check if User exists
    cur = connection.execute(
        "SELECT * "
        "FROM users "
        "WHERE username = ? ",
        (username, )
    )
    if not cur:
        return flask.abort(404)

    # Get all users logname is following
    followers_list = []

    cur = connection.execute(
        "SELECT * "
        "FROM users "
    )
    users = cur.fetchall()

    cur = connection.execute(
        "SELECT * "
        "FROM following "
        "WHERE username2 = ?",
        (username, )
    )
    followers = cur.fetchall()

    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 = ? ",
        (logname, )
    )
    log_followers = cur.fetchall()

    for fol in log_followers:
        followers_list.append(fol["username2"])

    for fol in followers:
        for us in users:
            if fol["username1"] == us["username"]:
                fol["profilename"] = us["filename"]

    # Add database info to context
    context = {"username": username, "logname": logname,
               "followers": followers,
               "followers_list": followers_list}

    return flask.render_template("followers.html", **context)


# Show Following
@insta485.app.route('/u/<username>/following/', methods=['POST', 'GET'])
def show_following(username):
    """Show A Page."""
    if "logname" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    else:
        logname = flask.session["logname"]
        connection = insta485.model.get_db()

    if flask.request.method == 'POST':
        follow = str(flask.request.form.get("follow"))
        profname = str(flask.request.form.get("username"))
        unfollow = str(flask.request.form.get("unfollow"))
        print(flask.request.form)
        print(follow, profname, unfollow)
        # Follow Form
        if follow == "follow":
            connection.execute(
                "INSERT INTO following(username1, username2) "
                "VALUES(?, ?) ",
                (logname, profname, )
            )

        # Unfollow Form
        elif unfollow == "unfollow":
            connection.execute(
                "DELETE FROM following "
                "WHERE username1=? AND username2=? ",
                (logname, profname, )
            )

    # Check if User exists
    cur = connection.execute(
        "SELECT * "
        "FROM users "
        "WHERE username = ? ",
        (username, )
    )
    if not cur:
        return flask.abort(404)
    # Get all users logname is following
    followers_list = []

    cur = connection.execute(
        "SELECT * "
        "FROM users "
    )
    users = cur.fetchall()

    cur = connection.execute(
        "SELECT * "
        "FROM following "
        "WHERE username1 = ?",
        (username, )
    )
    followers = cur.fetchall()

    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 = ?",
        (logname, )
    )
    log_followers = cur.fetchall()

    for fol in log_followers:
        followers_list.append(fol["username2"])

    for fol in followers:
        for us in users:
            if fol["username2"] == us["username"]:
                fol["profilename"] = us["filename"]
        print(fol)

    # Add database info to context
    context = {"username": username, "logname": logname,
               "followers": followers,
               "log_followers": followers_list}

    return flask.render_template("following.html", **context)


# Show Explore
@insta485.app.route('/explore/', methods=['POST', 'GET'])
def show_explore():
    """Show A Page."""
    if "logname" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    else:
        logname = flask.session["logname"]
        connection = insta485.model.get_db()

    if flask.request.method == 'POST':
        follow = str(flask.request.form.get("follow"))
        username = str(flask.request.form.get("username"))
        unfollow = str(flask.request.form.get("unfolow"))

        # Follow Form
        if follow:
            connection.execute(
                "INSERT INTO following(username1, username2) "
                "VALUES(?, ?) ",
                (logname, username, )
            )

        # Unfollow Form
        elif unfollow:
            connection.execute(
                "REMOVE * FROM following "
                "WHERE username1=?, username2=? ",
                (logname, username, )
            )

    # Get Stuff
    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 = ? ",
        (logname, )
    )
    log_following = cur.fetchall()

    loglist = []

    for el in log_following:
        loglist.append(el["username2"])

    cur = connection.execute(
        "SELECT * "
        "FROM users "
    )
    users = cur.fetchall()
    stranger_list = []

    for user in users:
        if user["username"] not in loglist and user["username"] != logname:
            stranger_list.append(user)

    context = {"logname": logname, "strangers": stranger_list}
    return flask.render_template("explore.html", **context)


# Show Post
@insta485.app.route('/p/<postid>/', methods=['POST', 'GET'])
def show_post(postid):
    """Show A Page."""
    if "logname" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    else:
        logname = flask.session["logname"]
        connection = insta485.model.get_db()

    if flask.request.method == 'POST':
        pid = str(flask.request.form.get("postid"))
        like = str(flask.request.form.get("like"))
        unlike = str(flask.request.form.get("unlike"))
        comment = str(flask.request.form.get("comment"))
        text = str(flask.request.form.get("text"))
        commentid = str(flask.request.form.get("commentid"))
        uncomment = str(flask.request.form.get("uncomment"))
        deletecom = str(flask.request.form.get("delete"))
        print(text)
        # Like Form
        if like == "like":
            connection.execute(
                "INSERT INTO likes(owner, postid) "
                "VALUES(?, ?) ",
                (logname, pid, )
            )

        # Unlike Form
        elif unlike == "unlike":
            connection.execute(
                "DELETE FROM likes "
                "WHERE owner=? AND postid=? ",
                (logname, int(pid),)
            )

        # Comment Form
        elif comment == "comment":
            connection.execute(
                "INSERT INTO comments(owner, postid, text) "
                "VALUES(?, ?, ?) ",
                (logname, pid, text,)
            )

        # Delete Comment Form
        elif uncomment == "delete":
            # Check if User Authorized
            cur = connection.execute(
                "SELECT * "
                "FROM comments "
                "WHERE postid = ? AND owner=? ",
                (pid, logname, )
            )
            if not cur:
                return flask.abort(403)

            # Delete Comment
            connection.execute(
                "DELETE FROM comments "
                "WHERE owner=? AND commentid=? ",
                (logname, commentid, )
            )

        # Delete Post Form
        elif deletecom:
            # Check if User Authorized
            cur = connection.execute(
                "SELECT * "
                "FROM posts "
                "WHERE postid = ? AND owner = ? ",
                (pid, commentid, )
            )
            if not cur:
                return flask.abort(403)

            # Delete Post
            connection.execute(
                "DELETE FROM posts "
                "WHERE postid=? ",
                (pid, )
            )

    # Get posts
    cur = connection.execute(
        "SELECT * "
        "FROM posts "
    )
    posts = cur.fetchall()
    mainpost = posts[0]

    for post in posts:
        if int(postid) == post["postid"]:
            print("changed mianpost")
            mainpost = post
    print(mainpost)

    mainpost["created"] = str(arrow.get(mainpost["created"]).humanize())

    cur = connection.execute(
        "SELECT * "
        "FROM users "
        "WHERE username=? ",
        (mainpost["owner"], )
    )
    post_owner = cur.fetchall()

    cur = connection.execute(
        "SELECT * "
        "FROM comments "
        "WHERE postid=? ",
        (int(postid), )
    )
    comments = cur.fetchall()

    cur = connection.execute(
        "SELECT * "
        "FROM likes "
    )
    likes = cur.fetchall()

    count = 0
    for like in likes:
        if like["postid"] == int(postid):
            count += 1

    context = {"comments": comments, "logname": logname,
               "mainpost": mainpost, "post_owner": post_owner,
               "likes": count}
    return flask.render_template("post.html", **context)


# Show Create
@insta485.app.route('/accounts/create/', methods=['POST', 'GET'])
def show_create():
    """Show A Page."""
    # Redirect if logged in
    if "logname" in flask.session:
        return flask.redirect(flask.url_for('show_edit'))

    connection = insta485.model.get_db()
    # Else create Account
    if flask.request.method == 'POST':
        profilename = ""
        # Get form info
        username = str(flask.request.form.get("username"))
        fullname = str(flask.request.form.get("fullname"))
        filename = str(flask.request.form.get("file"))
        email = str(flask.request.form.get("email"))
        password = str(flask.request.form.get("password"))

        if flask.request.files["file"]:
            # Unpack flask object
            fileobj = flask.request.files["file"]

            # Compute base name (filename without directory).
            # We use a UUID to avoid
            # clashes with existing files, and ensure that
            # the name is compatible with the
            # filesystem.
            uuid_basename = "{stem}{suffix}".format(
                stem=uuid.uuid4().hex,
                suffix=pathlib.Path(profilename).suffix
            )
            # Save to diskd
            path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
            fileobj.save(path)

            # Delete old Profile Picture !

            profilename = uuid_basename

        # Check for Invalid Info
        if not password:
            return flask.abort(400)

        cur = connection.execute(
            "SELECT * "
            "FROM users "
            "WHERE username=? ",
            (username, )
        )
        users = cur.fetchall()
        if bool(users):
            return flask.abort(409)

        # Encrypt Password
        algorithm = 'sha512'
        salt = uuid.uuid4().hex
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + password
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_db_string = "$".join([algorithm, salt, password_hash])

        # Add User to Table
        if profilename == "":
            connection.execute(
                "INSERT INTO users(username, fullname, email, password) "
                "VALUES (?, ?, ?, ?, ?) ",
                (username, fullname, email, password_db_string, )
            )
        else:
            connection.execute(
                "INSERT INTO users "
                "(username, fullname, email, filename, password) "
                "VALUES (?, ?, ?, ?, ?) ",
                (username, fullname, email, str(profilename),
                 password_db_string,)
            )

        # Log in and Redirect
        flask.session["logname"] = username
        return flask.redirect(flask.url_for('show_index'))

    else:
        return flask.render_template("create.html")


# Show Delete
@insta485.app.route('/accounts/delete/', methods=['POST', 'GET'])
def show_delete():
    """Show A Page."""
    if "logname" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session["logname"]

    if flask.request.method == 'POST':
        confirm = str(flask.request.form.get("delete"))
        if confirm == "confirm delete account":
            # Delete Account
            connection = insta485.model.get_db()
            connection.execute(
                "DELETE FROM users "
                "WHERE username=? ",
                (logname,)
            )
            return flask.redirect(flask.url_for('show_create'))
    else:
        context = {"logname": logname}
        return flask.render_template("delete.html", **context)


# Show Logout
@insta485.app.route('/accounts/logout', methods=['POST'])
def show_logout():
    """Show A Page."""
    flask.session.pop("logname")
    return flask.redirect(flask.url_for('show_login'))


# Show Edit
@insta485.app.route('/accounts/edit/', methods=['POST', 'GET'])
def show_edit():
    """Show A Page."""
    if "logname" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    logname = flask.session["logname"]
    connection = insta485.model.get_db()

    if flask.request.method == 'POST':
        profilename = str(flask.request.form.get("file"))
        fullname = str(flask.request.form.get("fullname"))
        email = str(flask.request.form.get("email"))
        print(profilename)
        if flask.request.files["file"]:
            # Unpack flask object
            fileobj = flask.request.files["file"]
            # Compute base name (filename without directory).
            # We use a UUID to avoid
            # clashes with existing files, and ensure that
            # the name is compatible with the
            # filesystem.
            uuid_basename = "{stem}{suffix}".format(
                stem=uuid.uuid4().hex,
                suffix=pathlib.Path(fileobj.filename).suffix
            )
            print(pathlib.Path(profilename).suffix)
            # Save to diskd
            path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
            fileobj.save(path)

            # Delete old Profile Picture !

            # Update Profile Picture
            connection.execute(
                "UPDATE users "
                "SET filename = ? "
                "WHERE username=? ",
                (str(uuid_basename), logname, )
            )
        # Update Account
        connection.execute(
            "UPDATE users "
            "SET filename = ?, fullname = ?, email = ? "
            "WHERE username=?",
            (uuid_basename, fullname, email, logname, )
        )
    # GET
    cur = connection.execute(
        "SELECT * "
        "FROM users "
        "WHERE username=? ",
        (logname, )
    )
    username = cur.fetchall()

    context = {"user": username, "logname": logname}
    return flask.render_template("edit.html", **context)


# Show Password
@insta485.app.route('/accounts/password/', methods=['POST', 'GET'])
def show_password():
    """Show A Page."""
    # Redirect if logged in
    if "logname" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    logname = flask.session["logname"]
    connection = insta485.model.get_db()

    # Else Change Password
    if flask.request.method == 'POST':

        # Get form info
        password = str(flask.request.form.get("password"))
        newpassword = str(flask.request.form.get("new_password1"))
        newpassconf = str(flask.request.form.get("new_password2"))
        submit = str(flask.request.form.get("update_password"))

        if submit == "submit":
            # Get Current user and password
            cur = connection.execute(
                "SELECT username, password "
                "FROM users "
                "WHERE username=?",
                (logname, )
            )
            correct = cur.fetchall()
            passparts = correct[0]["password"].split('$')

            # Encrypt + Try attempted password
            algorithm = 'sha512'
            salt = passparts[1]
            hash_obj = hashlib.new(algorithm)
            password_salted = salt + password
            hash_obj.update(password_salted.encode('utf-8'))
            password_hash = hash_obj.hexdigest()
            attemptpassword = "$".join([algorithm, salt, password_hash])

            # Check Validity of Passwords
            if not attemptpassword == correct[0]["password"]:
                return flask.abort(403)
            if not newpassconf == newpassword:
                return flask.abort(401)

            # Encrypt new password
            hash_obj = hashlib.new(algorithm)
            password_salted = salt + newpassword
            hash_obj.update(password_salted.encode('utf-8'))
            password_hash = hash_obj.hexdigest()
            encrypted_password = "$".join([algorithm, salt, password_hash])

            # Update Password
            connection.execute(
                "UPDATE users "
                "SET password = ? "
                "WHERE username=?",
                (encrypted_password, logname, )
            )
            return flask.redirect(flask.url_for('show_edit'))

    context = {"logname": logname}
    return flask.render_template("password.html", **context)


# Show Login
@insta485.app.route('/accounts/login/', methods=['POST', 'GET'])
def show_login():
    """Show A Page."""
    connection = insta485.model.get_db()
    # Else, commence login
    if flask.request.method == 'POST':
        username = str(flask.request.form.get("username"))
        password = str(flask.request.form.get("password"))

        # Get user and password
        cur = connection.execute(
            "SELECT username, password "
            "FROM users "
            "WHERE username=?",
            (username, )
        )
        correct = cur.fetchall()

        passparts = correct[0]["password"].split('$')
        # Encrypt
        algorithm = 'sha512'
        salt = passparts[1]
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + password
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        attemptpassword = "$".join([algorithm, salt, password_hash])

        if username == correct[0]["username"] and attemptpassword == correct[0]["password"]:
            flask.session["logname"] = username
            return flask.redirect(flask.url_for('show_index'))
        else:
            flask.abort(403)

    else:
        return flask.render_template("login.html")
