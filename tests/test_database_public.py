"""
Test student-created SQL scripts.

EECS 485 Project 2

Andrew DeOrio <awdeorio@umich.edu>
"""


def test_sql_schema(db_connection):
    """Verify schema.sql produces correct tables.

    Note: 'db_connection' is a fixture fuction that provides an empty,
    in-memory sqlite3 database.  It is implemented in conftest.py and reused by
    many tests.  Docs: https://docs.pytest.org/en/latest/fixture.html
    """
    # Load student schema.sql
    with open("sql/schema.sql") as infile:
        schema_sql = infile.read()
    assert "PRAGMA foreign_keys = ON" in schema_sql
    db_connection.executescript(schema_sql)
    db_connection.commit()

    # Verify column names in users table
    cur = db_connection.execute("PRAGMA table_info('users')")
    schema = cur.fetchall()
    columns = [i["name"] for i in schema]
    assert set(columns) == set((
        'username', 'fullname', 'email', 'filename', 'password', 'created',
    ))

    # Verify column names in posts table
    cur = db_connection.execute("PRAGMA table_info('posts')")
    schema = cur.fetchall()
    columns = [i["name"] for i in schema]
    assert set(columns) == set(('postid', 'filename', 'owner', 'created'))

    # Verify column names in following table
    cur = db_connection.execute("PRAGMA table_info('following')")
    schema = cur.fetchall()
    columns = [i["name"] for i in schema]
    assert set(columns) == set(('username1', 'username2', 'created'))

    # Verify column names in comments table
    cur = db_connection.execute("PRAGMA table_info('comments')")
    schema = cur.fetchall()
    columns = [i["name"] for i in schema]
    assert set(columns) == set((
        'commentid', 'owner', 'postid', 'text', 'created',
    ))

    # Verify column names in likes table
    cur = db_connection.execute("PRAGMA table_info('likes')")
    schema = cur.fetchall()
    columns = [i["name"] for i in schema]
    assert set(columns) == set(('owner', 'postid', 'created'))


def test_sql_data_users_posts(db_connection):
    """Verify data.sql produces correct tables: users, posts.

    Note: 'db_connection' is a fixture fuction that provides an empty,
    in-memory sqlite3 database.  It is implemented in conftest.py and reused by
    many tests.  Docs: https://docs.pytest.org/en/latest/fixture.html
    """
    # Load student schema.sql and data.sql
    with open("sql/schema.sql") as infile:
        schema_sql = infile.read()
    with open("sql/data.sql") as infile:
        data_sql = infile.read()
    assert "PRAGMA foreign_keys = ON" in schema_sql
    assert "PRAGMA foreign_keys = ON" in data_sql
    db_connection.executescript(schema_sql)
    db_connection.executescript(data_sql)
    db_connection.commit()

    # Verify data in users table
    cur = db_connection.execute(
        "SELECT username, email, fullname, filename FROM users"
    )
    users = cur.fetchall()
    assert users == [
        {
            'username': 'awdeorio',
            'email': 'awdeorio@umich.edu',
            'fullname': 'Andrew DeOrio',
            'filename': 'e1a7c5c32973862ee15173b0259e3efdb6a391af.jpg',
        },
        {
            'username': 'jflinn',
            'email': 'jflinn@umich.edu',
            'fullname': 'Jason Flinn',
            'filename': '505083b8b56c97429a728b68f31b0b2a089e5113.jpg',
        },
        {
            'username': 'michjc',
            'email': 'michjc@umich.edu',
            'fullname': 'Michael Cafarella',
            'filename': '5ecde7677b83304132cb2871516ea50032ff7a4f.jpg',
        },
        {
            'username': 'jag',
            'email': 'jag@umich.edu',
            'fullname': 'H.V. Jagadish',
            'filename': '73ab33bd357c3fd42292487b825880958c595655.jpg',
        },
    ]

    # Verify data in posts table
    cur = db_connection.execute("SELECT postid, owner, filename FROM posts")
    posts = cur.fetchall()
    assert posts == [
        {
            'filename': '122a7d27ca1d7420a1072f695d9290fad4501a41.jpg',
            'owner': 'awdeorio',
            'postid': 1,
        },
        {
            'filename': 'ad7790405c539894d25ab8dcf0b79eed3341e109.jpg',
            'owner': 'jflinn',
            'postid': 2,
        },
        {
            'filename': '9887e06812ef434d291e4936417d125cd594b38a.jpg',
            'owner': 'awdeorio',
            'postid': 3,
        },
        {
            'filename': '2ec7cf8ae158b3b1f40065abfb33e81143707842.jpg',
            'owner': 'jag',
            'postid': 4,
        }
    ]
