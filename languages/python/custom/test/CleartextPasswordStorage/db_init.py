import sqlite3


def db_init_users():
    users = [
        ("admin", "SuperSecret"),  # $ Source
        ("elliot", "123123123"),  # $ Source
    ]
    conn = sqlite3.connect("db_users.sqlite")
    c = conn.cursor()
    c.execute("CREATE TABLE users (username text, password text, failures int)")
    for u, p in users:
        c.execute(
            "INSERT INTO users (username, password, failures) VALUES ('%s', '%s', '%d')"
            % (u, p, 0)  # $ Alert
        )


def create_app_db():
    conn = sqlite3.connect("database.db")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS user
    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, access_level INTEGER)"""
    )
    insert_admin_query = """INSERT INTO user (id, username, password, access_level)
    VALUES (1, 'admin', 'maximumentropy', 0)"""  # $ Alert
    conn.execute(insert_admin_query)
    conn.commit()


# --- Safe cases ---


def create_placeholder_user(username):
    conn = sqlite3.connect("db_users.sqlite")
    # Safe: the password column is set to an empty placeholder and hashed later.
    conn.execute(
        "INSERT INTO users (username, password, salt, failures) VALUES ('%s', '%s', '%s', '%d')"
        % (username, "", "", 0)
    )


def seed_names():
    conn = sqlite3.connect("db_users.sqlite")
    # Safe: hard-coded values are not written to the password column.
    for name, role in [("admin", "root"), ("guest", "viewer")]:
        conn.execute("INSERT INTO users (username, role) VALUES (?, ?)", (name, role))
    conn.execute("UPDATE users SET role = 'admin' WHERE username = 'admin' AND password = ?", ("x",))


def seed_hashed(conn):
    conn.execute(
        "INSERT INTO users (username, password) VALUES ('carol', '$2b$12$abcdefghijklmnopqrstuv')"
    )
