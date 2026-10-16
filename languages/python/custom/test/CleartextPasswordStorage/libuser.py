import os
import sqlite3
from binascii import hexlify

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from werkzeug.security import generate_password_hash


def create(username, password):  # $ Source
    conn = sqlite3.connect("db_users.sqlite")
    c = conn.cursor()
    c.execute(
        "INSERT INTO users (username, password, failures) VALUES ('%s', '%s', '%d')"
        % (username, password, 0)  # $ Alert
    )
    conn.commit()


def password_change(username, password):  # $ Source
    conn = sqlite3.connect("db_users.sqlite")
    c = conn.cursor()
    c.execute("UPDATE users SET password = '{}' WHERE username = '{}'".format(password, username))  # $ Alert
    conn.commit()


def password_change_param(username, new_password):  # $ Source
    conn = sqlite3.connect("db_users.sqlite")
    conn.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))  # $ Alert
    conn.commit()


def register_fstring(username, passwd):  # $ Source
    conn = sqlite3.connect("db_users.sqlite")
    conn.execute(f"INSERT INTO users (username, passwd) VALUES ('{username}', '{passwd}')")  # $ Alert


# --- Safe cases ---


def password_set(username, password):
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password.encode())
    conn = sqlite3.connect("db_users.sqlite")
    conn.execute(
        "UPDATE users SET password = ?, salt = ? WHERE username = ?",
        (hexlify(key).decode(), hexlify(salt).decode(), username),
    )


def register_hashed(username, password):
    hashed = generate_password_hash(password)
    conn = sqlite3.connect("db_users.sqlite")
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))


def login(username, password):
    conn = sqlite3.connect("db_users.sqlite")
    # Safe for this query: reading, not storing, the password (SQL injection is a separate query).
    return conn.execute(
        "SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)
    ).fetchone()


def rename(username, new_name):
    conn = sqlite3.connect("db_users.sqlite")
    # Safe: no password is written.
    conn.execute("UPDATE users SET username = ? WHERE username = ?", (new_name, username))
