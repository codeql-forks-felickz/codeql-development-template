import logging
import sqlite3

import pyotp


def login(username, password):  # $ Source[py/sqlite-trace-callback-sensitive-logging]
    conn = sqlite3.connect("db_users.sqlite")
    conn.set_trace_callback(print)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    user = c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)).fetchone()  # $ Alert[py/sqlite-trace-callback-sensitive-logging]
    return user


def mfa_reset_secret(username):
    secret = pyotp.random_base32()  # $ Source[py/sqlite-trace-callback-sensitive-logging]
    conn = sqlite3.connect("db_users.sqlite")
    conn.set_trace_callback(print)
    c = conn.cursor()
    c.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (secret, username))  # $ Alert[py/sqlite-trace-callback-sensitive-logging]
    conn.commit()
    return True


def password_change(username, password):  # $ Source[py/sqlite-trace-callback-sensitive-logging]
    conn = sqlite3.connect("db_users.sqlite")
    conn.set_trace_callback(logging.getLogger(__name__).debug)
    conn.execute("UPDATE users SET password = ? WHERE username = ?", [password, username])  # $ Alert[py/sqlite-trace-callback-sensitive-logging]
    conn.commit()


def login_untraced(username, password):
    # Safe: no trace callback on the connection.
    conn = sqlite3.connect("db_users.sqlite")
    c = conn.cursor()
    return c.execute("SELECT * FROM users WHERE username = ? and password = ?", (username, password)).fetchone()


def login_trace_disabled(username, password):
    # Safe: tracing explicitly disabled.
    conn = sqlite3.connect("db_users.sqlite")
    conn.set_trace_callback(None)
    c = conn.cursor()
    return c.execute("SELECT * FROM users WHERE username = ? and password = ?", (username, password)).fetchone()


def login_trace_after(username, password):
    # Safe: tracing enabled only after the sensitive statement ran.
    conn = sqlite3.connect("db_users.sqlite")
    c = conn.cursor()
    user = c.execute("SELECT * FROM users WHERE username = ? and password = ?", (username, password)).fetchone()
    conn.set_trace_callback(print)
    return user


def list_users(username):
    # Safe: traced connection, but no sensitive data in the statement.
    conn = sqlite3.connect("db_users.sqlite")
    conn.set_trace_callback(print)
    c = conn.cursor()
    return c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()


def other_connection(password):
    # Safe: the traced connection is not the one executing the sensitive statement.
    traced = sqlite3.connect("audit.sqlite")
    traced.set_trace_callback(print)
    conn = sqlite3.connect("db_users.sqlite")
    return conn.execute("SELECT * FROM users WHERE password = ?", (password,)).fetchone()
