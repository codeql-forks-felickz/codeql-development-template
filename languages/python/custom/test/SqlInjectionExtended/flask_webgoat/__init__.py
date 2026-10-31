# SQL text is built by the caller and executed by an application-specific wrapper
# (pattern reduced from a deliberately vulnerable demo application).
import sqlite3

DB_FILENAME = "database.db"


def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        cur = conn.cursor().execute(query, args)  # $ Alert[py/sql-injection]
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()
