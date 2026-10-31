import sqlite3


def query_db(query, args=(), commit=False):
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        return cursor.fetchall()
