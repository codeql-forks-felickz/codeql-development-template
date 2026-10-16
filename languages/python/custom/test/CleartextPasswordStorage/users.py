import sqlite3

from flask import Blueprint, jsonify, request

bp = Blueprint("users", __name__)


def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect("database.db") as conn:
        cur = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()


@bp.route("/create_user", methods=["POST"])
def create_user():
    username = request.form.get("username")
    password = request.form.get("password")  # $ Source
    access_level = request.form.get("access_level")
    query = (
        "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
        % (username, password, int(access_level))  # $ Alert
    )
    query_db(query, [], False, True)
    return jsonify({"success": True})
