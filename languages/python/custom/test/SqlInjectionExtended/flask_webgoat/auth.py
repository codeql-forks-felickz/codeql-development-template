from flask import Blueprint, jsonify, request  # $ Source[py/sql-injection]

from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
    # Already reported by `py/sql-injection` (at the `execute` call in `query_db`),
    # so the extended query must not report it again.
    username = request.form.get("username")
    password = request.form.get("password")
    query = (
        "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
        % (username, password)
    )
    return jsonify(query_db(query, [], True))


@bp.route("/login_safe", methods=["POST"])
def login_safe():
    # GOOD: parameter binding
    username = request.form.get("username")
    password = request.form.get("password")
    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    return jsonify(query_db(query, (username, password), True))
