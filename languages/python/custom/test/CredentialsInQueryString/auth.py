from flask import Blueprint, Flask, jsonify, request

bp = Blueprint("auth", __name__)
app = Flask(__name__)


def query_db(query, args, one=False):
    return None


@bp.route("/login_and_redirect")
def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")  # $ Alert[py/credentials-in-query-string]
    url = request.args.get("url")
    if username is None or password is None or url is None:
        return jsonify({"error": "missing parameters"}), 400
    query = "SELECT id FROM user WHERE username = ? AND password = ?"
    return jsonify(query_db(query, (username, password), True))


@app.route("/login_subscript")
def login_subscript():
    passwd = request.args["passwd"]  # $ Alert[py/credentials-in-query-string]
    return jsonify(passwd)


@app.route("/login_getlist")
def login_getlist():
    pw = request.args.getlist("user_password")  # $ Alert[py/credentials-in-query-string]
    return jsonify(pw)


@app.route("/login", methods=["POST"])
def login_post():
    # Safe: credentials read from the POST body.
    username = request.form.get("username")
    password = request.form.get("password")
    return jsonify(query_db("SELECT 1", (username, password), True))


@app.route("/search")
def search():
    # Safe: non-credential query string parameters.
    term = request.args.get("q")
    page = request.args["page"]
    return jsonify(term + page)


@app.route("/reset")
def reset():
    # Safe: names that only mention passwords but are not credentials.
    return jsonify(request.args.get("password_reset_url"))
