from flask import Flask, make_response

app = Flask(__name__)

app.config["SESSION_COOKIE_SECURE"] = False  # BAD: session cookie sent over plain HTTP
app.config["SESSION_COOKIE_HTTPONLY"] = False  # BAD: session cookie readable by JavaScript
app.config.update(SESSION_COOKIE_HTTPONLY=False)  # BAD
app.config.update({"SESSION_COOKIE_SECURE": False})  # BAD
app.config.from_mapping(SESSION_COOKIE_SECURE=False, SESSION_COOKIE_HTTPONLY=False)  # BAD (both)

app.config["SESSION_COOKIE_SECURE"] = True  # GOOD
app.config["SESSION_COOKIE_HTTPONLY"] = True  # GOOD
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True)  # GOOD
app.config["SESSION_COOKIE_NAME"] = "False"  # GOOD: not a security flag
app.config["SESSION_COOKIE_SAMESITE"] = False  # GOOD: not modeled by these queries

not_flask = {}
not_flask["SESSION_COOKIE_SECURE"] = False  # GOOD: not a Flask application config


def create_app():
    # GOOD: the setting is absent; Flask defaults to `SESSION_COOKIE_SECURE = False`, but an
    # absent setting is deliberately not reported (heuristic, out of scope for high precision).
    other = Flask("other")
    return other


@app.route("/cookie")
def set_cookie():
    resp = make_response()
    resp.set_cookie("sessionid", value="value", secure=False, httponly=False)  # BAD (existing upstream detection)
    resp.set_cookie("sessionid", value="value", secure=True, httponly=True)  # GOOD
    return resp
