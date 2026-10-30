from flask import Flask, request, redirect  # $ Source

app = Flask(__name__)


@app.route("/flask-redirect")
def flask_redirect():
    # BAD: already reported by the upstream py/url-redirection query
    return redirect(request.args.get("next"))  # $ Alert


@app.route("/flask-safe")
def flask_safe():
    # GOOD: constant redirect target
    return redirect("/home")
