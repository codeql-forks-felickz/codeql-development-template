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


@app.route("/flask-overwritten")
def flask_overwritten():
    # GOOD: the unpacked user value is overwritten with a constant before the nested read
    _, target = ("", request.args["next"])
    target = "/home"
    return redirect((lambda: target)())


@app.route("/flask-unpacked-captured")
def flask_unpacked_captured():
    _, target = ("", request.args["next"])
    # BAD: unpacked user value read in a nested scope
    return redirect((lambda: target)())  # $ Alert
