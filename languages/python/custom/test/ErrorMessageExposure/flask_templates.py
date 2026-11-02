import traceback
from flask import Flask, render_template, stream_template

app = Flask(__name__)


@app.route("/a")
def a():
    try:
        return str(1 / 0)
    except ZeroDivisionError as e: # $ Source[py/error-message-exposure]
        return render_template("error.html", error=e) # $ Alert[py/error-message-exposure]


@app.route("/b")
def b():
    try:
        return str(1 / 0)
    except ZeroDivisionError:
        return render_template("error.html", trace=traceback.format_exc()) # $ Alert[py/error-message-exposure]


@app.route("/c")
def c():
    try:
        return str(1 / 0)
    except ZeroDivisionError:
        # Safe: generic message only.
        return render_template("error.html", error="Something went wrong")


@app.route("/unpacked-literal")
def unpacked_literal():
    try:
        return str(1 / 0)
    except ZeroDivisionError as e: # $ Source[py/error-message-exposure]
        return render_template("error.html", **{"error": e}) # $ Alert[py/error-message-exposure]


@app.route("/unpacked-context")
def unpacked_context():
    try:
        return str(1 / 0)
    except ZeroDivisionError as e: # $ Source[py/error-message-exposure]
        ctx = {"error": e}
        return render_template("error.html", **ctx) # $ Alert[py/error-message-exposure]


@app.route("/unpacked-safe")
def unpacked_safe():
    return render_template("error.html", **{"error": "Something went wrong"})


@app.route("/stream-unpacked")
def stream_unpacked():
    try:
        return str(1 / 0)
    except ZeroDivisionError as e: # $ Source[py/error-message-exposure]
        return stream_template("error.html", **{"error": e}) # $ Alert[py/error-message-exposure]


@app.route("/stream-unpacked-safe")
def stream_unpacked_safe():
    return stream_template("error.html", **{"error": "Something went wrong"})
