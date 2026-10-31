import traceback
from flask import Flask, render_template

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
