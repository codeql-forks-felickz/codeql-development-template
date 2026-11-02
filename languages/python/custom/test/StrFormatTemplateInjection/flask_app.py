import os
import string

from flask import Flask, request  # $ Source

app = Flask(__name__)


class Config:
    SECRET_KEY = "not-a-real-secret"


@app.route("/render")
def render():
    tmpl = request.args["tmpl"]
    out = []
    out.append(tmpl.format(open(__file__), os))  # $ Alert
    out.append(tmpl.format(cfg=Config()))  # $ Alert
    out.append(tmpl.format_map({"env": os.environ}))  # $ Alert
    out.append(string.Formatter().format(tmpl, Config()))  # $ Alert
    out.append(string.Formatter().vformat(tmpl, (Config(),), {}))  # $ Alert
    out.append(string.Formatter().vformat(format_string=tmpl, args=(Config(),), kwargs={}))  # $ Alert
    return "".join(out)


@app.route("/safe")
def safe():
    tmpl = request.args["tmpl"]
    out = []
    # Safe: the format string is a constant and only the argument is user-controlled.
    out.append("Hello {}".format(tmpl))
    out.append("{name}".format_map({"name": tmpl}))
    out.append(string.Formatter().format("Hello {}", tmpl))
    # Safe: nothing to traverse.
    out.append(tmpl.format())
    out.append(tmpl.format("literal", 1))
    out.append(tmpl.format_map({}))
    out.append(tmpl.format_map({"name": "x"}))
    out.append(tmpl.format(*[], **{}))
    out.append(string.Formatter().vformat(tmpl, (), {}))
    out.append(string.Formatter().vformat(format_string=tmpl, args=(), kwargs={}))
    # Safe: compared against a constant.
    if tmpl == "{0.name}":
        out.append(tmpl.format(Config()))
    return "".join(out)
