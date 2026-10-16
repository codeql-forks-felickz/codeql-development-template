import glob
from pathlib import Path

from flask import Flask, request  # $ Source[py/path-injection]

app = Flask(__name__)


@app.route("/api/post", methods=["POST"])
def authenticate_bad():
    # Attacker-controlled API key is used as part of a glob pattern. A value such
    # as `*` matches any existing key file, bypassing authentication (CWE-288).
    key = request.headers["X-APIKEY"]
    for f in Path("/tmp/").glob("vulpy.apikey.*." + key):  # $ Alert[py/path-injection]
        return f.name.split(".")[2]
    return None


@app.route("/api/rglob")
def rglob_bad():
    pattern = request.args["pattern"]
    return [str(p) for p in Path("/srv/data").rglob(pattern)]  # $ Alert[py/path-injection]


@app.route("/api/rglob-kw")
def rglob_keyword_bad():
    pattern = request.args["pattern"]
    return [str(p) for p in Path("/srv/data").rglob(pattern=pattern)]  # $ Alert[py/path-injection]


@app.route("/api/glob-module")
def glob_module_bad():
    name = request.args["name"]
    return glob.glob("/srv/data/" + name)  # $ Alert[py/path-injection]


@app.route("/api/iglob-module")
def iglob_module_bad():
    name = request.args["name"]
    return list(glob.iglob(pathname="/srv/data/" + name))  # $ Alert[py/path-injection]


KNOWN_KEYS = {"0123abcd": "alice"}


@app.route("/api/post-safe", methods=["POST"])
def authenticate_good():
    # Safe: the attacker-controlled key is compared against a fixed mapping and
    # never used to build a glob pattern.
    key = request.headers["X-APIKEY"]
    return KNOWN_KEYS.get(key)


@app.route("/api/list-safe")
def glob_constant_good():
    # Safe: constant glob pattern, no user input involved.
    return [str(p) for p in Path("/tmp/").glob("vulpy.apikey.*")]
