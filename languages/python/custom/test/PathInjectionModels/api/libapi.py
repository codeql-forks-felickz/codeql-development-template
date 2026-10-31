import glob
from pathlib import Path

from flask import Flask, request  # $ Source[py/path-injection]

app = Flask(__name__)


@app.route("/key", methods=["POST"])
def keygen():
    username = request.get_json()["username"]
    for f in Path("/tmp/").glob("vulpy.apikey." + username + ".*"):  # $ Alert[py/path-injection]
        f.unlink()
    for f in Path("/tmp/").rglob("vulpy.apikey." + username + ".*"):  # $ Alert[py/path-injection]
        f.unlink()
    for name in glob.glob("/tmp/vulpy.apikey." + username + ".*"):  # $ Alert[py/path-injection]
        print(name)
    for name in glob.iglob(pathname="/tmp/vulpy.apikey." + username + ".*"):  # $ Alert[py/path-injection]
        print(name)
    return "ok"


@app.route("/key-safe", methods=["POST"])
def keygen_safe():
    username = request.get_json()["username"]
    if username not in ("alice", "bob"):
        return "invalid", 400
    for f in Path("/tmp/").glob("vulpy.apikey." + username + ".*"):
        f.unlink()
    for name in glob.glob("/tmp/vulpy.apikey.*"):
        print(name)
    return "ok"
