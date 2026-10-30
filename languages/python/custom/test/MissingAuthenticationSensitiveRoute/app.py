import os

from flask import Flask, jsonify
from flask_login import login_required

app = Flask(__name__)


# NON_COMPLIANT: shell execution on an unauthenticated app route
@app.route("/reboot", methods=["POST"])
def reboot():  # $ Alert[py/missing-authentication-sensitive-route]
    os.system("reboot")
    return jsonify({"success": True})


# COMPLIANT: protected by flask_login.login_required
@app.route("/reboot_protected", methods=["POST"])
@login_required
def reboot_protected():
    os.system("reboot")
    return jsonify({"success": True})


# COMPLIANT: no dangerous operation
@app.route("/")
def index():
    return jsonify({"hello": "world"})
