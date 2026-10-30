import base64
import pickle
import subprocess

from flask import Blueprint, jsonify, request, session

bp = Blueprint("actions", __name__)


# NON_COMPLIANT: shell execution without any authentication check
@bp.route("/grep_processes")
def grep_processes():  # $ Alert[py/missing-authentication-sensitive-route]
    name = request.args.get("name")
    res = subprocess.run(
        ["ps aux | grep " + name + " | awk '{print $11}'"],
        shell=True,
        capture_output=True,
    )
    return jsonify({"success": True, "names": res.stdout.decode("utf-8").split("\n")})


# NON_COMPLIANT: pickle deserialization without any authentication check
@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():  # $ Alert[py/missing-authentication-sensitive-route]
    pickled = request.form.get("pickled")
    data = base64.urlsafe_b64decode(pickled)
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})


# COMPLIANT: the session is checked before the dangerous operation
@bp.route("/grep_processes_checked")
def grep_processes_checked():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})
    name = request.args.get("name")
    res = subprocess.run(["ps", "aux", name], capture_output=True)
    return jsonify({"success": True, "out": res.stdout.decode("utf-8")})


def login_required(f):
    def wrapper(*args, **kwargs):
        if "user_info" not in session:
            return jsonify({"error": "login required"}), 401
        return f(*args, **kwargs)

    return wrapper


# COMPLIANT: protected by an authentication decorator
@bp.route("/deserialized_descr_decorated", methods=["POST"])
@login_required
def deserialized_descr_decorated():
    data = base64.urlsafe_b64decode(request.form.get("pickled"))
    return jsonify({"description": str(pickle.loads(data))})


# COMPLIANT: no dangerous operation
@bp.route("/status")
def status():
    return jsonify({"success": True})
