import os

from flask import Blueprint, Flask, abort, session

first_app = Flask("first")
second_app = Flask("second")
bp = Blueprint("shared", __name__)


@bp.before_app_request
def require_login():
    if not session.get("user_id"):
        abort(401)


@bp.route("/blueprint_protected")
def blueprint_protected():
    os.system("reboot")


first_app.register_blueprint(bp)


@first_app.route("/same_app_protected")
def same_app_protected():
    os.system("reboot")


@second_app.route("/other_app")
def other_app():  # $ Alert[py/missing-authentication-sensitive-route]
    os.system("reboot")
