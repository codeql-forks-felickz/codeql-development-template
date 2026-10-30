import os

from flask import Blueprint, abort, session

bp = Blueprint("callback_hooks", __name__)


def require_login():
    if not session.get("user_id"):
        abort(401)


bp.before_request(require_login)


@bp.route("/callback_protected")
def callback_protected():
    os.system("reboot")
