import os

from flask import Blueprint, abort, jsonify, session

bp = Blueprint("admin", __name__)


@bp.before_request
def require_login():
    if "user_info" not in session:
        abort(401)


# COMPLIANT: every route in this blueprint is protected by a before_request hook
@bp.route("/admin/restart")
def restart():
    os.system("systemctl restart app")
    return jsonify({"success": True})
