import os

from flask import Blueprint
from external_authentication import require_login

bp = Blueprint("unresolved_hook", __name__)
bp.before_request(require_login)


@bp.route("/unresolved_hook")
def unresolved_hook():
    os.system("reboot")
