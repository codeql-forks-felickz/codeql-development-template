import logging
import os

from flask import Blueprint

bp = Blueprint("logging_hook", __name__)


def log_request():
    logging.info("request received")


bp.before_request(log_request)


@bp.route("/logging_only")
def logging_only():  # $ Alert[py/missing-authentication-sensitive-route]
    os.system("reboot")
