from app_factory import create_app
from flask import Blueprint

app = create_app()
bp = Blueprint("bp", __name__)


@app.after_request
def add_csp_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # $ Alert
    response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"  # $ Alert
    return response


@bp.after_app_request
def add_blueprint_headers(response):
    response.headers.add("Access-Control-Allow-Origin", "*")  # $ Alert
    return response


def not_a_hook(response):
    # Not registered as an after-request hook, so `response` is not known to be a Flask response.
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response
