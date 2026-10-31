from flask import Flask, make_response

import custom_session_lib

app = Flask(__name__)


def create_sessions():
    response = make_response()
    custom_session_lib.create_plain(response, "plain session")
    custom_session_lib.create_encrypted(response, "encrypted session")
    custom_session_lib.create_theme(response, "dark")
    return response
