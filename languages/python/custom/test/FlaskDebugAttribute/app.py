import os
from os import getenv

from flask import Flask

app = Flask(__name__)


# NON_COMPLIANT: environment variable lookup with a truthy default.
def env_default_true():
    app.debug = os.environ.get("FLASK_DEBUG", True)  # $ Alert
    app.run(port=7000)


# NON_COMPLIANT: any non-empty string is truthy, including "False" and "0".
def env_default_string_false():
    app.debug = os.environ.get("FLASK_DEBUG", "False")  # $ Alert
    app.run()


# NON_COMPLIANT: `os.getenv` with a truthy keyword default.
def getenv_default():
    app.debug = getenv("FLASK_DEBUG", default="1")  # $ Alert
    app.run()


# NON_COMPLIANT: debug enabled via attribute instead of `run(debug=True)`.
def literal_true():
    app.debug = True  # $ Alert
    app.run(host="0.0.0.0")


# NON_COMPLIANT: value flows through a local variable.
def via_variable():
    debug = os.environ.get("FLASK_DEBUG", True)
    app.debug = debug  # $ Alert
    app.run()


# COMPLIANT: no default, so debug is off unless explicitly configured.
def env_no_default():
    app.debug = os.environ.get("FLASK_DEBUG")
    app.run()


# COMPLIANT: falsy default.
def env_default_false():
    app.debug = os.environ.get("FLASK_DEBUG", False)
    app.run()


# COMPLIANT: falsy (empty string) default.
def env_default_empty_string():
    app.debug = os.environ.get("FLASK_DEBUG", "")
    app.run()


# COMPLIANT: the environment value is parsed into a real boolean.
def env_parsed():
    app.debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run()


# COMPLIANT: debug disabled.
def literal_false():
    app.debug = False
    app.run()


# COMPLIANT: an explicit `debug` argument to `run` overrides `app.debug`
# (and a truthy one is already reported by `py/flask-debug`).
def overridden_by_run_keyword():
    app.debug = True
    app.run(debug=False)


# COMPLIANT: positional `debug` argument overrides `app.debug`.
def overridden_by_run_positional():
    app.debug = True
    app.run("127.0.0.1", 5000, False)


# COMPLIANT: `run` blocks, so setting `debug` afterwards has no effect.
def set_after_run():
    app.run()
    app.debug = True


# COMPLIANT: the app is never run with the development server here.
def never_run():
    app.debug = True
    return app


# COMPLIANT: not a Flask application.
class NotFlask:
    def run(self):
        pass


def not_flask():
    other = NotFlask()
    other.debug = True
    other.run()


if __name__ == "__main__":
    app.debug = os.environ.get('FLASK_DEBUG', True)  # $ Alert
    app.run(port=7000)
