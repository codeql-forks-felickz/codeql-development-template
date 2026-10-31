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


# NON_COMPLIANT: debug enabled through the `DEBUG` config key.
def config_subscript_true():
    app.config["DEBUG"] = True  # $ Alert
    app.run()


# NON_COMPLIANT: `DEBUG` config key set from an environment variable with a truthy default.
def config_subscript_env_default():
    app.config["DEBUG"] = os.getenv("FLASK_DEBUG", "1")  # $ Alert
    app.run()


# NON_COMPLIANT: `DEBUG` set through `config.update`.
def config_update_true():
    app.config.update(DEBUG=True)  # $ Alert
    app.run()


# COMPLIANT: `DEBUG` config key disabled.
def config_subscript_false():
    app.config["DEBUG"] = False
    app.run()


# COMPLIANT: a different config key.
def config_other_key():
    app.config["TESTING"] = True
    app.run()


# COMPLIANT: an explicit `debug` argument to `run` overrides the config.
def config_overridden_by_run():
    app.config["DEBUG"] = True
    app.run(debug=False)


# COMPLIANT: `config.update` with a falsy `DEBUG`.
def config_update_false():
    app.config.update(DEBUG=False)
    app.run()


# COMPLIANT: not a Flask config mapping.
def not_flask_config():
    config = {}
    config["DEBUG"] = True
    app.run()


# COMPLIANT: the debug setting belongs to a different Flask application.
def debug_set_on_different_app():
    admin = Flask("admin")
    public = Flask("public")
    admin.debug = True
    public.run()


# COMPLIANT: the DEBUG config setting belongs to a different Flask application.
def config_set_on_different_app():
    admin = Flask("admin")
    public = Flask("public")
    admin.config["DEBUG"] = True
    public.run()


# COMPLIANT: the config.update setting belongs to a different Flask application.
def config_update_on_different_app():
    admin = Flask("admin")
    public = Flask("public")
    admin.config.update(DEBUG=True)
    public.run()


# COMPLIANT: a later config write disables debug mode before run().
def config_overwrites_attribute():
    app.debug = True
    app.config["DEBUG"] = False
    app.run()


# COMPLIANT: a later attribute write disables debug mode before run().
def attribute_overwrites_config():
    app.config["DEBUG"] = True
    app.debug = False
    app.run()


# COMPLIANT: a later config.update disables debug mode before run().
def update_overwrites_config():
    app.config["DEBUG"] = True
    app.config.update(DEBUG=False)
    app.run()


# NON_COMPLIANT: debug may still be enabled when the conditional overwrite is skipped.
def conditionally_overwritten():
    app.config["DEBUG"] = True  # $ Alert
    if os.getenv("DISABLE_DEBUG"):
        app.debug = False
    app.run()


if __name__ == "__main__":
    app.debug = os.environ.get('FLASK_DEBUG', True)  # $ Alert
    app.run(port=7000)
