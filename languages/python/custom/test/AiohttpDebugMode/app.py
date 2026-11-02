import os
from aiohttp import web
from aiohttp.web import Application


def init_bad():
    app = Application(debug=True, middlewares=[])  # $ Alert
    return app


def init_bad_web():
    debug = True
    return web.Application(debug=debug)  # $ Alert


def init_good():
    # Safe: debug mode is explicitly disabled.
    return web.Application(debug=False)


def init_good_default():
    # Safe: debug mode defaults to off.
    return web.Application()


def init_env():
    # Safe: debug mode is controlled by configuration, not hard-coded on.
    return web.Application(debug=os.environ.get("DEBUG") == "1")


def init_good_handler_override():
    return web.Application(debug=True, handler_args={"debug": False})


def init_bad_handler_override():
    return web.Application(debug=True, handler_args={"debug": True})  # $ Alert
