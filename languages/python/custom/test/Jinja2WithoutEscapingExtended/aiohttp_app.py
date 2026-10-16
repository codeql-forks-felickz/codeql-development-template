import aiohttp_jinja2
import jinja2
from aiohttp.web import Application
from aiohttp_jinja2 import setup as setup_jinja
from jinja2.loaders import PackageLoader


def bad_aliased():
    app = Application()
    # BAD: autoescaping globally disabled (dvpwa pattern).
    setup_jinja(app, loader=PackageLoader("app", "templates"), context_processors=[], autoescape=False)  # $ Alert
    return app


def bad_module_attr():
    app = Application()
    # BAD: autoescaping globally disabled.
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader("templates"), autoescape=False)  # $ Alert
    return app


def bad_via_variable():
    app = Application()
    escape = False
    # BAD: `False` flows into the `autoescape` argument.
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader("templates"), autoescape=escape)  # $ Alert
    return app


def good_default():
    app = Application()
    # GOOD: aiohttp_jinja2.setup enables autoescaping by default.
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader("templates"))
    return app


def good_explicit():
    app = Application()
    # GOOD: autoescaping explicitly enabled.
    setup_jinja(app, loader=PackageLoader("app", "templates"), autoescape=True)
    return app


def good_select():
    app = Application()
    # GOOD: extension-based autoescaping.
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader("templates"), autoescape=jinja2.select_autoescape())
    return app
