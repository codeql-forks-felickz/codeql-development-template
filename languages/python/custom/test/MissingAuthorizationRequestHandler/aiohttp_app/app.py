from aiohttp.web import Application

from .views import setup_routes


def init():
    app = Application(debug=True)
    setup_routes(app)
    return app
