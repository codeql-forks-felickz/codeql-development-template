from aiohttp.web import Application

from middlewares import error_middleware, session_middleware

app = Application(middlewares=[session_middleware, error_middleware])  # $ Alert
app.router.add_route("POST", "/", handler)


async def handler(request):
    return None
