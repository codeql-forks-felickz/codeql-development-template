from aiohttp.web import Application

from middlewares import csrf_middleware, session_middleware

app = Application(middlewares=[session_middleware, csrf_middleware])
app.router.add_route("POST", "/", handler)


async def handler(request):
    return None
