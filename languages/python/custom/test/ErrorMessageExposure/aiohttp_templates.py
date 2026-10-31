from aiohttp import web
from aiohttp_jinja2 import render_template
import aiohttp_jinja2


def error_pages(overrides):
    @web.middleware
    async def middleware(request, handler):
        try:
            return await handler(request)
        except web.HTTPException as ex:
            override = overrides.get(ex.status)
            if override is None:
                raise
            return await override(request, ex)

    return middleware


async def handle_50x(request, exc): # $ Source[py/error-message-exposure]
    # The exception object is handed to the template, which may dump its internals.
    return render_template("errors/50x.jinja2", request, {"error": exc}) # $ Alert[py/error-message-exposure]


async def handle_40x(request, exc):
    # Safe: only the status code is passed to the template.
    return render_template("errors/40x.jinja2", request, {"status": exc.status})


async def show_login(request, error):
    # Safe: `error` is an application-defined message, not an exception.
    return render_template("login.jinja2", request, {"error": error})


async def view(request):
    try:
        data = await request.post()
        value = int(data["value"])
    except Exception as e: # $ Source[py/error-message-exposure]
        return aiohttp_jinja2.render_template("error.jinja2", request, context={"error": e}) # $ Alert[py/error-message-exposure]
    return aiohttp_jinja2.render_template("ok.jinja2", request, {"value": value})


async def view_safe(request):
    try:
        data = await request.post()
        value = int(data["value"])
    except Exception:
        # Safe: generic message only.
        return aiohttp_jinja2.render_template("error.jinja2", request, {"error": "Invalid value"})
    return aiohttp_jinja2.render_template("ok.jinja2", request, {"value": value})


error_middleware = error_pages({x: handle_50x for x in range(500, 600)})
app = web.Application(middlewares=[error_middleware])
app.router.add_post("/view", view)
app.router.add_post("/view_safe", view_safe)
