from flask import Blueprint, Flask, abort, redirect
from flask_login import current_user

from models import Item
from aiohttp.web import Application

app = Flask(__name__)
unguarded_app = Flask(__name__)
guarded_blueprint = Blueprint("guarded", __name__)
unrelated_blueprint = Blueprint("unrelated", __name__)


@app.before_request
def require_login():
    # Every request must be authenticated before reaching any route.
    if not current_user.is_authenticated:
        abort(401)


@app.route("/items/<int:item_id>/delete", methods=["POST"])
def delete_item(item_id):
    item = Item.query.get(item_id)
    item.delete()
    return redirect("/items")


@unguarded_app.route("/items/<int:item_id>/delete", methods=["POST"])
def delete_from_other_app(item_id):  # $ Alert[py/missing-authorization-request-handler]
    item = Item.query.get(item_id)
    item.delete()
    return redirect("/items")


@guarded_blueprint.before_request
def require_blueprint_login():
    if not current_user.is_authenticated:
        abort(401)


@guarded_blueprint.route("/items/<int:item_id>/delete", methods=["POST"])
def delete_from_guarded_blueprint(item_id):
    item = Item.query.get(item_id)
    item.delete()
    return redirect("/items")


@unrelated_blueprint.route("/items/<int:item_id>/delete", methods=["POST"])
def delete_from_unrelated_blueprint(item_id):  # $ Alert[py/missing-authorization-request-handler]
    item = Item.query.get(item_id)
    item.delete()
    return redirect("/items")


def aiohttp_auth_middleware(request, handler):
    if not request.user.is_authenticated:
        raise Exception()
    return handler(request)


aiohttp_app = Application(middlewares=[aiohttp_auth_middleware])


async def aiohttp_guarded_handler(request):
    request.db.save()


aiohttp_app.router.add_route("POST", "/guarded", aiohttp_guarded_handler)


def unused_aiohttp_auth_middleware(request, handler):
    if not request.user.is_authenticated:
        raise Exception()
    return handler(request)


unregistered_aiohttp_app = Application()


async def aiohttp_unprotected_handler(request):  # $ Alert[py/missing-authorization-request-handler]
    request.db.save()


unregistered_aiohttp_app.router.add_route("POST", "/unguarded", aiohttp_unprotected_handler)


unused_django_middleware_name = "django.contrib.auth.middleware.LoginRequiredMiddleware"
