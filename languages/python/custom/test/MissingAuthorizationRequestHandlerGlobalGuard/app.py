from flask import Flask, abort, redirect
from flask_login import current_user

from models import Item

app = Flask(__name__)


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
