from flask import Flask, abort, redirect, request
from flask_login import current_user, login_required

from .models import Item

app = Flask(__name__)


@app.route("/items/<int:item_id>/delete", methods=["POST"])
def delete_item(item_id):  # $ Alert[py/missing-authorization-request-handler]
    item = Item.query.get(item_id)
    item.delete()
    return redirect("/items")


@app.route("/safe/items/<int:item_id>/delete", methods=["POST"])
@login_required
def delete_item_login_required(item_id):
    item = Item.query.filter_by(id=item_id, owner_id=current_user.id).first_or_404()
    item.delete()
    return redirect("/items")


@app.route("/safe/items/<int:item_id>/rename", methods=["POST"])
def rename_item_checks_owner(item_id):
    item = Item.query.get(item_id)
    if item.owner_id != current_user.id:
        abort(403)
    item.name = request.form["name"]
    item.save()
    return redirect("/items")
