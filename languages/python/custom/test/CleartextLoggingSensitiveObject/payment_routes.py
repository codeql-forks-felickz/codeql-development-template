import json

from flask import Blueprint, request
from logger_config import logger

bp = Blueprint("routes", __name__)


def add_card_into_db(id, holder, number, expiry, cvv):
    return {"id": id}


# Reduced from a payment service: the whole parsed request body is logged,
# but it carries the card number, expiry date and CVV.
@bp.route("/payment-info/<int:id>", methods=["POST"])
def add_card(id):
    data = request.get_json()  # $ Source
    logger.debug("Received request data: %s", data)  # $ Alert
    card_holder_name = data["cardHolderName"]
    card_number = data["cardNumber"]
    expiry_date = data["expiryDate"]
    cvv = data["cvv"]
    logger.info("Credit card number is valid")
    return add_card_into_db(id, card_holder_name, card_number, expiry_date, cvv)


@bp.route("/payment-raw", methods=["POST"])
def add_card_raw():
    body = json.loads(request.data)  # $ Source
    print(body)  # $ Alert
    return add_card_into_db(0, body["name"], body.get("card_number"), None, None)


# SAFE: only a non-sensitive field of the body is logged.
@bp.route("/payment-safe/<int:id>", methods=["POST"])
def add_card_safe(id):
    data = request.get_json()
    logger.debug("Received request for holder %s", data["cardHolderName"])
    return add_card_into_db(id, None, data["cardNumber"], None, data["cvv"])


# SAFE: the body carries no sensitive keys.
@bp.route("/profile", methods=["POST"])
def update_profile():
    data = request.get_json()
    logger.debug("Received request data: %s", data)
    return {"name": data["displayName"], "theme": data.get("theme")}
