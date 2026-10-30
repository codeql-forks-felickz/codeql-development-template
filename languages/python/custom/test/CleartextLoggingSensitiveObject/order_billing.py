import json
import logging

logger = logging.getLogger(__name__)


def charge(billing):
    return {"status": 120, "billing": billing}


# Reduced from a billing Lambda: the whole event is logged, but the event
# carries payment card data under `event["billing"]` (card number, CVV, expiry).
def lambda_handler(event, context):  # $ Source
    print(json.dumps(event))  # $ Alert
    order_id = event["orderId"]
    return charge(event["billing"])


def logger_handler(event, context):  # $ Source
    logger.info("received event: %s", event)  # $ Alert
    card = event.get("card_number")
    return charge(card)


def cvv_handler(event, context):  # $ Source
    print(event["payment"])  # $ Alert
    return charge(event["payment"])


# SAFE: only a correlation ID is logged; the payment data is never logged.
def safe_correlation_id_handler(event, context):
    print("processing order " + event["orderId"])
    logger.info("order %s", event.get("orderId"))
    return charge(event["billing"])


def sensitive_fallback_handler(event, context):  # $ Source
    print(event.get("orderId", event))  # $ Alert
    return charge(event["billing"])


# SAFE: a fallback unrelated to the event cannot expose its sensitive fields.
def safe_unrelated_fallback_handler(event, context):
    logger.info("order %s", event.get("orderId", context.aws_request_id))
    return charge(event["billing"])


# SAFE: a literal fallback cannot expose sensitive fields from the event.
def safe_literal_fallback_handler(event, context):
    logger.info("order %s", event.get("orderId", "unknown"))
    return charge(event["billing"])


# SAFE: the event does not carry payment or other sensitive data.
def safe_non_sensitive_handler(event, context):
    print(json.dumps(event))
    return {"orderId": event["orderId"], "user": event["user"]}


# SAFE: not a Lambda handler signature (no `context` parameter).
def not_a_handler(event):
    print(json.dumps(event))
    return charge(event["billing"])


def log_order_id(payload):
    print(payload["orderId"])


def helper_correlation_id_handler(event, context):
    log_order_id(event)
    return charge(event["billing"])


def log_cvv(payload):
    print(payload["cvv"])  # $ Alert


def helper_sensitive_key_handler(event, context):  # $ Source
    log_cvv(event)
    return charge(event["billing"])
