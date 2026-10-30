# Clear-text logging of an object containing sensitive data

Code often logs a whole object for debugging, for example the incoming AWS Lambda `event` or a parsed request body (`request.get_json()`). If that object contains payment card data (a card number, CVV or expiry date, or an `event["billing"]` object holding them) or other sensitive data, every request writes it to the logs (for example CloudWatch Logs or a module logger set to `DEBUG`). Anyone with log access, or any later log disclosure, can then recover it.

The standard `py/clear-text-logging-sensitive-data` query does not report this, because the logged variable (`event`, `data`, `body`) is not named like sensitive data. This query treats an object as sensitive when the code reads a payment key (such as `billing`, `payment`, `cardNumber`, `card_number`, `cvv`) or another sensitive key (such as `password`) from it via `obj["key"]` or `obj.get("key")`. It considers two kinds of object:

- the `event` parameter of an AWS Lambda handler `f(event, context)`;
- the result of a call, such as `request.get_json()` or `json.loads(...)`.

It reports flows of such an object to logging or printing sinks. Reading a non-sensitive key such as `event["orderId"]` stops the flow.

## Recommendation

Do not log the whole object. Log only a correlation ID, or explicitly redact payment and other sensitive fields before logging.

## Example

The following AWS Lambda handler logs the whole event, which includes the billing card data:

```python
def lambda_handler(event, context):
    print(json.dumps(event))  # BAD
    return charge(event["billing"])
```

The following Flask route logs the whole request body, which includes the card number and CVV:

```python
@app.route("/payment-info/<int:id>", methods=["POST"])
def add_card(id):
    data = request.get_json()
    logger.debug("Received request data: %s", data)  # BAD
    return save_card(id, data["cardNumber"], data["cvv"])
```

Log only a correlation ID or a non-sensitive field instead:

```python
def lambda_handler(event, context):
    print("processing order " + event["orderId"])  # GOOD
    return charge(event["billing"])
```

## References

- OWASP: [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- AWS: [Lambda function logging in Python](https://docs.aws.amazon.com/lambda/latest/dg/python-logging.html).
- Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
- Common Weakness Enumeration: [CWE-359](https://cwe.mitre.org/data/definitions/359.html).
- Common Weakness Enumeration: [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
