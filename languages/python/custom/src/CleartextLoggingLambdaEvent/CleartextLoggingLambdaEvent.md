# Clear-text logging of sensitive AWS Lambda event

AWS Lambda handlers often log the whole incoming `event` for debugging. If that event contains payment card data (for example an `event["billing"]` object holding the card number, CVV and expiry date) or other sensitive data, every invocation writes it to CloudWatch Logs. Anyone with log access, or any later log disclosure, can then recover it.

The standard `py/clear-text-logging-sensitive-data` query does not report this, because the `event` parameter is not named like sensitive data. This query treats the `event` parameter of a handler `f(event, context)` as sensitive when the handler reads a payment key (such as `billing`, `payment`, `card_number`, `cvv`) or another sensitive key (such as `password`) from it, and reports flows of the event to logging or printing sinks. Reading a non-sensitive key such as `event["orderId"]` stops the flow.

## Recommendation

Do not log the whole event. Log only a correlation ID, or explicitly redact payment and other sensitive fields before logging.

## Example

The following handler logs the whole event, which includes the billing card data:

```python
def lambda_handler(event, context):
    print(json.dumps(event))  # BAD
    return charge(event["billing"])
```

Log only a correlation ID instead:

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
