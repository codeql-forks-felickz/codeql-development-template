from boto3.dynamodb.conditions import Attr


def lambda_handler(event, context):  # $ Source[py/code-injection]
    dateTo = event['to']
    dateFrom = event['from']

    # Reduced from the AI scan finding: `fe` is assembled only from string
    # literals. The event decides *which* literals are concatenated (control
    # dependency) but its values never become part of the evaluated code, so
    # taint tracking does not report it.
    fe = "Attr('paymentTS').between(dateFrom, dateTo)"
    orderId = "" if 'orderId' not in event else " & Attr('orderId').eq(event['orderId'])"
    fe = fe + orderId
    eval(fe)

    # Event values interpolated into the evaluated string are reported.
    eval("Attr('orderId').eq('" + event['orderId'] + "')")  # $ Alert[py/code-injection]

    # Safe: build the condition programmatically.
    return Attr('paymentTS').between(dateFrom, dateTo) & Attr('orderId').eq(event['orderId'])
