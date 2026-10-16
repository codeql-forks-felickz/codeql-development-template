import json
import os

import boto3
import jsonpickle

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["ORDERS_TABLE"])
client = boto3.client("dynamodb")


def get_item_unsafe(order_id):
    response = table.get_item(Key={"orderId": order_id})  # $ Source[py/unsafe-deserialization]
    return jsonpickle.decode(json.dumps(response["Item"]))  # $ Alert[py/unsafe-deserialization]


def query_unsafe(user_id):
    response = table.query(KeyConditionExpression="userId = :u", ExpressionAttributeValues={":u": user_id})  # $ Source[py/unsafe-deserialization]
    return [jsonpickle.decode(item["payload"]) for item in response["Items"]]  # $ Alert[py/unsafe-deserialization]


def scan_unsafe():
    response = table.scan()  # $ Source[py/unsafe-deserialization]
    for item in response["Items"]:
        jsonpickle.decode(item["payload"])  # $ Alert[py/unsafe-deserialization]


def batch_get_item_unsafe(order_id):
    response = dynamodb.batch_get_item(RequestItems={"orders": {"Keys": [{"orderId": order_id}]}})  # $ Source[py/unsafe-deserialization]
    return jsonpickle.decode(response["Responses"]["orders"][0]["payload"])  # $ Alert[py/unsafe-deserialization]


def client_get_item_unsafe(order_id):
    response = client.get_item(TableName="orders", Key={"orderId": {"S": order_id}})  # $ Source[py/unsafe-deserialization]
    return jsonpickle.decode(response["Item"]["payload"]["S"])  # $ Alert[py/unsafe-deserialization]


def client_execute_statement_unsafe(order_id):
    response = client.execute_statement(Statement="SELECT * FROM orders WHERE orderId = ?", Parameters=[{"S": order_id}])  # $ Source[py/unsafe-deserialization]
    return jsonpickle.decode(response["Items"][0]["payload"]["S"])  # $ Alert[py/unsafe-deserialization]


def session_table_unsafe(order_id):
    session = boto3.session.Session()
    orders = session.resource("dynamodb").Table("orders")
    response = orders.get_item(Key={"orderId": order_id})  # $ Source[py/unsafe-deserialization]
    return jsonpickle.decode(response["Item"]["payload"])  # $ Alert[py/unsafe-deserialization]


def session_client_unsafe(order_id):
    session_client = boto3.Session().client("dynamodb")
    response = session_client.scan(TableName="orders")  # $ Source[py/unsafe-deserialization]
    return jsonpickle.decode(response["Items"][0]["payload"]["S"])  # $ Alert[py/unsafe-deserialization]


def get_item_safe(order_id):
    # Safe: plain JSON parsing does not instantiate arbitrary objects.
    response = table.get_item(Key={"orderId": order_id})
    return json.loads(json.dumps(response["Item"]))


def decode_constant_safe():
    # Safe: the jsonpickle payload is not read from DynamoDB.
    return jsonpickle.decode('{"orderId": "1"}')
