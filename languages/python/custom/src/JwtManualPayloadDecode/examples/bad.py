import base64
import json


def lambda_handler(event, context):
    token_sections = event["headers"]["Authorization"].split(".")
    auth_data = base64.b64decode(token_sections[1] + "==")  # BAD: signature never checked
    user = json.loads(auth_data)["username"]
    return user
