import urllib3
import urllib.parse

HTTP = urllib3.PoolManager()


def getEmailById(email, _id, mod):
    url = "https://www.1secmail.com/api/v1/?action=readMessage&login={}&domain={}&id={}".format(email.split("@")[0], email.split("@")[1], _id)
    res = HTTP.request("GET", url)  # $ Alert[py/partial-ssrf]
    return res


def getEmailByIdSafe(email, _id):
    res = HTTP.request(
        "GET",
        "https://www.1secmail.com/api/v1/",
        fields={"action": "readMessage", "login": email.split("@")[0], "domain": email.split("@")[1], "id": _id},
    )
    return res


def lambda_handler(event, context):  # $ Source[py/partial-ssrf]
    _id = event["msgId"]
    mod = 'htmlBody' if event["type"] == 'html' else 'textBody'
    getEmailById("user@1secmail.com", _id, mod)
    getEmailByIdSafe("user@1secmail.com", _id)
