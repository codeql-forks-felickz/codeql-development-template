# Reduced from an unbounded image fetcher in a FastAPI menu service (CWE-400).
import base64

import requests
from requests import Session


def image_url_to_base64(image_url: str):
    response = requests.get(image_url, stream=True)  # $ Alert[py/file-upload-resource-handling]
    return base64.b64encode(response.content).decode()


def post_without_timeout(url, data):
    return requests.post(url, data=data).text  # $ Alert[py/file-upload-resource-handling]


def generic_request_without_timeout(url):
    return requests.request("GET", url).json()  # $ Alert[py/file-upload-resource-handling]


def session_without_timeout(url):
    session = requests.Session()
    return session.get(url).content  # $ Alert[py/file-upload-resource-handling]


def imported_session_without_timeout(url):
    with Session() as s:
        return s.get(url).content  # $ Alert[py/file-upload-resource-handling]


# Safe: an explicit timeout bounds how long the worker can be held.
def image_url_to_base64_safe(image_url: str):
    response = requests.get(image_url, timeout=5)
    return base64.b64encode(response.content).decode()


def session_with_timeout(url):
    session = requests.Session()
    return session.get(url, timeout=(3.05, 27)).content


# Safe: a timeout may be supplied through keyword expansion, so do not flag it.
def forwarded_kwargs(url, **kwargs):
    return requests.get(url, **kwargs).content


# Safe: constant URL is not attacker-influenced.
def fetch_constant():
    return requests.get("https://example.com/health").status_code
