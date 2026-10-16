import base64
from typing import Optional

import requests
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

ALLOWED_IMAGE_URLS = {"https://cdn.example.com/default.png"}


class ItemCreate(BaseModel):
    name: str
    image_url: Optional[str] = None


def _image_url_to_base64(image_url: str):
    response = requests.get(image_url, stream=True)  # $ Alert[py/full-ssrf]
    return base64.b64encode(response.content).decode()


def create_item(item: ItemCreate):
    item_dict = item.dict()
    image_url = item_dict.pop("image_url", None)
    if image_url:
        return _image_url_to_base64(image_url)


@app.put("/items")
def create_item_handler(item: ItemCreate):  # $ Source[py/full-ssrf]
    return create_item(item)


@app.put("/items/v2")
def create_item_v2_handler(item: ItemCreate):  # $ Source[py/full-ssrf]
    data = item.model_dump()
    return requests.get(data["image_url"])  # $ Alert[py/full-ssrf]


@app.put("/items/safe")
def create_item_safe_handler(item: ItemCreate):
    item_dict = item.dict()
    name = item_dict.pop("name", None)
    # Safe: the URL is a constant, only the non-URL field is user-controlled.
    return requests.get("https://cdn.example.com/default.png", params={"q": name})
