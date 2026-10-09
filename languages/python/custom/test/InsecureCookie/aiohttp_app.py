from aiohttp import web
from aiohttp_session import session_middleware, SimpleCookieStorage
from aiohttp_session.redis_storage import RedisStorage
from aiohttp_session.cookie_storage import EncryptedCookieStorage


@web.middleware
async def middleware(request, handler):
    storage = RedisStorage(request.app["redis"], httponly=False)  # BAD: session cookie readable by JavaScript
    return await session_middleware(storage)(request, handler)


def make_storages(redis, key):
    return [
        EncryptedCookieStorage(key, secure=False),  # BAD: session cookie sent over plain HTTP
        RedisStorage(redis, secure=True, httponly=True),  # GOOD
        RedisStorage(redis),  # GOOD: `httponly` defaults to `True`
        SimpleCookieStorage(httponly=True),  # GOOD
    ]
