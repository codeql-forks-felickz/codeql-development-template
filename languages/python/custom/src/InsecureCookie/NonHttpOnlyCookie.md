# Sensitive cookie missing `HttpOnly` attribute

Cookies without the `HttpOnly` flag set are accessible to JavaScript running in the same origin. In case of a Cross-Site Scripting (XSS) vulnerability, the cookie can be stolen by a malicious script. If a sensitive cookie does not need to be accessed directly by client-side JavaScript, the `HttpOnly` flag should be set.

In addition to explicit cookie writes (such as `set_cookie`), this query reports framework settings that explicitly disable the `HttpOnly` flag of session cookies managed by the framework itself:

- Flask: `SESSION_COOKIE_HTTPONLY` set to `False` through `app.config[...]`, `app.config.update(...)` or `app.config.from_mapping(...)`.
- Django settings modules and Flask configuration objects: module-level or class-level `SESSION_COOKIE_HTTPONLY = False`.
- `aiohttp-session` storages: `httponly=False` passed to a storage constructor such as `RedisStorage`.

`CSRF_COOKIE_HTTPONLY = False` is not reported, since Django documents that marking the CSRF cookie as `HttpOnly` offers no practical protection.

## Recommendation

Set the `HttpOnly` flag on all sensitive cookies that do not need to be accessed directly by client-side JavaScript, and set framework settings such as `SESSION_COOKIE_HTTPONLY` to `True` (the default in Flask and Django).

## Example

In the following examples, the cases marked GOOD show the `HttpOnly` attribute being set; whereas in the cases marked BAD it is not.

```python
from django.http import HttpResponse


def bad(request):
    response = HttpResponse("ok")
    response.set_cookie("refresh_token", "value", httponly=False)  # BAD
    return response


def good(request):
    response = HttpResponse("ok")
    response.set_cookie("refresh_token", "value", httponly=True)  # GOOD
    return response
```

```python
# Django settings.py
SESSION_COOKIE_HTTPONLY = False  # BAD
```

```python
from aiohttp_session.redis_storage import RedisStorage

storage = RedisStorage(redis, httponly=False)  # BAD
```

## References

- PortSwigger: [Cookie without HttpOnly flag set](https://portswigger.net/kb/issues/00500600_cookie-without-httponly-flag-set).
- MDN: [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie).
- Flask: [SESSION_COOKIE_HTTPONLY](https://flask.palletsprojects.com/en/stable/config/#SESSION_COOKIE_HTTPONLY).
- Django: [SESSION_COOKIE_HTTPONLY](https://docs.djangoproject.com/en/stable/ref/settings/#session-cookie-httponly) and [CSRF_COOKIE_HTTPONLY](https://docs.djangoproject.com/en/stable/ref/settings/#csrf-cookie-httponly).
- Common Weakness Enumeration: [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html).
