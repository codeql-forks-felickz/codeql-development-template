# Failure to use secure cookies

Cookies without the `Secure` flag set may be transmitted using HTTP instead of HTTPS. This leaves them vulnerable to being read by a third party attacker. If a sensitive cookie such as a session key is intercepted this way, it would allow the attacker to perform actions on a user's behalf.

In addition to explicit cookie writes (such as `set_cookie`), this query reports framework settings that explicitly disable the `Secure` flag of cookies managed by the framework itself:

- Flask: `SESSION_COOKIE_SECURE` set to `False` through `app.config[...]`, `app.config.update(...)` or `app.config.from_mapping(...)`.
- Django settings modules and Flask configuration objects: module-level or class-level `SESSION_COOKIE_SECURE = False` or `CSRF_COOKIE_SECURE = False`.
- `aiohttp-session` storages: `secure=False` passed to a storage constructor such as `EncryptedCookieStorage`.

Only settings explicitly set to `False` are reported. A missing setting (for example, Flask's default `SESSION_COOKIE_SECURE = False`) is not reported.

## Recommendation

Always set `secure` to `True`, or add `; Secure;` to the cookie's raw header value, to ensure SSL is used to transmit the cookie with encryption. Set framework settings such as `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` to `True`.

## Example

In the following examples, the cases marked GOOD show secure cookie attributes being set; whereas in the cases marked BAD they are not set.

```python
from flask import Flask, make_response

app = Flask(__name__)
app.config["SESSION_COOKIE_SECURE"] = False  # BAD
app.config["SESSION_COOKIE_SECURE"] = True  # GOOD


@app.route("/good")
def good():
    resp = make_response()
    resp.set_cookie("sessionid", value="value", secure=True, httponly=True, samesite="Strict")  # GOOD
    return resp


@app.route("/bad")
def bad():
    resp = make_response()
    resp.set_cookie("access_token", value="value", secure=False)  # BAD
    return resp
```

```python
# Django settings.py
SESSION_COOKIE_SECURE = False  # BAD
CSRF_COOKIE_SECURE = True  # GOOD
```

## References

- Detectify: [Cookie lack Secure flag](https://support.detectify.com/support/solutions/articles/48001048982-cookie-lack-secure-flag).
- PortSwigger: [TLS cookie without secure flag set](https://portswigger.net/kb/issues/00500200_tls-cookie-without-secure-flag-set).
- MDN: [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie).
- Flask: [SESSION_COOKIE_SECURE](https://flask.palletsprojects.com/en/stable/config/#SESSION_COOKIE_SECURE).
- Django: [SESSION_COOKIE_SECURE](https://docs.djangoproject.com/en/stable/ref/settings/#session-cookie-secure).
- Common Weakness Enumeration: [CWE-614](https://cwe.mitre.org/data/definitions/614.html).
