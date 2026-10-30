---
category: newQuery
---

- Added `py/custom/unsafe-deserialization`, which extends `py/unsafe-deserialization` with taint propagation through `urllib.parse.unquote_to_bytes`. This detects request query parameters from `http.server.BaseHTTPRequestHandler` handlers that are percent-decoded and passed to `pickle.loads`. It also propagates taint through the Python 2 `StringIO.StringIO` and `cStringIO.StringIO` constructors, which detects request data (for example, cookie values) unpickled with `pickle.Unpickler(StringIO(...)).load()`.
- Added `py/custom/django-pickle-session-serializer`, which reports Django settings modules that set `SESSION_SERIALIZER` to `PickleSerializer` while `SESSION_ENGINE` is the signed-cookie session backend.
