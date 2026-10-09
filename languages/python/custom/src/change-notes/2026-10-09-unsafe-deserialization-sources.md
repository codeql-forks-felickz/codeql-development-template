---
category: newQuery
---

- Added `py/custom/unsafe-deserialization`, which extends `py/unsafe-deserialization` with taint propagation through `urllib.parse.unquote_to_bytes`. This detects request query parameters from `http.server.BaseHTTPRequestHandler` handlers that are percent-decoded and passed to `pickle.loads`.
- Added `py/custom/django-pickle-session-serializer`, which reports Django settings modules that set `SESSION_SERIALIZER` to `PickleSerializer` while `SESSION_ENGINE` is the signed-cookie session backend.
