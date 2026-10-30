# Deserialization of user-controlled data (extended)

Deserializing untrusted data using any deserialization framework that allows the construction of arbitrary serializable objects is easily exploitable and in many cases allows an attacker to execute arbitrary code.

This query extends the standard `py/unsafe-deserialization` query with additional taint propagation through `urllib.parse.unquote_to_bytes`. That function is commonly used by `http.server.BaseHTTPRequestHandler` style handlers to percent-decode raw query string values from `self.path` before passing them to `pickle.loads`.

It also propagates taint through the Python 2 `StringIO.StringIO` and `cStringIO.StringIO` constructors (the Python 3 `io.StringIO` is already modeled upstream). Legacy Flask apps often wrap a decoded cookie value in one of these objects and pass it to `pickle.Unpickler(...).load()`. Signing the cookie does not make this safe if the signing secret is weak or guessable.

## Recommendation

Avoid deserialization of untrusted data if at all possible. If the architecture permits it, use a data-only serialization format such as JSON (`json.loads`) instead of `pickle`, `marshal`, or unsafe YAML loaders.

## Example

The following handler decodes the `object` query parameter with `urllib.parse.unquote_to_bytes` and passes it directly to `pickle.loads`, which allows an unauthenticated attacker to execute arbitrary code:

```python
import http.server, pickle, re, urllib.parse


class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        data = pickle.loads(urllib.parse.unquote_to_bytes(re.search(r"object=([^&]+)", query).group(1)))
```

Using a data-only format avoids the issue:

```python
import json

data = json.loads(urllib.parse.unquote_to_bytes(re.search(r"object=([^&]+)", query).group(1)))
```

Similarly, the following Python 2 handler unpickles a cookie value through a `cStringIO.StringIO` wrapper:

```python
import pickle
from base64 import b64decode
from cStringIO import StringIO
from flask import request


def getlocation():
    digest, location = request.cookies.get("location").split("!")
    return pickle.Unpickler(StringIO(b64decode(location))).load()
```

## References

- OWASP: [Deserialization of untrusted data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data).
- Python documentation: [urllib.parse.unquote_to_bytes](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.unquote_to_bytes).
- Python 2 documentation: [cStringIO](https://docs.python.org/2/library/stringio.html#module-cStringIO).
- Common Weakness Enumeration: [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
