---
category: newQuery
---
* Added `py/http-response-splitting-extended`, a variant of `py/http-response-splitting` that also tracks flow through `dict.get` on dictionaries built from (key, value) pairs (for example `dict(<generator of pairs>)`), and through variables bound by iterable unpacking (for example `path, query = ...`) that are read from a nested scope such as a generator expression or inner function. This finds header injection in hand-written `http.server.BaseHTTPRequestHandler` servers that parse the query string into a dictionary.
* Added `py/jinja2/autoescape-false-extended`, a variant of `py/jinja2/autoescape-false` that also reports `aiohttp_jinja2.setup(..., autoescape=False)`, which globally disables autoescaping of the `jinja2.Environment` created on the application's behalf.
