---
category: minorAnalysis
---
* Added a custom version of the `py/url-redirection` query that also treats values written to a `Location` response header (for example `BaseHTTPRequestHandler.send_header("Location", url)` in `http.server`) as redirect sinks, and that tracks taint from variables defined by iterable unpacking (for example `path, query = self.path.split("?", 1)`) into nested scopes such as generator expressions, comprehensions and lambdas.
