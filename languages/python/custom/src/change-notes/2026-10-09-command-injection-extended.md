---
category: newQuery
---

- Added the `py/custom/command-line-injection-extended` query, a variant of `py/command-line-injection` that additionally tracks taint into lambdas, nested functions and comprehensions that capture a variable defined by tuple unpacking (for example `path, query = self.path.split("?", 1)` in an `http.server` request handler), and through `urllib.parse.parse_qsl`.
