# SQL query built from user-controlled sources (extended coverage)

This query extends `py/sql-injection` and reports only SQL queries that `py/sql-injection` does not already report, so that it can run next to the default query suite without duplicate alerts.

## Overview

If a database query (such as a SQL query) is built from user-provided data without sufficient sanitization, a user may be able to run malicious database queries.

In addition to the sources, sinks and sanitizers of `py/sql-injection`, this query models:

- **Captured variables defined without a value.** A local variable that is defined by iterable unpacking (`path, query = ...`) or as a `for` loop target, and that is read inside a nested scope such as a generator expression, a comprehension or a lambda. The variable-capture modeling in `codeql/python-all` does not track flow from these definitions into the nested scope (see `lib/CapturedUnpackingFlow.qll`).
- **`d.get("key")` on dictionaries with unknown keys.** Taint stored in a dictionary at an unknown key (for example by `dict(iterable)`) is kept by `d["key"]` but lost by `d.get("key")` (see `lib/DictionaryGetFlow.qll`).
- **Django views whose module cannot be resolved.** Function-based views routed as `module.view` (for example `url(r"^...$", views.upload)` after `from taskManager import views`) when standard module resolution fails. This happens when the project is in a folder whose name contains a dot, such as `django.nV`: `Folder.getStem()` is then `django`, the folder is treated as a namespace package named `django`, and `taskManager.views` becomes `django.taskManager.views` (see `lib/DjangoFallbackRouting.qll`).

## Recommendation

Most database connector libraries offer a way of safely embedding untrusted data into a query by means of query parameters or prepared statements.

## Example

In the following `http.server` handler, `query` is defined by iterable unpacking and then read inside a generator expression. The SQL statement is built by string concatenation and is vulnerable to SQL injection:

```python
class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(
            (m.group("p"), urllib.parse.unquote(m.group("v")))
            for m in re.finditer(r"(?P<p>\w+)=(?P<v>[^&]+)", query)
        )
        cursor.execute("SELECT * FROM users WHERE id=" + params["id"])  # BAD
        cursor.execute("SELECT * FROM users WHERE id=?", (params["id"],))  # GOOD
```

## References

- Wikipedia: [SQL injection](https://en.wikipedia.org/wiki/SQL_injection).
- OWASP: [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
