---
category: newQuery
---

- Added the `py/sql-injection-extended` query, which reports SQL injection that `py/sql-injection` misses: flow from variables defined by iterable unpacking or as `for` loop targets into nested scopes (generator expressions, comprehensions, lambdas), `d.get("key")` on dictionaries built with unknown keys (for example `dict(iterable)`), and Django function-based views that cannot be resolved because the project is in a folder whose name contains a dot (for example `django.nV`). It only reports results that `py/sql-injection` does not already report.
