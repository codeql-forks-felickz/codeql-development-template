---
category: newQuery
---
* Added a new query, `py/path-injection-captured-variable`, which extends `py/path-injection` to track taint through local variables that are defined by tuple unpacking or `for` loops and then captured by a comprehension, generator expression, lambda or nested function (for example `path, query = self.path.split("?", 1)` followed by `dict((k, query) for k in keys)`). Only results that `py/path-injection` does not already report are reported.
