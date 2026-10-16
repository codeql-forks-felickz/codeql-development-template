---
category: newQuery
---

- Added a new query, `py/custom/code-injection-remote-content`, which complements the standard `py/code-injection` query. It detects code execution (for example `exec`, `eval`, or `compile`) of content fetched from a user-controlled URL via an outgoing HTTP request, such as `exec(urllib.request.urlopen(url).read())`. Flows already reported by `py/code-injection` (for example through `requests`) are not reported again.
