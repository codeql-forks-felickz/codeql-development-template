# aiohttp application created in debug mode

Creating an `aiohttp.web.Application` with `debug=True` enables aiohttp's debug behavior. In debug mode, unhandled exceptions can be reported to the client with diagnostic details such as tracebacks, exposing implementation details (file paths, library internals, database errors) that help an attacker map and exploit the application.

Debug mode is intended for local development only and should never be hard-coded on for an application that is reachable by untrusted users.

## Recommendation

Do not enable debug mode in production. Leave `debug` at its default, or derive it from a configuration value that is disabled in deployed environments.

## Example

The following application is always created in debug mode:

```python
from aiohttp.web import Application

app = Application(debug=True)  # BAD
```

Instead, keep debug mode off unless explicitly configured for development:

```python
import os
from aiohttp import web

app = web.Application(debug=os.environ.get("APP_DEBUG") == "1")  # GOOD
```

## References

- aiohttp: [Application](https://docs.aiohttp.org/en/stable/web_reference.html#application).
- Python: [asyncio debug mode](https://docs.python.org/3/library/asyncio-dev.html#debug-mode).
- Common Weakness Enumeration: [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
- Common Weakness Enumeration: [CWE-215](https://cwe.mitre.org/data/definitions/215.html).
- Common Weakness Enumeration: [CWE-489](https://cwe.mitre.org/data/definitions/489.html).
