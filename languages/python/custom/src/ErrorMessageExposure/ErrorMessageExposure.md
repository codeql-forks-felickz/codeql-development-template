# Information exposure through an exception (additional sinks)

Software developers often add stack traces or exception details to error messages as a debugging aid. When that information reaches an end user, it can reveal file system paths, library versions, SQL statements and other implementation details that help an attacker plan a follow-up attack.

This query complements `py/stack-trace-exposure`. It tracks the same exception sources (caught exceptions, `sys.exc_info()` and `traceback` formatting functions) to sinks that `py/stack-trace-exposure` does not model:

- data written to `self.wfile` in a `http.server.BaseHTTPRequestHandler` subclass, which is sent directly to the HTTP client;
- values passed in the context of a server-side template render (`aiohttp_jinja2.render_template`/`render_string`, `flask.render_template`/`stream_template`, `django.shortcuts.render`), where the template may print the exception or dump its attributes (for example `{{ error.__dict__ }}`).

Because error callbacks are often invoked through dynamic dispatch (for example a status-code-to-handler dictionary in a middleware), parameters named `ex`, `exc`, `exception` or `exc_info`, or annotated with an `...Exception`/`...Error` type, are also treated as exception sources.

## Recommendation

Log exception details on the server and send only a generic error message to the user. Do not pass exception objects or formatted stack traces to templates that are rendered for the user.

## Example

In the following `http.server` handler, the stack trace is written to the response:

```python
class ReqHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            content = open(self.path.lstrip("/")).read()
        except Exception:
            content = traceback.format_exc()  # BAD
        self.send_response(200)
        self.end_headers()
        self.wfile.write(content.encode())
```

In the following aiohttp error handler, the exception object is passed to a template that renders it:

```python
async def handle_50x(request, exc):
    return render_template("errors/50x.jinja2", request, {"error": exc})  # BAD
```

Instead, log the details and return a generic message:

```python
async def handle_50x(request, exc):
    log.exception("Unhandled error")
    return render_template("errors/50x.jinja2", request, {"status": exc.status})  # GOOD
```

## References

- OWASP: [Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling).
- Common Weakness Enumeration: [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
- Common Weakness Enumeration: [CWE-497](https://cwe.mitre.org/data/definitions/497.html).
