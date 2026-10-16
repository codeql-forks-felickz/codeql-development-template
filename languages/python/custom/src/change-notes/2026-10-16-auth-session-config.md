---
category: newQuery
---

- Added `py/custom/flask-debug-attribute`, which finds Flask apps where `app.debug` gets a truthy default before `app.run()` is called without a `debug` argument. One example is `app.debug = os.environ.get("FLASK_DEBUG", True)`. A non-empty string default such as `"False"` also counts as truthy. The standard `py/flask-debug` query only checks the `debug` argument of `app.run(...)`.
- Added `py/custom/csrf-protection-disabled-tuple`, which finds Django `MIDDLEWARE` settings written as a tuple that enable `AuthenticationMiddleware` without `CsrfViewMiddleware`. The standard `py/csrf-protection-disabled` query only checks the list form.
