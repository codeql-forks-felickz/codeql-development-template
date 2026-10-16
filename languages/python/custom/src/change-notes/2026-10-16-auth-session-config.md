---
category: newQuery
---

- Added `py/custom/flask-debug-attribute`, which finds Flask apps where `app.debug` gets a truthy default before `app.run()` is called without a `debug` argument. One example is `app.debug = os.environ.get("FLASK_DEBUG", True)`. A non-empty string default such as `"False"` also counts as truthy. The standard `py/flask-debug` query only checks the `debug` argument of `app.run(...)`.
- Added `py/custom/csrf-protection-disabled-tuple`, which finds Django `MIDDLEWARE` settings written as a tuple that enable `AuthenticationMiddleware` without `CsrfViewMiddleware`. The standard `py/csrf-protection-disabled` query only checks the list form.
- Added `py/custom/django-csrf-exempt-state-change`, which finds Django views decorated with `@csrf_exempt` that change server-side state (model `save`/`delete`, manager or query-set `create`/`update`/`delete`, or `set_password`). The standard `py/csrf-protection-disabled` query only checks the global `MIDDLEWARE` setting, so these views are missed when `CsrfViewMiddleware` is enabled.
- Added `py/custom/django-state-change-on-get`, which finds routed function-based Django views that change server-side state without checking `request.method`, validating a form, or using `require_POST`/`require_http_methods`. Django's CSRF middleware does not check GET requests, so these views can be triggered by a cross-site link even when the middleware is enabled.
