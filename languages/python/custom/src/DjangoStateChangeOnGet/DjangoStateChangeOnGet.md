# Django view changes state on any HTTP method

Django's `CsrfViewMiddleware` only checks unsafe methods such as POST, PUT and DELETE. GET, HEAD, OPTIONS and TRACE requests are never checked. A view that deletes or updates data without checking the HTTP method can therefore be triggered by a link, an image tag or a redirect on another site. The victim's browser attaches the session cookie, so the change runs as the victim. This happens whether or not the middleware is enabled.

This query reports state-changing calls in routed function-based views: model `save`/`delete`, manager or query-set `create`/`update`/`delete` (and the related bulk methods), and `set_password`. It skips views that read `request.method`, call `is_valid()` on a form, or use `require_POST` or `require_http_methods`. Class-based views are skipped because Django dispatches them by method name.

## Recommendation

Only change state for POST (or other unsafe) requests. Decorate the view with `@require_POST`, or check `request.method` before changing anything. Render destructive actions as forms that include `{% csrf_token %}`, not as plain links.

## Example

In the following example, any GET request to the route deletes the task:

```python
@login_required
def task_delete(request, project_id, task_id):
    Task.objects.get(pk=task_id).delete()
    return redirect("/tasks/")
```

Restrict the view to POST:

```python
@login_required
@require_POST
def task_delete(request, project_id, task_id):
    Task.objects.get(pk=task_id).delete()
    return redirect("/tasks/")
```

## References

- Django documentation: [How CSRF protection works](https://docs.djangoproject.com/en/stable/ref/csrf/#how-it-works).
- Django documentation: [Allowed HTTP methods decorators](https://docs.djangoproject.com/en/stable/topics/http/decorators/#allowed-http-methods).
- OWASP: [Cross Site Request Forgery](https://owasp.org/www-community/attacks/csrf).
- Common Weakness Enumeration: [CWE-352](https://cwe.mitre.org/data/definitions/352.html).
