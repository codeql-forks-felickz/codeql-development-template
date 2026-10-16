# CSRF protection disabled on state-changing Django view

Django's `CsrfViewMiddleware` rejects cross-site POST requests that lack a valid CSRF token. The `@csrf_exempt` decorator turns this check off for a single view. If that view changes server-side state, such as editing a profile or changing a password, an attacker's page can submit a form to it. The victim's browser attaches the session cookie, so the change runs as the victim.

The standard `py/csrf-protection-disabled` query only checks the global `MIDDLEWARE` setting, so it does not report exempt views when the middleware is enabled. This query reports `@csrf_exempt` on a view that saves or deletes a model instance, calls `create`, `update`, `delete`, `bulk_create`, `bulk_update`, `get_or_create` or `update_or_create` on a manager or query set, or calls `set_password`. Views that mention an `Authorization` header, an API key or a signature are skipped, because they probably use a non-cookie credential that a cross-site request cannot send.

## Recommendation

Remove `@csrf_exempt` and send the CSRF token with the request (for example with `{% csrf_token %}` in the form). Only exempt views that authenticate with something other than cookies, such as a signed webhook or a bearer token.

## Example

In the following example, CSRF protection is disabled for a password change:

```python
@csrf_exempt
def change_password(request):
    if request.method == "POST":
        request.user.set_password(request.POST["new_password"])
        request.user.save()
    return render(request, "change_password.html")
```

Remove the decorator so `CsrfViewMiddleware` checks the request:

```python
def change_password(request):
    if request.method == "POST":
        request.user.set_password(request.POST["new_password"])
        request.user.save()
    return render(request, "change_password.html")
```

## References

- Django documentation: [Cross Site Request Forgery protection](https://docs.djangoproject.com/en/stable/ref/csrf/).
- OWASP: [Cross Site Request Forgery](https://owasp.org/www-community/attacks/csrf).
- Common Weakness Enumeration: [CWE-352](https://cwe.mitre.org/data/definitions/352.html).
