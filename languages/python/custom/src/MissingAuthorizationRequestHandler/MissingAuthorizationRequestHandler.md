# Missing authorization in state-changing request handler

Web request handlers that create, modify, or delete persistent data must verify that the requester is authenticated and is allowed to perform the operation on the referenced object. A handler that skips this check lets any client, including anonymous users, perform the operation. When the handler also trusts an object identifier taken from the URL, any user can change or delete objects that belong to someone else (insecure direct object reference).

This query reports Django, Flask, aiohttp, and other request handlers recognized by the CodeQL Python library that persist changes (for example `obj.save()`, `obj.delete()`, `Model.objects.create(...)`, `Model.create(conn, ...)`, or `queryset.filter(...).update(...)`) without any evidence of an authentication or authorization check.

The following are treated as authentication or authorization checks:

- a decorator on the handler or its class whose name refers to authentication or authorization, such as `@login_required`, `@permission_required`, `@user_passes_test`, `@authorize()`, or `@method_decorator(login_required, name="dispatch")`;
- a base class (direct or inherited) or class-level attribute that refers to authentication or authorization, such as `LoginRequiredMixin` or `PermissionRequiredMixin`;
- a reference, in the handler or in a function it calls, to a name such as `is_authenticated`, `has_perm`, `is_staff`, `is_superuser`, `owner`, or `get_auth_user`;
- a global guard installed for that application: Django's `LoginRequiredMiddleware` listed in `MIDDLEWARE`, a Flask `before_request` hook on the same app or blueprint, or an aiohttp middleware passed to that application's `Application(middlewares=[...])`.

Handlers for account flows that are intentionally public (login, logout, sign-up, registration, password reset, account activation, and confirmation) are not reported.

## Recommendation

Require authentication for every handler that changes state, for example with Django's `login_required` decorator or `LoginRequiredMixin`, Flask-Login's `login_required`, or an application-specific `authorize()` decorator. In addition, verify that the authenticated user is allowed to act on the referenced object, for example by restricting the lookup to objects owned by, or assigned to, the current user.

## Example

The following Django view loads a task from an identifier in the URL and updates it. It does not require the user to be logged in and does not check that the user is assigned to the project that owns the task:

```python
def task_edit(request, project_id, task_id):
    task = Task.objects.get(pk=task_id)
    task.title = request.POST.get("task_title")
    task.save()
    return redirect("/tasks/" + task_id)
```

The following aiohttp handler writes to the database without calling `authorize()` or checking the current user:

```python
@template("students.jinja2")
async def students(request):
    data = await request.post()
    async with request.app["db"].acquire() as conn:
        await Student.create(conn, data["name"])
    return {}
```

In the following corrected versions, the Django view requires a logged-in user and only loads tasks from projects the user is assigned to, and the aiohttp handler is wrapped with the application's `authorize()` decorator:

```python
@login_required
def task_edit(request, project_id, task_id):
    task = Task.objects.get(pk=task_id, project__users_assigned=request.user)
    task.title = request.POST.get("task_title")
    task.save()
    return redirect("/tasks/" + task_id)


@authorize()
@template("students.jinja2")
async def students(request):
    data = await request.post()
    async with request.app["db"].acquire() as conn:
        await Student.create(conn, data["name"])
    return {}
```

## Limitations

The query uses name-based heuristics. It may miss handlers whose authorization helpers have unrelated names, and it may report handlers that are protected by a mechanism it does not recognize, such as a custom URL-routing wrapper or a reverse proxy. Global guard matching is limited to registrations that are directly visible in the same module. In particular, it does not infer that a Flask app-level hook covers routes registered through a blueprint, or that aiohttp middleware and route setup in separate modules refer to the same application.

## References

- Common Weakness Enumeration: [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html).
- Common Weakness Enumeration: [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html).
- OWASP Top 10: [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/).
- Django documentation: [Limiting access to logged-in users](https://docs.djangoproject.com/en/stable/topics/auth/default/#limiting-access-to-logged-in-users).
