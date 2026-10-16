# CSRF protection disabled in Django tuple middleware setting

Cross-site request forgery (CSRF) lets an attacker make a logged-in user's browser send a state-changing request that the user did not intend. Django protects against this with `django.middleware.csrf.CsrfViewMiddleware`.

The standard `py/csrf-protection-disabled` query only checks `MIDDLEWARE` settings written as a list. This query checks the same thing for settings written as a tuple. It alerts when the tuple contains `django.contrib.auth.middleware.AuthenticationMiddleware`, which means session cookie authentication is in use, but has neither `CsrfViewMiddleware` nor `session_csrf.CsrfMiddleware`. Like the standard query, it skips settings files whose path contains `test`, ignores projects that use `@csrf_protect` on views, and only alerts when every non-test settings file is vulnerable.

## Recommendation

Keep `django.middleware.csrf.CsrfViewMiddleware` in `MIDDLEWARE`. Mark individual views with `@csrf_exempt` only when they use another defense, such as a non-cookie authentication scheme.

## Example

In the following example, CSRF protection has been commented out:

```python
MIDDLEWARE = (
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # 'django.middleware.csrf.CsrfViewMiddleware',
    "django.contrib.auth.middleware.AuthenticationMiddleware",
)
```

Restore the middleware:

```python
MIDDLEWARE = (
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
)
```

## References

- Django documentation: [Cross Site Request Forgery protection](https://docs.djangoproject.com/en/stable/ref/csrf/).
- OWASP: [Cross Site Request Forgery](https://owasp.org/www-community/attacks/csrf).
- Common Weakness Enumeration: [CWE-352](https://cwe.mitre.org/data/definitions/352.html).
