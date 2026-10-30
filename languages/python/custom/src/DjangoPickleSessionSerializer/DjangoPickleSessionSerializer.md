# Django signed-cookie sessions deserialized with pickle

When a Django project uses the signed-cookie session backend (`django.contrib.sessions.backends.signed_cookies`), the entire session is stored on the client in a cookie. If the project also sets `SESSION_SERIALIZER` to `django.contrib.sessions.serializers.PickleSerializer`, every request causes the server to unpickle data supplied by the client. The cookie is signed with `SECRET_KEY`, but anyone who knows or obtains that key (for example, a key that is hard-coded, leaked, or left at a default value) can forge a cookie that executes arbitrary code when it is deserialized.

This query reports a settings module that assigns these literal values to both `SESSION_ENGINE` and `SESSION_SERIALIZER`.

## Recommendation

Use the default `django.contrib.sessions.serializers.JSONSerializer`. If session data must contain values that are not JSON serializable, store the session server side (for example, with the database or cache session backend) instead of in signed cookies.

## Example

The following settings unpickle client-controlled cookie data:

```python
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"
```

Using the JSON serializer avoids the issue:

```python
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"
```

## References

- Django documentation: [Session serialization](https://docs.djangoproject.com/en/4.0/topics/http/sessions/#session-serialization).
- Django documentation: [Using cookie-based sessions](https://docs.djangoproject.com/en/stable/topics/http/sessions/#using-cookie-based-sessions).
- Common Weakness Enumeration: [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
