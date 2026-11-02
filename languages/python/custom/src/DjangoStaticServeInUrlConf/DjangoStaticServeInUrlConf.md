# Django static file view routed in URL configuration

`django.views.static.serve` is a development helper. The Django documentation states that it is "grossly inefficient and probably insecure" and must not be used in production. When a URLconf routes a pattern such as `^media/(?P<path>.*)$` to this view without restricting it to `DEBUG`, every file under the document root (for example all user uploads in `MEDIA_ROOT`) is publicly readable without authentication or authorization, and its `Content-Type` is derived from the file extension, which can enable stored cross-site scripting.

## Recommendation

Serve static and media files with the web server or a storage service in production. If the view is needed for local development, only add it when `django.conf.settings.DEBUG` is enabled, for example with the `django.conf.urls.static.static()` helper or an `if settings.DEBUG:` block. The query recognizes this Django setting through aliases, but a bare `DEBUG` name, including one imported from a project settings module, is not treated as a guard and will still be reported. Serve private files through a view that enforces access control.

## Example

The following URLconf exposes `MEDIA_ROOT` in every deployment:

```python
from django.conf import settings
from django.urls import re_path
from django.views.static import serve

urlpatterns = [
    re_path(r"^media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT}),
]
```

The following URLconf only serves media files during development:

```python
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # ...
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

## References

- Django documentation: [Serving files in development](https://docs.djangoproject.com/en/stable/howto/static-files/#serving-files-uploaded-by-a-user-during-development).
- Django documentation: [`django.views.static.serve`](https://docs.djangoproject.com/en/stable/ref/views/#serving-files-in-development).
- Common Weakness Enumeration: [CWE-552](https://cwe.mitre.org/data/definitions/552.html).
