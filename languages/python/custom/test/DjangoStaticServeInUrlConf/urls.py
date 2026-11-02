from django.conf import settings
from django.conf import settings as django_settings
from django.conf.urls import url
from django.conf.urls.static import static
from django.contrib.auth.decorators import login_required
from django.urls import path, re_path
from django.views import static as static_views
from django.views.static import serve
from project_settings import DEBUG

urlpatterns = [
    re_path(r"^media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT}),  # $ Alert
    path("files/<path:path>", static_views.serve, {"document_root": "/srv/files"}),  # $ Alert
    url(r"^legacy/(?P<path>.*)$", view=serve, kwargs={"document_root": settings.MEDIA_ROOT}),  # $ Alert
]

media_view = serve
urlpatterns += [re_path(r"^uploads/(?P<path>.*)$", media_view, {"document_root": settings.MEDIA_ROOT})]  # $ Alert


# Safe: the `static()` helper only adds routes when DEBUG is enabled.
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Safe: development only route guarded by DEBUG.
if settings.DEBUG:
    urlpatterns += [re_path(r"^dev-media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT})]

if settings.DEBUG and settings.SERVE_MEDIA:
    urlpatterns += [re_path(r"^combined-dev-media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT})]

if not settings.DEBUG:
    urlpatterns += [re_path(r"^unsafe-not-debug-media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT})]  # $ Alert
else:
    urlpatterns += [re_path(r"^else-dev-media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT})]

if django_settings.DEBUG:
    urlpatterns += [re_path(r"^aliased-dev-media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT})]

if settings.DEBUG or settings.SERVE_MEDIA:
    urlpatterns += [re_path(r"^unsafe-or-media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT})]  # $ Alert

class feature_flags:
    DEBUG = True


if feature_flags.DEBUG:
    urlpatterns += [re_path(r"^feature-flag-media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT})]  # $ Alert

if DEBUG:
    urlpatterns += [re_path(r"^project-debug-media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT})]  # $ Alert


# Safe: a regular (non static serve) view.
def download(request, path):
    pass


urlpatterns += [path("download/<path:path>", login_required(download))]
