from django.conf.urls import url

from taskManager import urls as views

urlpatterns = [
    url(r"^(?P<project_id>\d+)/mixed_fallback/$", views.mixed_upload, name="mixed_fallback"),
]
