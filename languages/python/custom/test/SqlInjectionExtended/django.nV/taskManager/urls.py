from django.conf.urls import url

from taskManager import views

urlpatterns = [
    url(r"^(?P<project_id>\d+)/upload/$", views.upload, name="upload"),
    url(r"^(?P<project_id>\d+)/safe_upload/$", views.safe_upload, name="safe_upload"),
]
