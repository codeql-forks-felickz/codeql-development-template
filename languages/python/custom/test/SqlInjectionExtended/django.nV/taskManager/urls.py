from django.conf.urls import url

from taskManager import views


def mixed_upload(request, project_id):
    pass


urlpatterns = [
    url(r"^(?P<project_id>\d+)/upload/$", views.upload, name="upload"),
    url(r"^(?P<project_id>\d+)/safe_upload/$", views.safe_upload, name="safe_upload"),
    url(r"^default/$", views.default_parameter, name="default_parameter"),
    url(r"^(?P<project_id>\d+)/mixed_resolved/$", mixed_upload, name="mixed_resolved"),
]
