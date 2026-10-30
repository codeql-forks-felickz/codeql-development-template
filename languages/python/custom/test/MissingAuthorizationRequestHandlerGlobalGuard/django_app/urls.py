from django.urls import path

from . import views


urlpatterns = [path("project", views.update_project)]
