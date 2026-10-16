from django.urls import path, re_path

import views

urlpatterns = [
    re_path(r"^(?P<project_id>\d+)/task_delete/(?P<task_id>\d+)$", views.task_delete),
    re_path(r"^(?P<project_id>\d+)/task_complete/(?P<task_id>\d+)$", views.task_complete),
    path("clear_completed/", views.clear_completed),
    path("post_only/<int:task_id>/", views.task_delete_post_only),
    path("require_post/<int:task_id>/", views.task_delete_require_post),
    path("require_methods/<int:task_id>/", views.task_delete_require_methods),
    path("create/", views.task_create),
    path("tasks/", views.task_list),
    path("class/<int:task_id>/", views.TaskDeleteView.as_view()),
]
