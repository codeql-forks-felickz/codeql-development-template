from django.urls import path, re_path

import views

urlpatterns = [
    re_path(r"^(?P<project_id>\d+)/task_delete/(?P<task_id>\d+)$", views.task_delete),
    re_path(r"^(?P<project_id>\d+)/task_complete/(?P<task_id>\d+)$", views.task_complete),
    path("clear_completed/", views.clear_completed),
    path("post_only/<int:task_id>/", views.task_delete_post_only),
    path("require_post/<int:task_id>/", views.task_delete_require_post),
    path("require_methods/<int:task_id>/", views.task_delete_require_methods),
    path("get_allowed/<int:task_id>/", views.task_delete_get_allowed),
    path("logs_method/<int:task_id>/", views.task_delete_logs_method),
    path("on_get/<int:task_id>/", views.task_delete_on_get),
    path("early_guard/<int:task_id>/", views.task_delete_early_guard),
    path("in_guard/<int:task_id>/", views.task_delete_in_guard),
    path("create/", views.task_create),
    path("tasks/", views.task_list),
    path("profile_signature/", views.profile_signature),
    path("unused_nested_helper/", views.unused_nested_helper),
    path("create_from_comprehension/", views.create_from_comprehension),
    path("create_on_commit/", views.create_on_commit),
    path("class/<int:task_id>/", views.TaskDeleteView.as_view()),
]
