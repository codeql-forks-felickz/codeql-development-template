from django.urls import path

import views

urlpatterns = [
    path("change_password/", views.change_password),
    path("legacy_webhook/", views.legacy_webhook),
    path("profile_signature/", views.profile_signature),
    path("unused_nested_helper/", views.unused_nested_helper),
    path("create_from_comprehension/", views.create_from_comprehension),
    path("create_on_commit/", views.create_on_commit),
    path("profile/<int:user_id>/", views.profile_by_id),
    path("complete_all/", views.complete_all),
    path("task_create/", views.task_create),
    path("tasks/", views.task_list),
    path("task_delete/<int:task_id>/", views.task_delete),
    path("task_rename/<int:task_id>/", views.task_rename),
    path("webhook/", views.webhook),
    path("create_in_thread/", views.create_in_thread),
    path("create_with_unused_header_check/", views.create_with_unused_header_check),
]
