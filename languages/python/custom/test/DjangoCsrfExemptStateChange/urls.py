from django.urls import path

import views

urlpatterns = [
    path("change_password/", views.change_password),
    path("profile/<int:user_id>/", views.profile_by_id),
    path("complete_all/", views.complete_all),
    path("task_create/", views.task_create),
    path("tasks/", views.task_list),
    path("task_delete/<int:task_id>/", views.task_delete),
    path("task_rename/<int:task_id>/", views.task_rename),
    path("webhook/", views.webhook),
]
