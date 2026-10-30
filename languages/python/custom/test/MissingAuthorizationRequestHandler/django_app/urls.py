from django.contrib.auth.decorators import login_required
from django.urls import path

from . import views

urlpatterns = [
    path("tasks/<task_id>/edit", views.task_edit),
    path("projects/<project_id>/delete", views.project_delete),
    path("projects/create", views.project_create),
    path("tasks/<task_id>/notes/create", views.note_create),
    path("profile/<user_id>", views.profile_by_id),
    path("prepare-user/<user_id>", views.prepare_user),
    path("tasks/<task_id>/complete", views.TaskCompleteView.as_view()),
    path("register-class", views.RegisterView.as_view()),
    path("plain", views.PlainView.as_view()),
    path("safe/tasks/<task_id>/edit", views.task_edit_login_required),
    path("safe/projects/<project_id>/delete", views.project_delete_with_permission),
    path("safe/projects/<project_id>/delete2", views.project_delete_checks_authenticated),
    path("safe/tasks/<task_id>/notes/create", views.note_create_checks_permission),
    path("safe/tasks/<task_id>/complete", views.TaskCompleteLoginView.as_view()),
    path("safe/tasks/<task_id>/reopen", views.TaskReopenView.as_view()),
    path("safe/tasks/<task_id>/archive", views.TaskArchiveView.as_view()),
    path("safe/projects/<project_id>/delete3", login_required(views.wrapped_in_urls)),
    path("projects/<project_id>", views.project_details),
    path("login", views.login),
    path("register", views.register),
    path("forgot", views.forgot_password),
]
