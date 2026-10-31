import logging

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views import View
from django.views.decorators.http import require_http_methods, require_POST

from models import Profile, Task


# NON_COMPLIANT: deletion runs for GET requests (e.g. a plain link).
@login_required
def task_delete(request, project_id, task_id):
    task = Task.objects.get(pk=task_id)
    task.delete()  # $ Alert
    return redirect("/tasks/")


# NON_COMPLIANT: toggling state on GET.
@login_required
def task_complete(request, project_id, task_id):
    task = Task.objects.get(pk=task_id)
    task.completed = not task.completed
    task.save()  # $ Alert
    return redirect("/tasks/")


# NON_COMPLIANT: query-set deletion on GET.
def clear_completed(request):
    Task.objects.filter(completed=True).delete()  # $ Alert
    return redirect("/tasks/")


# COMPLIANT: the state change only happens for POST requests.
def task_delete_post_only(request, task_id):
    if request.method == "POST":
        Task.objects.get(pk=task_id).delete()
    return redirect("/tasks/")


# COMPLIANT: restricted with `require_POST`.
@require_POST
def task_delete_require_post(request, task_id):
    Task.objects.get(pk=task_id).delete()
    return redirect("/tasks/")


# COMPLIANT: restricted with `require_http_methods`.
@require_http_methods(["POST", "DELETE"])
def task_delete_require_methods(request, task_id):
    Task.objects.get(pk=task_id).delete()
    return redirect("/tasks/")


# NON_COMPLIANT: GET is explicitly allowed by the decorator.
@require_http_methods(["GET", "POST"])
def task_delete_get_allowed(request, task_id):
    Task.objects.get(pk=task_id).delete()  # $ Alert


# NON_COMPLIANT: reading the method for logging does not restrict it.
def task_delete_logs_method(request, task_id):
    logging.info("request method: %s", request.method)
    Task.objects.get(pk=task_id).delete()  # $ Alert


# NON_COMPLIANT: the GET branch performs the state change.
def task_delete_on_get(request, task_id):
    if request.method == "GET":
        Task.objects.get(pk=task_id).delete()  # $ Alert


# COMPLIANT: an early return prevents GET from reaching the mutation.
def task_delete_early_guard(request, task_id):
    if request.method != "POST":
        return redirect("/tasks/")
    Task.objects.get(pk=task_id).delete()


# COMPLIANT: membership checks can exclude GET from the mutation.
def task_delete_in_guard(request, task_id):
    if request.method not in ("POST", "DELETE"):
        return redirect("/tasks/")
    Task.objects.get(pk=task_id).delete()


# COMPLIANT: the change only happens for a valid bound form.
def task_create(request):
    form = TaskForm(request.POST or None)
    if form.is_valid():
        Task.objects.create(title=form.cleaned_data["title"])
    return render(request, "task_create.html", {"form": form})


# COMPLIANT: read-only view.
def task_list(request):
    return render(request, "tasks.html", {"tasks": Task.objects.all()})


# NON_COMPLIANT: rendering a template with "signature" is not authentication.
def profile_signature(request):
    profile = Profile.objects.get(pk=request.user.pk)
    profile.bio = request.POST.get("bio")
    profile.save()  # $ Alert
    return render(request, "profile/signature.html")


# COMPLIANT: the nested helper is never called or referenced.
def unused_nested_helper(request):
    def create_task():
        Task.objects.create(title="unused")

    return HttpResponse("ok")


# NON_COMPLIANT: a list comprehension executes its state-changing call.
def create_from_comprehension(request):
    [Task.objects.create(title="from comprehension") for _ in range(1)]  # $ Alert


# NON_COMPLIANT: the nested function is passed as a callback.
def create_on_commit(request):
    def create_task():
        Task.objects.create(title="from callback")  # $ Alert

    transaction.on_commit(create_task)


# COMPLIANT: class-based views dispatch on the HTTP method name.
class TaskDeleteView(View):
    def post(self, request, task_id):
        Task.objects.get(pk=task_id).delete()
        return HttpResponse("ok")


# COMPLIANT: not routed, so not a view.
def helper_not_routed(task_id):
    Task.objects.get(pk=task_id).delete()


class TaskForm:
    pass
