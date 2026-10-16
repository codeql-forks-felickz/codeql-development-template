from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views import View
from django.views.decorators.http import require_http_methods, require_POST

from models import Task


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


# COMPLIANT: the change only happens for a valid bound form.
def task_create(request):
    form = TaskForm(request.POST or None)
    if form.is_valid():
        Task.objects.create(title=form.cleaned_data["title"])
    return render(request, "task_create.html", {"form": form})


# COMPLIANT: read-only view.
def task_list(request):
    return render(request, "tasks.html", {"tasks": Task.objects.all()})


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
