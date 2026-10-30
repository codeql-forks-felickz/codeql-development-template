from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils.decorators import method_decorator
from django.views import View

from .models import Note, Project, Task


# ---- Vulnerable: no authentication or authorization before writes ----

def task_edit(request, project_id, task_id):  # $ Alert[py/missing-authorization-request-handler]
    proj = Project.objects.get(pk=project_id)
    task = Task.objects.get(pk=task_id)
    if request.method == "POST":
        if task.project == proj:
            task.title = request.POST.get("task_title")
            task.save()
        return redirect("/tasks/" + task_id)
    return render(request, "task_edit.html", {"task": task})


def project_delete(request, project_id):  # $ Alert[py/missing-authorization-request-handler]
    project = Project.objects.get(pk=project_id)
    project.delete()
    return redirect("/dashboard")


def project_create(request):  # $ Alert[py/missing-authorization-request-handler]
    if request.method == "POST":
        project = Project(title=request.POST.get("title"))
        project.save()
        return redirect("/")
    return render(request, "project_create.html", {})


def note_create(request, task_id):  # $ Alert[py/missing-authorization-request-handler]
    task = Task.objects.get(pk=task_id)
    Note.objects.create(task=task, text=request.POST.get("text"))
    return redirect("/tasks/" + task_id)


def profile_by_id(request, user_id):  # $ Alert[py/missing-authorization-request-handler]
    user = User.objects.get(pk=user_id)
    if request.method == "POST":
        user.email = request.POST.get("email")
        user.set_password(request.POST.get("password"))
        user.save()
    return render(request, "profile.html", {"user": user})


class TaskCompleteView(View):
    def post(self, request, task_id):  # $ Alert[py/missing-authorization-request-handler]
        task = Task.objects.get(pk=task_id)
        task.completed = True
        task.save()
        return redirect("/tasks/" + task_id)


# ---- Safe: authentication / authorization is enforced ----

@login_required
def task_edit_login_required(request, task_id):
    task = Task.objects.get(pk=task_id, project__users_assigned=request.user)
    task.title = request.POST.get("task_title")
    task.save()
    return redirect("/tasks/" + task_id)


@permission_required("tasks.delete_project")
def project_delete_with_permission(request, project_id):
    Project.objects.get(pk=project_id).delete()
    return redirect("/dashboard")


def project_delete_checks_authenticated(request, project_id):
    if not request.user.is_authenticated:
        return redirect("/login")
    project = Project.objects.get(pk=project_id, users_assigned=request.user)
    project.delete()
    return redirect("/dashboard")


def note_create_checks_permission(request, task_id):
    if not request.user.has_perm("tasks.add_note"):
        return HttpResponseForbidden()
    Note.objects.create(task_id=task_id, text=request.POST.get("text"))
    return redirect("/tasks/" + task_id)


class TaskCompleteLoginView(LoginRequiredMixin, View):
    def post(self, request, task_id):
        task = Task.objects.get(pk=task_id)
        task.completed = True
        task.save()
        return redirect("/tasks/" + task_id)


@method_decorator(login_required, name="dispatch")
class TaskReopenView(View):
    def post(self, request, task_id):
        task = Task.objects.get(pk=task_id)
        task.completed = False
        task.save()
        return redirect("/tasks/" + task_id)


class ProtectedView(LoginRequiredMixin, View):
    pass


class TaskArchiveView(ProtectedView):
    def post(self, request, task_id):
        Task.objects.get(pk=task_id).delete()
        return redirect("/tasks/")


def wrapped_in_urls(request, project_id):
    # Protected by `login_required(...)` in urls.py.
    Project.objects.get(pk=project_id).delete()
    return redirect("/dashboard")


# ---- Safe: no state-changing operation ----

def project_details(request, project_id):
    proj = Project.objects.get(pk=project_id)
    context = {"proj": proj}
    context.update({"tasks": Task.objects.filter(project=proj)})
    return render(request, "project_details.html", context)


# ---- Safe: intentionally public account flows ----

def login(request):
    creds = {"username": request.POST["username"], "password": request.POST["password"]}
    user = authenticate(**creds)
    if user is not None:
        auth_login(request, user)
        user.save()
    return redirect("/")


def register(request):
    user = User(username=request.POST["username"])
    user.set_password(request.POST["password"])
    user.save()
    return redirect("/login")


def forgot_password(request):
    user = User.objects.get(email=request.POST["email"])
    user.save()
    return HttpResponse("sent")


# ---- Not a request handler ----

def save_helper(project):
    project.save()
