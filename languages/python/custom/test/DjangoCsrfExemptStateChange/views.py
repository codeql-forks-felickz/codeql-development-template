import hmac
from threading import Thread

from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt, csrf_protect

from models import Profile, Task


# NON_COMPLIANT: password change with CSRF protection disabled.
@csrf_exempt  # $ Alert
def change_password(request):
    if request.method == "POST":
        user = request.user
        user.set_password(request.POST.get("new_password"))
        user.save()
    return render(request, "change_password.html")


# NON_COMPLIANT: profile edit with CSRF protection disabled.
@csrf_exempt  # $ Alert
def profile_by_id(request, user_id):
    if request.method == "POST":
        profile = Profile.objects.get(pk=user_id)
        profile.bio = request.POST.get("bio")
        profile.save()
    return render(request, "profile.html")


# NON_COMPLIANT: bulk update through a query set.
@csrf_exempt  # $ Alert
def complete_all(request):
    Task.objects.filter(completed=False).update(completed=True)
    return HttpResponse("ok")


# NON_COMPLIANT: creating a model through the manager.
@csrf_exempt  # $ Alert
def task_create(request):
    Task.objects.create(title=request.POST["title"])
    return HttpResponse("ok")


# COMPLIANT: CSRF exempt, but read-only.
@csrf_exempt
def task_list(request):
    return render(request, "tasks.html", {"tasks": Task.objects.all()})


# COMPLIANT: state change, but CSRF protection stays enabled.
def task_delete(request, task_id):
    if request.method == "POST":
        Task.objects.get(pk=task_id).delete()
    return HttpResponse("ok")


# COMPLIANT: explicitly protected.
@csrf_protect
def task_rename(request, task_id):
    task = Task.objects.get(pk=task_id)
    task.title = request.POST["title"]
    task.save()
    return HttpResponse("ok")


# COMPLIANT: webhook authenticated by a signature header instead of cookies.
@csrf_exempt
def webhook(request):
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not hmac.compare_digest(signature, "expected"):
        return HttpResponse(status=403)
    Task.objects.create(title="from webhook")
    return HttpResponse("ok")


# COMPLIANT: legacy Django header lookup uses request.META.
@csrf_exempt
def legacy_webhook(request):
    authorization = request.META.get("HTTP_AUTHORIZATION", "")
    Task.objects.create(title=authorization)
    return HttpResponse("ok")


# NON_COMPLIANT: a template name is not evidence of header authentication.
@csrf_exempt  # $ Alert
def profile_signature(request):
    profile = Profile.objects.get(pk=request.user.pk)
    profile.bio = request.POST.get("bio")
    profile.save()
    return render(request, "profile/signature.html")


# COMPLIANT: the nested helper is never called or referenced.
@csrf_exempt
def unused_nested_helper(request):
    def create_task():
        Task.objects.create(title="unused")

    return HttpResponse("ok")


# NON_COMPLIANT: a state-changing call in a comprehension executes.
@csrf_exempt  # $ Alert
def create_from_comprehension(request):
    [Task.objects.create(title="from comprehension") for _ in range(1)]
    return HttpResponse("ok")


# NON_COMPLIANT: the nested function is passed as a callback.
@csrf_exempt  # $ Alert
def create_on_commit(request):
    def create_task():
        Task.objects.create(title="from callback")

    transaction.on_commit(create_task)
    return HttpResponse("ok")


# NON_COMPLIANT: the nested function is passed as a thread target.
@csrf_exempt  # $ Alert
def create_in_thread(request):
    def create_task():
        Task.objects.create(title="from thread")

    Thread(target=create_task).start()
    return HttpResponse("ok")


# NON_COMPLIANT: an unused nested header lookup does not authenticate the view.
@csrf_exempt  # $ Alert
def create_with_unused_header_check(request):
    def get_signature():
        return request.headers.get("X-Hub-Signature-256")

    Task.objects.create(title="not authenticated")
    return HttpResponse("ok")
