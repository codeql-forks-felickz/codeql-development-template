import os

from django.http import HttpResponse
from django.urls import path


def store_uploaded_file(title, uploaded_file):
    upload_dir_path = "/srv/uploads"
    os.system("mv " + uploaded_file.temporary_file_path() + " " + "%s/%s" % (upload_dir_path, title))  # $ Alert
    return "/static/uploads/%s" % title


def upload(request):  # $ Source
    name = request.POST.get("name", False)
    store_uploaded_file(name, request.FILES["file"])
    return HttpResponse("ok")


def upload_name(request):  # $ Source
    f = request.FILES["file"]
    title = request.POST.get("title", "")
    os.system("mv " + f.name + " /tmp/" + title)  # $ Alert
    return HttpResponse("ok")


def upload_safe(request):
    f = request.FILES["file"]
    os.system("mv /tmp/upload /srv/uploads/static.bin")  # OK
    return HttpResponse("ok")


urlpatterns = [
    path("upload/", upload),
    path("upload_name/", upload_name),
    path("upload_safe/", upload_safe),
]
