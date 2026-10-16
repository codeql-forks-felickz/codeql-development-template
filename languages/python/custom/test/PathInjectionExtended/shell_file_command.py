import os
import shlex
import subprocess

from django.http import HttpResponse
from django.urls import path

UPLOAD_DIR = "/srv/app/static/uploads"


def store_uploaded_file(title, uploaded_file):
    # Reduced from the django.nV `store_uploaded_file` helper.
    os.system(
        "mv " +
        uploaded_file.temporary_file_path() +
        " " +
        "%s/%s" %
        (UPLOAD_DIR,
         title))  # $ Alert
    return "/static/uploads/%s" % title


def store_quoted(title, uploaded_file):
    # Quoting stops command injection but not `../` traversal.
    cmd = "mv %s %s" % (shlex.quote(uploaded_file.temporary_file_path()), shlex.quote(os.path.join(UPLOAD_DIR, title)))  # $ Alert
    os.system(cmd)


def store_with_argument_list(title, uploaded_file):
    subprocess.call(["mv", uploaded_file.temporary_file_path(), os.path.join(UPLOAD_DIR, title)])  # $ Alert


def store_with_absolute_command(title, uploaded_file):
    subprocess.run(["/bin/cp", uploaded_file.temporary_file_path(), UPLOAD_DIR + "/" + title])  # $ Alert


def store_basename(title, uploaded_file):
    safe = os.path.basename(title)
    subprocess.call(["mv", uploaded_file.temporary_file_path(), os.path.join(UPLOAD_DIR, safe)])


def store_checked(title, uploaded_file):
    target = os.path.normpath(os.path.join(UPLOAD_DIR, title))
    if target.startswith(UPLOAD_DIR + "/"):
        subprocess.call(["mv", uploaded_file.temporary_file_path(), target])


def echo_title(title):
    # Not a file command.
    subprocess.call(["echo", title])


def store_with_shutil(title, uploaded_file):
    # Already reported by the standard `py/path-injection` query.
    import shutil
    shutil.move(uploaded_file.temporary_file_path(), os.path.join(UPLOAD_DIR, title))


def upload(request):  # $ Source
    name = request.POST.get("name", False)
    f = request.FILES["file"]
    store_uploaded_file(name, f)
    store_quoted(name, f)
    store_with_argument_list(name, f)
    store_with_absolute_command(name, f)
    store_basename(name, f)
    store_checked(name, f)
    echo_title(name)
    store_with_shutil(name, f)
    return HttpResponse("ok")


urlpatterns = [
    path("upload/", upload),
]
