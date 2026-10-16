import importlib
import json
import os
import pathlib

from django.http import JsonResponse
from django.urls import path

from .utility import code_converter


def code_checker(request):  # $ Source
    python_code = request.POST["python_code"]
    if not code_converter(python_code):
        return JsonResponse({"status": "error"})
    from playground.lab import main
    return JsonResponse({"result": main.lab("x")})


def log_function_checker(request):  # $ Source
    log_code = request.POST.get("log_code")
    dirname = os.path.dirname(__file__)
    log_filename = os.path.join(dirname, "playground/A9/main.py")
    f = open(log_filename, "w")
    f.write(log_code)  # $ Alert
    f.close()
    return JsonResponse({"message": "success"})


def reload_module(request):  # $ Source
    with open("plugins/user_plugin.py", "w") as f:
        f.write(request.POST["code"])  # $ Alert
    import plugins.user_plugin
    importlib.reload(plugins.user_plugin)
    return JsonResponse({"message": "success"})


def pathlib_write(request):  # $ Source
    pathlib.Path("generated/settings_override.py").write_text(request.GET["code"])  # $ Alert
    return JsonResponse({"message": "success"})


def write_text_file(request):
    # Not a Python source file.
    with open("uploads/notes.txt", "w") as f:
        f.write(request.POST["notes"])
    return JsonResponse({"message": "success"})


def write_json_file(request):
    # Not a Python source file.
    with open(os.path.join("data", "state.json"), "w") as f:
        f.write(json.dumps(request.POST.dict()))
    return JsonResponse({"message": "success"})


def write_constant_module(request):
    # Content is not user controlled.
    with open("generated/constants.py", "w") as f:
        f.write("DEBUG = False\n")
    return JsonResponse({"message": "success"})


def write_allowlisted_module(request):
    code = request.POST["code"]
    if code == "DEBUG = False\n":
        with open("generated/constants.py", "w") as f:
            f.write(code)
    return JsonResponse({"message": "success"})


urlpatterns = [
    path("checker", code_checker),
    path("log", log_function_checker),
    path("reload", reload_module),
    path("pathlib", pathlib_write),
    path("txt", write_text_file),
    path("json", write_json_file),
    path("constant", write_constant_module),
    path("allowlisted", write_allowlisted_module),
]
