import traceback
from django.shortcuts import render


def view(request):
    try:
        value = int(request.GET["value"])
    except (KeyError, ValueError):
        return render(request, "error.html", {"trace": traceback.format_exc()}) # $ Alert[py/error-message-exposure]
    return render(request, "ok.html", {"value": value})


def view_safe(request):
    try:
        value = int(request.GET["value"])
    except (KeyError, ValueError):
        # Safe: generic message only.
        return render(request, "error.html", {"error": "Invalid value"})
    return render(request, "ok.html", {"value": value})


def handle_error(request, exception: Exception): # $ Source[py/error-message-exposure]
    return render(request, "500.html", context={"exception": exception}) # $ Alert[py/error-message-exposure]
