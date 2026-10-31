from django.shortcuts import redirect
from django.contrib.auth import logout
from django.urls import path


def logout_view(request):  # $ Source
    logout(request)
    # BAD: `redirect` query parameter is used without validating that it is a local URL
    return redirect(request.GET.get("redirect", "/"))  # $ Alert


def logout_safe(request):
    logout(request)
    # GOOD: constant redirect target
    return redirect("/")


urlpatterns = [
    path("logout/", logout_view),
    path("logout-safe/", logout_safe),
]
