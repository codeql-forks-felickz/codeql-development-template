from django.http import HttpResponse, HttpResponseRedirect


def login(request, access_token, refresh):
    response = HttpResponseRedirect(request.GET.get("next", "/"))
    response.set_cookie("access_token", access_token, httponly=False, secure=False)  # BAD
    response.set_cookie("refresh_token", str(refresh), httponly=False, secure=False)  # BAD
    response.set_cookie("theme", "dark", httponly=False, secure=False)  # GOOD: not sensitive
    return response


def view(request):
    response = HttpResponse("ok")
    response.set_cookie("sessionid", "value", httponly=False, secure=False)  # BAD
    response.set_cookie("access_token", "value", httponly=True, secure=True)  # GOOD
    return response
