from django.http import HttpResponse


def permissive_view(request):
    response = HttpResponse("ok")
    response["Access-Control-Allow-Origin"] = "*"  # $ Alert
    response.headers["Content-Security-Policy"] = "script-src 'unsafe-inline'"  # $ Alert
    return response


def safe_view(request):
    response = HttpResponse("ok")
    response["Access-Control-Allow-Origin"] = "https://trusted.example.com"
    response.headers["Content-Security-Policy"] = "script-src 'self'"
    return response
