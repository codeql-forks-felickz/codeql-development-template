from django.shortcuts import redirect


def update_project(request):  # $ Alert[py/missing-authorization-request-handler]
    request.project.save()
    return redirect("/")
