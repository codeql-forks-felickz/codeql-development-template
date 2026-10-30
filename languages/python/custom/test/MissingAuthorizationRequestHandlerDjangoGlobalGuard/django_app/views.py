from django.shortcuts import redirect


def update_project(request):
    request.project.save()
    return redirect("/")
