from django.db import connection
from django.shortcuts import redirect


def upload(request, project_id):  # $ Source[py/sql-injection-extended]
    if request.method == "POST":
        name = request.POST.get("name", False)
        curs = connection.cursor()
        curs.execute(
            "insert into taskManager_file ('name','project_id') values ('%s',%s)"
            % (name, project_id)  # $ Alert[py/sql-injection-extended]
        )
    return redirect("/taskManager/" + project_id + "/")


def safe_upload(request, project_id):
    if request.method == "POST":
        name = request.POST.get("name", False)
        curs = connection.cursor()
        # GOOD: parameter binding
        curs.execute(
            "insert into taskManager_file ('name','project_id') values (%s,%s)",
            (name, project_id),
        )
    return redirect("/taskManager/" + project_id + "/")
