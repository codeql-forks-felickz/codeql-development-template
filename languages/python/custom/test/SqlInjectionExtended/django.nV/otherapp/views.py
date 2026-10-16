from django.db import connection


def upload(request, project_id):
    # GOOD: same function name as a routed view, but this module is never routed
    connection.cursor().execute("SELECT * FROM t WHERE id=" + project_id)
