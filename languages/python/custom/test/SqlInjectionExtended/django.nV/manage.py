#!/usr/bin/env python
# The checkout folder is named `django.nV`: `Folder.getStem()` is `django`, so this
# folder is treated as a namespace package named `django`, and `taskManager.views`
# is named `django.taskManager.views` in the database.
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "taskManager.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
