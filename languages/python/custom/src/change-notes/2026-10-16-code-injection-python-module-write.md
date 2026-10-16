---
category: newQuery
---

- Added a new query, `py/custom/code-injection-python-module-write`, which detects user-controlled text being written to a Python source file (for example `open(os.path.join(dirname, "main.py"), "w").write(code)`), where it may be executed when the module is imported or reloaded.
