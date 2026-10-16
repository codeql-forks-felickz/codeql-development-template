---
category: newQuery
---
* Added a new query, `py/path-injection-extended`, which extends `py/path-injection` with:
  * taint through local variables that are defined by tuple unpacking or `for` loops and then captured by a comprehension, generator expression, lambda or nested function (for example `path, query = self.path.split("?", 1)` followed by `dict((k, query) for k in keys)`).
  * file paths passed to operating system file commands such as `mv`, `cp` or `cat`, either in a shell command string (`os.system("mv " + src + " " + dst)`) or in an argument list (`subprocess.call(["mv", src, dst])`).

  Results of `os.path.basename` are treated as safe. Only results that `py/path-injection` does not already report are reported.
