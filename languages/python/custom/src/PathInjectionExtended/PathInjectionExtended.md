Accessing files using paths constructed from user-controlled data can allow an attacker to access unexpected resources, such as files outside an intended directory (CWE-22).

This query extends the standard `py/path-injection` query in three ways:

* `py/path-injection` loses track of user input when it is assigned to a local variable by tuple unpacking or by a `for` loop and that variable is then read inside a comprehension, generator expression, lambda or nested function. This query follows that flow.
* `py/path-injection` only considers file system APIs such as `open` or `shutil.move`. This query also considers file paths passed to operating system file commands such as `mv`, `cp` or `cat`, whether in a shell command string or in an argument list. Quoting the command (for example with `shlex.quote`) prevents command injection but not path traversal.
* This query considers user-controlled template names passed to `django.shortcuts.render`, which can select a template outside the intended directory.

Results that `py/path-injection` already reports are not repeated.

## Known limitations

Shell command strings are analyzed only when path substitutions can be identified as concatenation operands or simple `%s` formatting arguments in the first command segment. Other shell-string construction and formatting forms are not parsed.

Comprehension capture flow may retain taint when every branch reassigns an unpacked variable and those definitions merge before the comprehension.

Taint is not tracked across values persisted with raw SQL and later loaded through the Django ORM. A filename stored in one request and used in a later request can therefore be missed.

## Recommendation

Validate user input before using it to construct a file path. Normalize the path with `os.path.normpath` or `os.path.realpath`, then check that the result is inside an allowed directory. Alternatively, map user input to a fixed allowlist of file names.

## Example

The following handler splits the request path into a path and a query string, parses the query string using a generator expression, and opens the file named by the `path` parameter. An attacker can request `/?path=../../etc/passwd` to read arbitrary files.

```python
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(
            (m.group("p"), urllib.parse.unquote(m.group("v")))
            for m in re.finditer(r"(?P<p>\w+)=(?P<v>[^&]+)", query)
        )
        content = open(os.path.abspath(params["path"]), "rb").read()  # BAD
```

Check the normalized path against a base directory before opening it:

```python
        base = "/srv/www/"
        target = os.path.normpath(os.path.join(base, params["path"]))
        if target.startswith(base):
            content = open(target, "rb").read()  # GOOD
```

The following Django view moves an uploaded file to a destination built from the user-provided `name` field. A name such as `../../settings.py` moves the file outside the upload directory and can overwrite application files.

```python
def store_uploaded_file(title, uploaded_file):
    subprocess.call(["mv", uploaded_file.temporary_file_path(), os.path.join(UPLOAD_DIR, title)])  # BAD
```

Do not rely on `os.path.basename` alone, since `os.path.basename("..")` is still `".."`:

```python
def store_uploaded_file(title, uploaded_file):
    safe = os.path.basename(title)
    subprocess.call(["mv", uploaded_file.temporary_file_path(), os.path.join(UPLOAD_DIR, safe)])  # BAD
```

## References

* OWASP: [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).
* Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
