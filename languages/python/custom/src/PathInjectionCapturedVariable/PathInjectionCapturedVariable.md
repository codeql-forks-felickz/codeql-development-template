Accessing files using paths constructed from user-controlled data can allow an attacker to access unexpected resources, such as files outside an intended directory (CWE-22).

The standard `py/path-injection` query loses track of user input when it is assigned to a local variable by tuple unpacking or by a `for` loop and that variable is then read inside a comprehension, generator expression, lambda or nested function. This query reports those additional flows. Results that `py/path-injection` already reports are not repeated.

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

## References

* OWASP: [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).
* Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
