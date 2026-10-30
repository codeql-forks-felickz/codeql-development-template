# Uncontrolled command line (extended)

Code that passes user input directly to `os.system`, `subprocess` with `shell=True`, or some other library routine that executes a command, allows the user to execute malicious commands.

This query is a variant of the standard `py/command-line-injection` query. In addition to the standard sources, sinks and taint steps, it tracks taint:

- into lambdas, nested functions and comprehensions (including generator expressions) that capture a local variable defined without a directly assigned value, such as a tuple-unpacking target (`path, query = self.path.split("?", 1)`);
- through `urllib.parse.parse_qsl`, commonly used to read request parameters in `http.server` request handlers.

## Recommendation

If possible, use hard-coded string literals to specify the command to run. Instead of passing the user input directly to a shell, pass the command and its arguments as a list without `shell=True`, and examine the user input before using it, for example by choosing among hard-coded values from an allowlist.

## Example

The following `http.server` handler parses the query string with tuple unpacking and a generator expression, and then concatenates the `domain` parameter into a shell command. The first call is unsafe. The second call is safe because the arguments are passed as a list without a shell.

```python
class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(
            (m.group("p"), urllib.parse.unquote(m.group("v")))
            for m in re.finditer(r"(?P<p>\w+)=(?P<v>[^&]+)", query)
        )
        # BAD: user input is interpreted by a shell
        subprocess.check_output("nslookup " + params["domain"], shell=True)
        # GOOD: no shell is involved
        subprocess.check_output(["nslookup", params["domain"]])
```

## References

- OWASP: [Command Injection](https://owasp.org/www-community/attacks/Command_Injection).
- Python documentation: [urllib.parse.parse_qsl](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.parse_qsl).
- Common Weakness Enumeration: [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Common Weakness Enumeration: [CWE-88](https://cwe.mitre.org/data/definitions/88.html).
