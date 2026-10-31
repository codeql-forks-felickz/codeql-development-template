# URL redirection from remote source

Directly incorporating user input into a URL redirect request without validating the input can facilitate phishing attacks. In these attacks, unsuspecting users can be redirected to a malicious site that looks very similar to the real site they intend to visit, but which is controlled by the attacker.

This version of `py/url-redirection` extends the standard query in two ways:

- A value written to a `Location` response header (for example with `BaseHTTPRequestHandler.send_header("Location", url)` in the standard library `http.server` module) is treated as a redirect target, in addition to dedicated redirect APIs such as `flask.redirect`.
- Taint is tracked from local variables defined by iterable unpacking (for example `path, query = self.path.split("?", 1)`) into nested scopes, such as generator expressions, that read those variables.

## Recommendation

To guard against untrusted URL redirection, it is advisable to avoid putting user input directly into a redirect URL. Instead, maintain a list of authorized redirects on the server; then choose from that list based on the user input provided.

If this is not possible, then the user input should be validated in some other way, for example, by verifying that the target URL does not include an explicit host name.

## Example

The following example shows an `http.server` request handler that reads the `redir` query parameter and copies it into the `Location` header without validation. An attacker can use this to redirect users to an arbitrary site.

```python
import http.server
import urllib.parse


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        self.send_response(302)
        # BAD: the redirect target is fully controlled by the user
        self.send_header("Location", params["redir"][0])
        self.end_headers()
```

One way to remedy the problem is to only redirect to targets from a fixed list of allowed URLs:

```python
import http.server
import urllib.parse


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        target = params["redir"][0]
        if target in ["/home", "/profile"]:
            self.send_response(302)
            # GOOD: the redirect target is checked against an allowlist
            self.send_header("Location", target)
        else:
            self.send_response(400)
        self.end_headers()
```

## References

- OWASP: [Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).
- Python Library Reference: [http.server.BaseHTTPRequestHandler.send_header](https://docs.python.org/3/library/http.server.html#http.server.BaseHTTPRequestHandler.send_header).
- Common Weakness Enumeration: [CWE-601](https://cwe.mitre.org/data/definitions/601.html).
