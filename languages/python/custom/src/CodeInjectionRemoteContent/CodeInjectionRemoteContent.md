Fetching content from a URL that is controlled by a user, and then interpreting that content as Python code (for example with `exec`, `eval`, or `compile`), allows a malicious user to host arbitrary code on a server they control and have the application execute it. This is a form of remote file inclusion.

The standard `py/code-injection` query does not track taint from a user-controlled URL into the body of the response returned by every HTTP client library (for example `urllib.request.urlopen`). This query adds that propagation and only reports flows that `py/code-injection` does not already report.

## Recommendation

Never execute code that was downloaded from a location chosen by a user. If dynamic behavior is required, use a fixed allowlist of trusted locations or modules, and validate the user input against that allowlist before using it.

## Example

The following example fetches the URL given in the `include` request parameter and executes the response body:

```python
from urllib.request import urlopen
from flask import Flask, request

app = Flask(__name__)

@app.route("/include")
def include():
    body = urlopen(request.args["include"]).read()
    exec(body)  # BAD: executes attacker-hosted code
```

Executing a fixed local template is not affected by user input:

```python
exec(open("static_template.py").read())  # GOOD: constant path
```

## References

- OWASP: [Code Injection](https://owasp.org/www-community/attacks/Code_Injection).
- Wikipedia: [Code Injection](https://en.wikipedia.org/wiki/Code_injection).
- Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Common Weakness Enumeration: [CWE-95](https://cwe.mitre.org/data/definitions/95.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
