Writing user-controlled text into a Python source file (`*.py` or `*.pyw`) allows a malicious user to persist arbitrary code in the application. The code runs the next time the module is imported or reloaded, for example by `importlib.reload`, a development server's autoreloader, or a service restart.

This is a second-order form of code injection that the standard `py/code-injection` query does not cover. This query reuses the sources and sanitizers of `py/code-injection` and reports file writes where the data is user-controlled and the target path is built from a string literal naming a Python source file, for example `os.path.join(dirname, "playground/main.py")` or `pathlib.Path("plugins") / "user.py"`.

## Recommendation

Do not generate Python source files from user input. Store user-provided data in a non-executable format (for example JSON) and load it as data, or restrict the input to a fixed set of allowed values.

## Example

The following example writes the `log_code` request parameter into a module that the application later imports:

```python
import os

def log_function_checker(request):
    log_code = request.POST.get("log_code")
    filename = os.path.join(os.path.dirname(__file__), "playground/main.py")
    with open(filename, "w") as f:
        f.write(log_code)  # BAD
```

Writing user input to a data file instead is not reported:

```python
import json

with open("data/state.json", "w") as f:
    f.write(json.dumps(request.POST.dict()))  # GOOD: not a Python module
```

## References

- OWASP: [Code Injection](https://owasp.org/www-community/attacks/Code_Injection).
- Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Common Weakness Enumeration: [CWE-95](https://cwe.mitre.org/data/definitions/95.html).
