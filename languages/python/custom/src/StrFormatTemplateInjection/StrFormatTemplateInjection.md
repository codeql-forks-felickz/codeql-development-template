# Format string built from user-controlled sources

## Overview

Python format strings (`str.format`, `str.format_map` and `string.Formatter`) are a small template language. A replacement field can access attributes and items of the format arguments, for example `{0.__class__}`, `{0.__init__.__globals__}` or `{1.environ[SECRET_KEY]}`. If a user controls the format string, they can traverse the objects passed as arguments and disclose secrets such as environment variables, configuration values or internal objects. Very large field widths (for example `{0:999999999}`) can also exhaust memory.

The query reports user-controlled values that are used as the format string of `str.format`, `str.format_map`, `string.Formatter.format` or `string.Formatter.vformat` when at least one non-literal value is formatted. It also tracks user-controlled values through local variables that are defined by iterable unpacking and read in a nested scope, such as a generator expression.

## Recommendation

Do not use user input as a format string. Use a constant format string and pass the user input as an argument, or use a template engine with a sandbox (for example `string.Template` or `jinja2.sandbox.SandboxedEnvironment`) that does not allow attribute traversal.

## Example

The following handler formats a user-provided template with an open file and the `os` module, so `{1.environ}` discloses the process environment:

```python
@app.route("/render")
def render():
    tmpl = request.args["tmpl"]
    return tmpl.format(open(__file__), os)  # BAD
```

Use a constant format string instead:

```python
@app.route("/render")
def render():
    name = request.args["name"]
    return "Hello {}".format(name)  # GOOD
```

## References

- Python documentation: [Format String Syntax](https://docs.python.org/3/library/string.html#format-string-syntax).
- Armin Ronacher: [Be Careful with Python's New-Style String Format](https://lucumr.pocoo.org/2016/12/29/careful-with-str-format/).
- Common Weakness Enumeration: [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html).
- Common Weakness Enumeration: [CWE-134](https://cwe.mitre.org/data/definitions/134.html).
