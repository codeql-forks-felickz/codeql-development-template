# Flask app run in debug mode via the `debug` attribute

Running a Flask application in debug mode enables the Werkzeug debugger. It lets anyone who can trigger an exception run arbitrary Python code on the server, so it must never be enabled in production.

The standard `py/flask-debug` query only reports `app.run(debug=True)`. This query covers code that turns debug mode on through the `debug` attribute and then calls `app.run()` without a `debug` argument. It only alerts when the value is truthy by default:

- a truthy literal, such as `True`, `1`, or any non-empty string (including `"False"` and `"0"`), or
- an environment variable lookup (`os.environ.get` or `os.getenv`) whose default is one of those literals. In that case debug mode is on whenever the variable is not set.

## Recommendation

Do not enable debug mode by default. Read the setting with a falsy default and convert it to a real boolean, or leave debug mode to the `flask run --debug` command line during development.

## Example

In the following example, debug mode is on unless the deployment sets `FLASK_DEBUG` to an empty string:

```python
if __name__ == "__main__":
    app.debug = os.environ.get("FLASK_DEBUG", True)
    app.run(port=7000)
```

Parse the variable explicitly and default to off:

```python
if __name__ == "__main__":
    app.debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(port=7000)
```

## References

- Flask documentation: [Debug Mode](https://flask.palletsprojects.com/en/latest/quickstart/#debug-mode).
- Werkzeug documentation: [Debugging Applications](https://werkzeug.palletsprojects.com/en/latest/debug/).
- Common Weakness Enumeration: [CWE-215](https://cwe.mitre.org/data/definitions/215.html).
- Common Weakness Enumeration: [CWE-489](https://cwe.mitre.org/data/definitions/489.html).
