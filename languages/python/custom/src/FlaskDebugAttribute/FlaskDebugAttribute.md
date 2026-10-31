# Flask or Django debug mode enabled by default

Running a Flask application in debug mode enables the Werkzeug debugger. It lets anyone who can trigger an exception run arbitrary Python code on the server, so it must never be enabled in production. Django's `DEBUG` and `TEMPLATE_DEBUG` settings expose detailed diagnostic information and should also be disabled in production.

The standard `py/flask-debug` query only reports `app.run(debug=True)`. This query covers code that turns Flask debug mode on through the `debug` attribute or the `DEBUG` config key (`app.config["DEBUG"] = ...` or `app.config.update(DEBUG=...)`) and then calls `app.run()` without a `debug` argument. It also reports literal `True` assignments to Django's `DEBUG` or `TEMPLATE_DEBUG` in a `settings.py` module. For Flask, it only alerts when the value is truthy by default:

- a truthy literal, such as `True`, `1`, or any non-empty string (including `"False"` and `"0"`), or
- an environment variable lookup (`os.environ.get` or `os.getenv`) whose default is one of those literals. In that case debug mode is on whenever the variable is not set.

## Recommendation

Do not enable debug mode by default. For Flask, read the setting with a falsy default and convert it to a real boolean, or leave debug mode to the `flask run --debug` command line during development. For Django, set both `DEBUG` and `TEMPLATE_DEBUG` to `False` in production.

## Known limitations

This query checks Django's `DEBUG` and `TEMPLATE_DEBUG` settings only; it does not assess `ALLOWED_HOSTS`.

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
- Django documentation: [Settings](https://docs.djangoproject.com/en/stable/ref/settings/#debug).
- Common Weakness Enumeration: [CWE-215](https://cwe.mitre.org/data/definitions/215.html).
- Common Weakness Enumeration: [CWE-489](https://cwe.mitre.org/data/definitions/489.html).
