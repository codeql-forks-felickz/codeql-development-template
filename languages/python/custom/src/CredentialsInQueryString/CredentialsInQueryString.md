# Credentials read from URL query string

Reading a password from the query string of an HTTP request (for example `flask.request.args`) means that clients send the credential as part of the URL. URLs are retained in browser history and bookmarks, are recorded in web server, reverse proxy and monitoring access logs, and can leak to third parties through the `Referer` header.

## Recommendation

Accept credentials only in the body of a `POST` request sent over HTTPS (for example `flask.request.form`), never as query string parameters.

## Example

The following handler reads the password from the query string:

```python
@app.route("/login_and_redirect")
def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")  # BAD
    ...
```

Read the credentials from the request body instead:

```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")  # GOOD
    ...
```

## References

- OWASP: [Information exposure through query strings in URL](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url).
- Common Weakness Enumeration: [CWE-598](https://cwe.mitre.org/data/definitions/598.html).
