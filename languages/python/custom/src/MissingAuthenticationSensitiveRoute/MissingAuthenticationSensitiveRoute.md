# Missing authentication for sensitive Flask route

Flask routes that perform dangerous operations, such as running system commands, evaluating code, or deserializing data with `pickle`, must only be reachable by authenticated users. If such a route does not check authentication, any anonymous user can invoke the operation, which greatly increases the impact of any related weakness (for example command injection or unsafe deserialization).

This query reports Flask route handlers that contain a system command execution, code execution, or unsafe deserialization operation, but where no authentication check could be found. A handler is considered to check authentication if:

- it has a decorator whose name looks authentication related (for example `login_required`, `auth_required`, `requires_permission`),
- its body references a name that looks authentication or session related (for example `session`, `current_user`, `is_authenticated`, `token`), or
- its module registers a `before_request` hook, or an application-wide `before_app_request` hook exists.

## Recommendation

Require authentication (and, where appropriate, authorization) for every route that performs a sensitive operation, for example with `flask_login.login_required` or by checking the session before performing the operation.

## Example

The following route runs a shell command and is reachable without authentication:

```python
@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    res = subprocess.run(["ps", "aux", name], capture_output=True)
    return jsonify({"out": res.stdout.decode("utf-8")})
```

Protect it with an authentication decorator:

```python
@bp.route("/grep_processes")
@login_required
def grep_processes():
    name = request.args.get("name")
    res = subprocess.run(["ps", "aux", name], capture_output=True)
    return jsonify({"out": res.stdout.decode("utf-8")})
```

## References

- MITRE: [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html).
- Flask-Login: [Protecting views](https://flask-login.readthedocs.io/en/latest/#flask_login.login_required).
