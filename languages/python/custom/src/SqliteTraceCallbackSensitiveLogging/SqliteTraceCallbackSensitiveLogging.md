# Sensitive data logged by SQLite trace callback

`sqlite3.Connection.set_trace_callback` registers a function that is invoked with the text of every SQL statement executed on the connection. When the SQLite library supports it, bound parameters are expanded into the statement text. Installing a callback such as `print` or a logger method therefore writes every statement, including passwords, secrets, or other sensitive values embedded in or bound to it, to the application output or logs, where anyone with log access can read them.

## Recommendation

Do not enable SQL statement tracing on connections that handle sensitive data, or disable it (`set_trace_callback(None)`) before executing such statements. Avoid storing secrets in clear text in the first place.

## Example

The following code enables tracing and then executes a statement that includes a password and a TOTP secret:

```python
conn = sqlite3.connect("db_users.sqlite")
conn.set_trace_callback(print)  # BAD
c = conn.cursor()
c.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (secret, username))
```

Remove the trace callback:

```python
conn = sqlite3.connect("db_users.sqlite")
c = conn.cursor()
c.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (secret, username))  # GOOD
```

## References

- Python documentation: [sqlite3.Connection.set_trace_callback](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.set_trace_callback).
- Common Weakness Enumeration: [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
- Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
