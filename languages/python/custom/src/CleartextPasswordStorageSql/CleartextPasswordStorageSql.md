# Clear-text password stored in a database

Storing user passwords in clear text means that anyone who can read the database (through SQL injection, a leaked backup, or excessive privileges) immediately learns every user's password, which is often reused on other services.

This query tracks password values (identified by heuristics on variable, parameter, attribute, and request-parameter names) into SQL statements that write to a password column: `INSERT INTO ... password ...`, `REPLACE INTO ... password ...`, or `UPDATE ... SET password = ...`. Both statements built with string formatting (`%`, `str.format`, f-strings) and parameterized statements (`cursor.execute(sql, params)`) are covered. Values that pass through a hashing, key-derivation, or encryption call are not reported.

## Recommendation

Hash passwords with a slow, salted password hashing function (for example Argon2, scrypt, bcrypt, or PBKDF2, via `argon2-cffi`, `bcrypt`, `werkzeug.security.generate_password_hash`, or `cryptography`'s `Scrypt`) before storing them, and compare hashes when authenticating.

## Example

The following code stores the supplied password directly:

```python
def create(username, password):
    c.execute("INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password))
```

Store a password hash instead (and use a parameterized query):

```python
from werkzeug.security import generate_password_hash

def create(username, password):
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
              (username, generate_password_hash(password)))
```

## References

- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-256](https://cwe.mitre.org/data/definitions/256.html).
- Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
