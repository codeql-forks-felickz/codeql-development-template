# Clear-text sensitive data stored in a database or user store

Storing sensitive data in clear text means that anyone who can read the database (through SQL injection, a leaked backup, or excessive privileges) can immediately learn the stored values.

This query reports sensitive values written without protection:

- Password values (identified by heuristics on variable, parameter, attribute, and request-parameter names) that reach an SQL statement writing to a password column: `INSERT INTO ... password ...`, `REPLACE INTO ... password ...`, or `UPDATE ... SET password = ...`. Statements built with string formatting (`%`, `str.format`, f-strings) and parameterized statements (`cursor.execute(sql, params)`) are both covered.
- Passwords or private data values identified by the same name heuristics that reach keyword arguments to a Django model manager's `.objects.create()` call.
- Hard-coded passwords, such as seed or default accounts, that reach such a statement (for example through a `for user, pw in seed_users:` loop) or appear as literals in the password position of the statement itself.
- Passwords stored under a `password` key in a module-level in-memory user store, such as `users[name] = {"password": password}`.

Values that pass through a hashing, key-derivation, or encryption call are not reported, and literals that already look like password hashes (hex digests, modular crypt, or Django encoded hashes) are ignored.

## Recommendation

Hash passwords with a slow, salted password hashing function (for example Argon2, scrypt, bcrypt, or PBKDF2) before storing them, and compare hashes when authenticating. Encrypt other private data at rest where appropriate.

## Known limitations

- For Django ORM storage, only keyword values passed directly to `.objects.create()` are modeled; assigning model attributes and then calling `.save()` is not covered.

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
