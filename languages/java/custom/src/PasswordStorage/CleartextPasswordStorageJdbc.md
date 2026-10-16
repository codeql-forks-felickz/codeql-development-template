# Cleartext storage of a password in a database

Writing a user's password to a database without hashing it means that anyone who can read the database, for example through SQL injection, a backup, debug output or privileged access, immediately obtains reusable credentials.

This query tracks password-like values (variables, getters and lookups such as `request.getParameter("password")`) into JDBC `INSERT`, `UPDATE`, `REPLACE` or `MERGE` statements, either concatenated into the SQL passed to `Statement.execute*`/`addBatch`, or bound with `PreparedStatement.set*`. Values that pass through a call whose name suggests hashing or encryption, or through a Spring `PasswordEncoder.encode`, are not reported.

## Recommendation

Store only the output of a password hashing function such as Argon2, scrypt, bcrypt or PBKDF2.

## Example

```java
stmt.executeUpdate("INSERT INTO users(username, password) VALUES ('" + user + "','" + pass + "')"); // BAD
```

```java
PreparedStatement ps = con.prepareStatement("INSERT INTO users(username, password) VALUES (?, ?)");
ps.setString(1, user);
ps.setString(2, passwordEncoder.encode(pass)); // GOOD
```

## References

- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- CWE-256: [Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
