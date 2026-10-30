# Password stored or checked in cleartext or with a fast hash

Passwords must never be stored in a form that lets anyone who reads the password store recover them. If a password is written to a database in cleartext, compared directly against a password column, or hashed with a fast general-purpose hash such as MD5, SHA-1 or SHA-256, an attacker who obtains a copy of the database (for example through SQL injection, a backup leak or an insider) can recover the original passwords, often within seconds, and reuse them on other services.

This query tracks password values (method parameters with password-like names and values such as `request.getParameter("password")`) and reports them when they reach, without first passing through a password-hashing function:

- a SQL statement that reads or writes a password column, either by string concatenation or as a bind parameter (CWE-256),
- the password setter of a JPA `@Entity` (CWE-256),
- a `String.equals` or `Objects.equals` comparison against a password read from storage, such as `user.getPassword()` (CWE-256),
- the input of a fast hash function such as `MessageDigest.update`/`digest`, Apache Commons Codec `DigestUtils`, Spring `DigestUtils` or Guava `HashFunction` (CWE-916).

## Recommendation

Store passwords using a dedicated, adaptive password-hashing function with a per-password salt, such as bcrypt, scrypt, Argon2 or PBKDF2 (for example Spring Security's `BCryptPasswordEncoder` or `Argon2PasswordEncoder`). Verify login attempts with the matching `matches` method of the encoder instead of comparing strings or querying the database with the submitted password.

## Example

In the following example the submitted password is written to the database in cleartext, compared against a stored cleartext password, and hashed with MD5:

```java
String pass = request.getParameter("password");
stmt.executeUpdate("INSERT into users(username, password) values ('" + user + "','" + pass + "')");

if (password.equals(user.getPassword())) { ... }

MessageDigest md = MessageDigest.getInstance("MD5");
md.update(password.getBytes());
```

The following code uses bcrypt instead, so only a slow, salted hash is stored and compared:

```java
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
jdbcTemplate.update("INSERT INTO users(username, password) VALUES (?, ?)", user, encoder.encode(password));

if (encoder.matches(password, user.getPassword())) { ... }
```

## References

- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html).
- Common Weakness Enumeration: [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html).
