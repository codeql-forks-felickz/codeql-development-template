# Cleartext storage of sensitive information in a database

Personal data such as social security numbers, dates of birth and salaries, as well as passwords, should not be stored in a database in cleartext. Anyone who can read the database, a backup of it, or the result of an injection attack against it can then read the data directly.

This query reports SQL `INSERT`, `UPDATE`, `REPLACE`, `UPSERT` and `MERGE` statements executed through `database/sql` (or another modeled SQL library) whose query text or bind parameters contain data whose name suggests it is sensitive, unless the data was first passed through a hashing or encryption function.

## Recommendation

Hash passwords with a password-specific adaptive hash function such as Argon2id, bcrypt or scrypt. Encrypt other sensitive data that must be recoverable, for example with an authenticated cipher such as AES-GCM and a key that is not stored alongside the data. Avoid storing sensitive data at all if the application does not need it.

## Example

In the following example, the social security number of a user is written to the database in cleartext (BAD), and in the second function it is encrypted before it is stored (GOOD).

```go

func storeUser(db *sql.DB, user User) {
	// BAD: the SSN is stored in cleartext
	db.Exec("INSERT INTO users (name, ssn) VALUES (?, ?)", user.Name, user.SSN)
}

func storeUserSafely(db *sql.DB, user User) {
	// GOOD: the SSN is encrypted before it is stored
	db.Exec("INSERT INTO users (name, ssn) VALUES (?, ?)", user.Name, encrypt(user.SSN))
}

```

## References

- OWASP: [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
- Common Weakness Enumeration: [CWE-359](https://cwe.mitre.org/data/definitions/359.html).
