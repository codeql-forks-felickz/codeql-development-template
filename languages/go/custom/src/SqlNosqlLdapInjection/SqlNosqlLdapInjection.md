# MySQL connection allows multiple statements per query

The `github.com/go-sql-driver/mysql` driver rejects query strings that contain more than one SQL statement unless `multiStatements` is enabled. When it is enabled (through the `multiStatements=true` DSN parameter, `Config.Params["multiStatements"]`, or `Config.MultiStatements`), a single call such as `db.Query` can execute several semicolon-separated statements.

This greatly increases the impact of any SQL injection in the application: instead of being limited to altering the original statement, an attacker can append arbitrary statements such as `DROP TABLE`, `UPDATE`, or `INSERT` (stacked queries).

## Recommendation

Leave `multiStatements` disabled (the driver default). If several statements must run together, issue them as separate calls or inside a transaction, and always use parameterized queries.

## Example

The following code enables multiple statements on the connection:

```go
cfg := mysql.NewConfig()
cfg.Params = map[string]string{}
cfg.Params["multiStatements"] = "true" // BAD
db, err := sql.Open("mysql", cfg.FormatDSN())
```

The fix is to not set the parameter:

```go
cfg := mysql.NewConfig()
db, err := sql.Open("mysql", cfg.FormatDSN()) // GOOD: multiStatements defaults to false
```

## References

- go-sql-driver/mysql: [multiStatements](https://github.com/go-sql-driver/mysql#multistatements).
- OWASP: [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
