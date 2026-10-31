# Database connection pool opened repeatedly without being closed

A `*sql.DB` returned by `database/sql.Open` or `database/sql.OpenDB` is not a single connection. It is a connection pool that owns open connections, a background connection-opener goroutine, and any file descriptors or sockets used by the driver. It is meant to be long-lived and shared.

If code that runs repeatedly (for example, an HTTP handler or a helper called per request) opens a new pool and never calls `Close`, every execution leaks a pool. Closing only the `*sql.Rows` or `*sql.Stmt` obtained from the pool does not release it. An attacker who can trigger the code path repeatedly can exhaust goroutines, connections, and file descriptors, causing a denial of service.

## Recommendation

Open the pool once (for example, at startup) and reuse it. If a pool really must be created locally, release it with `defer db.Close()` as soon as the open call succeeds.

## Example

In the following example, every search request opens a new pool. Only `rows` is closed, so the pool leaks:

```go
func getUsers(search string) []User {
	db, err := sql.Open("sqlite3", "data/users.db")
	if err != nil {
		panic(err)
	}
	rows, err := db.Query("SELECT id, name FROM user WHERE name LIKE ?", "%"+search+"%")
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	// ...
}
```

Close the pool when the function is done, or better, reuse a single shared pool:

```go
func getUsers(search string) []User {
	db, err := sql.Open("sqlite3", "data/users.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	// ...
}
```

## Limitations

The query reports a pool only when it is stored in a local variable that is never closed and never escapes the function (it is not returned, stored in a field, global, or composite literal, passed to another function, sent on a channel, or address-taken). Pools opened in `main` or `init`, or in helpers only reachable from them outside of a loop, are not reported because they run once per process.

## References

- Go documentation: [sql.Open](https://pkg.go.dev/database/sql#Open) ("The returned DB is safe for concurrent use by multiple goroutines and maintains its own pool of idle connections. Thus, the Open function should be called just once.").
- Common Weakness Enumeration: [CWE-772](https://cwe.mitre.org/data/definitions/772.html).
- Common Weakness Enumeration: [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
