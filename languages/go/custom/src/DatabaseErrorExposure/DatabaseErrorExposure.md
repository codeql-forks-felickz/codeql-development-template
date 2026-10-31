# Information exposure through a database error message

Errors returned by database drivers often contain connection strings, host names, user names, SQL fragments, table and column names, or driver versions. Writing the message of such an error to an HTTP response, or rendering it in a page template, reveals these internals to the user and can help an attacker refine further attacks such as SQL injection.

This query tracks errors returned by `database/sql` and common SQL and MongoDB driver packages to HTTP response bodies and to the data argument of `text/template` and `html/template` execution.

## Recommendation

Log the detailed error on the server and send the user a generic message that does not include the error text.

## Example

In the following example, the first handler writes the database error message to the response (BAD). The second handler logs the error and returns a generic message (GOOD).

```go

func listHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT name FROM items")
	if err != nil {
		// BAD: the database error message is sent to the user
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}

func safeListHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT name FROM items")
	if err != nil {
		// GOOD: the error is logged and a generic message is sent
		log.Printf("query failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}

```

## References

- OWASP: [Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling).
- Common Weakness Enumeration: [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
- Common Weakness Enumeration: [CWE-497](https://cwe.mitre.org/data/definitions/497.html).
