# Database query built from user-controlled sources (extended call graph)

This query is a variant of the standard `go/sql-injection` query. It reports the same results, and in addition it follows untrusted data into functions that are invoked through function-typed struct fields.

The standard Go data-flow library resolves a call through a function value only when that value reaches the call by local flow. When a function or method value is stored in a struct field (often in a struct literal that is appended to a global registry) and that field is invoked from another function, the call has no resolved target. Untrusted arguments therefore never reach the stored function's parameters.

The `lib/FunctionFieldCallTaintStep.qll` library adds a taint step for such unresolved calls. It connects each argument to the matching parameter of every function value written to the same field, including fields set in elided pointer element literals such as `[]*T{{F: fn}}`.

## Recommendation

Use parameterized queries (placeholders such as `?` with the values passed as separate arguments) instead of building SQL text with string concatenation or `fmt.Sprintf`.

## Example

The following handler is registered through a struct field and builds a query from untrusted input:

```go
type Sink struct {
	Handler func(mode, in string) string
}

func (si sqliteInj) execHandler(mode, in string) string {
	query := fmt.Sprintf("SELECT '%s' as '%s'", in, "test")
	si.db.Exec(query) // BAD
	si.db.Exec("SELECT ? as ?", in, "test") // GOOD
	return ""
}

var sinks = []*Sink{{Handler: sqliteInj{db}.execHandler}}

func handle(w http.ResponseWriter, r *http.Request) {
	for _, s := range sinks {
		s.Handler("unsafe", r.URL.Query().Get("input"))
	}
}
```

## References

- OWASP: [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
