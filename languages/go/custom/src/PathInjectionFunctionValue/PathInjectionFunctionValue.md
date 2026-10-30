# Uncontrolled data used in path expression (including calls through function-valued fields)

This query extends the standard `go/path-injection` query. It uses the same sources, sinks and sanitizers, and also follows user input into functions that are called through function values stored in struct fields.

Dispatch tables like this are common in Go web applications:

```go
type Sink struct {
	Name    string
	Wrapper func(payload string) (string, error)
}

var sinks = []*Sink{
	{Name: "os.ReadFile", Wrapper: osReadFile},
}

func osReadFile(payload string) (string, error) {
	b, err := os.ReadFile(payload) // path traversal
	return string(b), err
}

func handler(w http.ResponseWriter, r *http.Request) {
	for _, s := range sinks {
		s.Wrapper(r.URL.Query().Get("input"))
	}
}
```

The standard Go call graph does not resolve calls like `s.Wrapper(...)`, so taint stops at the call and `go/path-injection` reports nothing. This query resolves these calls field-sensitively. A call through field `F` may target any function or function literal written to `F`. Writes can be assignments (`s.F = fn`), struct literals (`T{F: fn}`), elided pointer struct literals inside slice, array or map literals (`[]*T{{F: fn}}`), or results of factory functions that return a function literal.

## Recommendation

Validate user input before using it to construct a file path. For example, reject paths that contain `..`, or resolve the path and check that it is inside a safe base directory.

## References

- OWASP: [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).
- Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
