# Command built from user-controlled sources

If a system command is built from user-provided data without sufficient sanitization, a malicious user may be able to run commands to exfiltrate data or compromise the system.

This is a customized variant of the standard `go/command-injection` query. The sources, sinks and sanitizers are unchanged. In addition, it tracks data passed to a call through a function-typed struct field (for example `s.Handler(mode, input)`) into the parameters of every function stored in that field, whether in a composite literal (`Sink{Handler: execHandler}`, including the `{...}` elements of a `[]*Sink{...}` literal) or by assignment (`s.Handler = execHandler`). The Go call graph does not resolve such calls, so the standard query misses handlers that are registered in a table and dispatched through a field, which is a common pattern for framework-agnostic route handlers.

## Recommendation

If possible, use hard-coded string literals to specify the command to run. Instead of interpreting user input directly as command names, examine the input and then choose among hard-coded string literals.

If this is not possible, then add sanitization code to verify that the user input is safe before using it.

## Example

```go
type Sink struct {
	Handler func(payload string) string
}

var sinks = []*Sink{{Handler: execHandler}}

func execHandler(in string) string {
	args := strings.Fields(in)
	out, _ := exec.Command(args[0], args[1:]...).Output() // BAD: the request selects the executable
	return string(out)
}

func handler(w http.ResponseWriter, r *http.Request) {
	for _, s := range sinks {
		w.Write([]byte(s.Handler(r.URL.Query().Get("input"))))
	}
}
```

## References

- OWASP: [Command Injection](https://www.owasp.org/index.php/Command_Injection).
- Common Weakness Enumeration: [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
