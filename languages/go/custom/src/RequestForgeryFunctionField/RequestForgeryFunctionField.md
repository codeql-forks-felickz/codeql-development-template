# Uncontrolled data used in network request via function-valued field

Directly incorporating user input into an HTTP request without validating the input can facilitate server-side request forgery (SSRF) attacks, in which the server can be tricked into making a request to, and interacting with, an attacker-controlled or internal server (for example loopback services, private networks or cloud metadata endpoints).

This query is a variant of `go/request-forgery`. The standard Go call graph does not resolve calls made through function values stored in struct fields, such as a handler registered in a route table and later invoked as `s.Handler(mode, input)`. As a result, user input passed through such a call to a function that issues an outgoing request is not tracked by `go/request-forgery`. This query additionally models those calls: an argument of an unresolved call through field `F` flows to the corresponding parameter of every function or function literal written to `F`. Results already reported by `go/request-forgery` are not repeated.

## Recommendation

To guard against SSRF attacks, avoid putting user input directly into a request URL. Instead, maintain a list of authorized URLs on the server and choose from that list based on the user input. Alternatively, validate the scheme, host, port and resolved IP address of the URL against an allow-list before sending the request.

## Example

In the following example, the route table stores `httpHandler` in the `Handler` field, and the request handler forwards the `input` query parameter through that field. `httpHandler` then sends a request to the user-supplied URL:

```go
type Sink struct {
	Handler func(payload string) string
}

var sinks = []*Sink{{Handler: httpHandler}}

func httpHandler(payload string) string {
	resp, _ := http.Get(payload) // BAD: payload is user-controlled
	defer resp.Body.Close()
	return resp.Status
}

func handle(w http.ResponseWriter, r *http.Request) {
	for _, s := range sinks {
		fmt.Fprint(w, s.Handler(r.URL.Query().Get("input")))
	}
}
```

One way to remedy the problem is to only allow requests to an allow-listed URL:

```go
func httpHandler(payload string) string {
	if payload != "https://example.com/status" {
		return "forbidden"
	}
	resp, _ := http.Get(payload) // GOOD: payload is validated against an allow-list
	defer resp.Body.Close()
	return resp.Status
}
```

## References

- OWASP: [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).
- Common Weakness Enumeration: [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
