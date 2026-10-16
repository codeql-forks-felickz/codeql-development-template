# Session cookie configured with HttpOnly disabled

Session-management libraries such as `github.com/gorilla/sessions` and `github.com/gin-contrib/sessions` store the session identifier (or the whole session) in a cookie whose attributes are configured through an `Options` struct. If the `HttpOnly` option is explicitly set to `false`, client-side scripts can read the session cookie through `document.cookie`. Any cross-site scripting (XSS) flaw in the application can then be used to steal the cookie and hijack the user's session.

The stock `go/cookie-httponly-not-set` query only models cookies written through `net/http` and Gin, so it does not report session cookies configured through these libraries.

## Recommendation

Set `HttpOnly: true` on session cookie options (and `Secure: true` when the application is served over HTTPS).

## Example

The following example disables `HttpOnly` on the authenticated session cookie:

```go
session.Options = &sessions.Options{
	Path:     "/",
	MaxAge:   3600,
	HttpOnly: false, // BAD
}
```

The cookie should instead be configured as follows:

```go
session.Options = &sessions.Options{
	Path:     "/",
	MaxAge:   3600,
	HttpOnly: true, // GOOD
	Secure:   true,
}
```

## Limitations

Only options whose `HttpOnly` field is explicitly assigned a constant `false` (directly, through a named constant, or through a local variable) are reported. Options literals that omit `HttpOnly`, and values read from configuration, are not reported.

## References

- OWASP: [HttpOnly](https://owasp.org/www-community/HttpOnly).
- gorilla/sessions: [Options](https://pkg.go.dev/github.com/gorilla/sessions#Options).
- Common Weakness Enumeration: [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html).
