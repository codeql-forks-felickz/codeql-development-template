# Sensitive cookie without HttpOnly

Session-management libraries such as `github.com/gorilla/sessions` and `github.com/gin-contrib/sessions` store the session identifier (or the whole session) in a cookie whose attributes are configured through an `Options` struct. If the `HttpOnly` option is explicitly set to `false`, client-side scripts can read the session cookie through `document.cookie`.

This query also reports sensitive cookies written through `net/http` or Echo when `HttpOnly` is omitted or explicitly set to `false`. Sensitive cookie names include names containing `session`, `login`, `token`, `user`, `auth` or `credential`, plus the exact names `Level` and `Uid`.

## Recommendation

Set `HttpOnly: true` on sensitive cookie options (and `Secure: true` when the application is served over HTTPS).

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

For Gorilla and Gin session options, only an `HttpOnly` value that flows from the constant `false` is reported; omitted fields and values from configuration are not reported. For `net/http` and Echo cookie writes, only cookie names matching the patterns above are reported. This query does not check the `Secure` or `SameSite` attributes.

## References

- OWASP: [HttpOnly](https://owasp.org/www-community/HttpOnly).
- gorilla/sessions: [Options](https://pkg.go.dev/github.com/gorilla/sessions#Options).
- Common Weakness Enumeration: [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html).
