# CORS misconfiguration (extended)

Web browsers, by default, disallow cross-origin resource sharing via direct HTTP requests. Still, to satisfy some needs that arose with the growth of the web, an expedient was created to make exceptions possible. CORS (Cross-origin resource sharing) is a mechanism that allows resources of a web endpoint (let's call it _Peer A_) to be accessed from another web page belonging to a different domain (_Peer B_).

For that to happen, _Peer A_ needs to make available its CORS configuration via special headers on the desired endpoint via the OPTIONS method.

This configuration can also allow the inclusion of cookies on the cross-origin request (i.e. when the `Access-Control-Allow-Credentials` header is set to `true`), meaning that _Peer B_ can send a request to _Peer A_ that will include the cookies as if the request was executed by the user.

This query is a variant of the experimental `go/cors-misconfiguration` query. It reports everything that query reports (an `Access-Control-Allow-Origin` value taken from the request, or set to `null`, while credentials are allowed), and additionally reports a policy that allows **any** origin (`*`, `http://*` or `https://*`) when the same policy either:

- allows credentials (`Access-Control-Allow-Credentials: true`, or `AllowCredentials: true`), or
- explicitly allows the state-changing methods `PUT`, `PATCH` or `DELETE`.

Both the `net/http` header form (`w.Header().Set("Access-Control-Allow-Origin", "*")`) and the configuration of the following CORS middleware are covered:

- Echo (`github.com/labstack/echo/middleware` and `github.com/labstack/echo/v4/middleware`): `CORSConfig.AllowOrigins`, `AllowMethods`, `AllowCredentials`
- `github.com/gin-contrib/cors`: `Config.AllowOrigins`, `AllowAllOrigins`, `AllowMethods`, `AllowCredentials`
- `github.com/rs/cors` and `github.com/go-chi/cors`: `Options.AllowedOrigins`, `AllowedMethods`, `AllowCredentials`

A wildcard origin combined with credentials shows that the developer intends any website to read authenticated responses. Depending on the browser and middleware, the origin may be reflected instead of sent as `*`, which makes the misconfiguration directly exploitable. Explicitly allowing `PUT`, `PATCH` or `DELETE` from any origin lets any website send state-changing requests that would otherwise be blocked by the CORS preflight check.

## Recommendation

Only allow a fixed list of trusted origins. Do not combine a wildcard origin with credentials, and only allow the methods that cross-origin clients really need.

## Example

In the following example, every JSON response allows any origin to read it with the user's cookies:

```go
func RenderAsJson(w http.ResponseWriter, data ...interface{}) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	// ...
}
```

In the following example, Echo is configured to allow any origin to send state-changing requests:

```go
e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
	AllowOrigins: []string{"*"},
	AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
}))
```

Instead, allow only trusted origins:

```go
e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
	AllowOrigins: []string{"https://app.example.com"},
	AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
}))
```

## Limitations

- A wildcard origin on its own, or together with only simple methods (`GET`, `HEAD`, `POST`), is not reported, because it is a common and usually intended setting for public, unauthenticated resources.
- Middleware defaults are not reported. For example, Echo's `middleware.CORS()` allows any origin and all methods by default, but is only reported when the origins and methods are set explicitly.
- For middleware configuration, the origins, methods and credentials must be written as literals to the same configuration struct (either in one composite literal or through field writes on the same local variable).
- Unlike `go/cors-misconfiguration`, this query reports `AllowAllOrigins: true` together with `AllowCredentials: true` for `github.com/gin-contrib/cors`.
- As in `go/cors-misconfiguration`, results guarded by a condition on a variable whose name suggests a debug, development or permission check (for example `debugMode` or `allowed`) are not reported.

## References

- Mozilla Developer Network: [CORS, Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin).
- Mozilla Developer Network: [CORS, Access-Control-Allow-Credentials](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials).
- PortSwigger: [Exploiting CORS Misconfigurations for Bitcoins and Bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties).
- Common Weakness Enumeration: [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
- Common Weakness Enumeration: [CWE-346](https://cwe.mitre.org/data/definitions/346.html).
