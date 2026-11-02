# Open URL redirect (extended call graph)

This query is a variant of the standard `go/unvalidated-url-redirection` query. It reports the same results, and in addition:

1. **Calls through function-typed struct fields.** The standard Go data-flow library resolves a call through a function value only when that value reaches the call by local flow; it has no general lambda-flow support. A common framework-agnostic pattern stores the vulnerable function in a struct field (for example `Sink{VulnerableFnWrapper: func(opaque interface{}, payload string) {...}}`) and invokes it later as `s.VulnerableFnWrapper(opaque, payload)`, possibly through another stored function (`s.Handler, err = GenericHandler(s)`). Such calls have no resolved callee, so untrusted data passed to them was lost. This query resolves them with a field-based approximation (see `lib/FunctionFieldCallTaintStep.qll`): argument `i` of a call through field `f` flows to parameter `i` of every function value that is written to `f`, and the results of those functions flow back to the call's results.
2. **gin `Context.Redirect`.** The `languages-go-custom-models` model pack adds `github.com/gin-gonic/gin.Context.Redirect` (argument 1) as a `url-redirection` sink.
3. **Safe request-URL suppression per source.** The standard query drops every result whose sink is also reached by a safe part of the request URL (such as `r.URL.Path`), even when other untrusted values reach the same sink. This query only drops a result when the safe-URL flow starts at that result's own source, so input helpers that fall back to a path element no longer hide untrusted query, form, cookie or header values.

## Recommendation

Do not redirect to a URL taken from untrusted input without validating it. Redirect only to known-good, same-origin paths, or check the target against an allow-list of trusted destinations.

## Example

```go
var redirectSink = Sink{
	VulnerableFnWrapper: func(opaque interface{}, payload string) (string, bool, error) {
		p := opaque.(httpHandlerPair)
		// BAD: payload is the unvalidated request input
		http.Redirect(p.ResponseWriter, p.Request, payload, http.StatusFound)
		return "", true, nil
	},
}

func handler(w http.ResponseWriter, r *http.Request) {
	for _, s := range sinks {
		s.Handler(Unsafe, GetUserInput(r), httpHandlerPair{w, r})
	}
}
```

The standard query does not report this redirect because neither `s.Handler(...)` nor `s.VulnerableFnWrapper(...)` has a resolved callee. This query reports it.

## Limitations

The field-based call graph is not context sensitive: every function value written to a field is a possible callee of every call through that field. If several sinks share one registry field, untrusted data that reaches one call through the field is considered to reach all functions stored in it. Only calls that the standard library cannot resolve are affected.

## References

- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP: Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
