# Reflected cross-site scripting (extended)

This query is a variant of the standard `go/reflected-xss` query. It reports the same results, and in addition:

1. **Tag-name blocklist filters are not sanitizers.** The standard query treats every regular-expression replacement whose pattern contains an HTML meta-character as a complete XSS sanitizer. A replacement that only removes specific tags, such as `regexp.MustCompile("<script*>.*</script>").ReplaceAllString(s, "")`, does not neutralize HTML: other tags (`<img src=x onerror=...>`, `<svg onload=...>`), event-handler attributes and case or spacing variants still execute script. This query does not treat a replacement as a sanitizer when its pattern matches a literal tag name after `<` (see `lib/XssSanitizers.qll`). Replacements that remove every tag or meta-character, such as `<[^>]*>` or `[<>]`, are still sanitizers.
2. **Calls through function-typed struct fields.** A vulnerable function stored in a struct field (for example `Sink{VulnerableFnWrapper: func(_ interface{}, payload string) (string, bool, error) { return payload, true, nil }}`) and later called as `s.VulnerableFnWrapper(opaque, payload)` has no resolved callee in the standard call graph, so taint passed to it is lost. This query follows such calls with the field-based approximation in `lib/FunctionFieldCallTaintStep.qll`.
3. **Content types that may be HTML.** The standard query ignores a response body whenever its content type is set from a value that is not a constant, such as `w.Header().Set("Content-Type", mime)`. This query also reports such a response body when a string constant naming an HTML MIME type (for example `RawMime: "text/html"`) may reach that content type (see `lib/DynamicHtmlContentType.qll`).

## Recommendation

Escape untrusted input before writing it to an HTML response, for example with `html.EscapeString`, or render it with `html/template`. Do not rely on removing a fixed list of tags.

## Example

```go
func removeScriptTag(text string) string {
	filter := regexp.MustCompile("<script*>.*</script>")
	return filter.ReplaceAllString(text, "")
}

func handler(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q")
	// BAD: `<img src=x onerror=alert(1)>` is not removed
	w.Write([]byte(removeScriptTag(in)))
}
```

```go
sinks := []*common.Sink{{
	Name: "reflectedXss",
	VulnerableFnWrapper: func(_ interface{}, payload string) (string, bool, error) {
		return payload, true, nil
	},
	RawMime: "text/html",
}}

// in the driver:
data, mime, status := s.Handler(common.Unsafe, common.GetUserInput(r), w)
w.WriteHeader(status)
w.Header().Set("Content-Type", mime)
// BAD: the payload is written verbatim with a `text/html` content type
fmt.Fprint(w, data)
```

The standard query reports neither example.

## Limitations

- Field accesses and calls through function-typed fields are approximated field-based, not context sensitive. If one registry field holds an HTML content type for one entry, every response whose content type is read from that field is considered HTML.
- A tag-name pattern written with character classes for each letter (for example `<[sS][cC][rR]...`) is still treated as a sanitizer.

## References

- [OWASP: XSS (Cross Site Scripting) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
