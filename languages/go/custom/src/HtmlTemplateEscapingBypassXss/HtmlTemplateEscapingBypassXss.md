# Cross-site scripting via HTML template escaping bypass (extended)

This query is a variant of the standard `go/html-template-escaping-bypass-xss` query. It reports the same results, and in addition it does not treat tag-name blocklist filters as sanitizers.

The standard query treats every regular-expression replacement whose pattern contains an HTML meta-character as a complete XSS sanitizer. A replacement that only removes specific tags, such as `regexp.MustCompile("<script*>.*</script>").ReplaceAllString(s, "")`, does not neutralize HTML: other tags (`<img src=x onerror=...>`, `<svg onload=...>`), event-handler attributes and case or spacing variants still execute script once the value is wrapped in `template.HTML`. This query does not treat a replacement as a sanitizer when its pattern matches a literal tag name after `<` (see `lib/XssSanitizers.qll`). Replacements that remove every tag or meta-character, such as `<[^>]*>` or `[<>]`, are still sanitizers.

## Recommendation

Do not convert untrusted input to `template.HTML`, `template.JS` or another type that `html/template` does not escape. Pass the plain string to the template, so that it is escaped for its context.

## Example

```go
func removeScriptTag(text string) string {
	filter := regexp.MustCompile("<script*>.*</script>")
	return filter.ReplaceAllString(text, "")
}

func handler(w http.ResponseWriter, r *http.Request) {
	term := removeScriptTag(r.FormValue("term"))
	data := map[string]interface{}{
		// BAD: `<img src=x onerror=alert(1)>` is not removed, and is not escaped
		"term": template.HTML(fmt.Sprintf("<b>%s</b> not found", term)),
	}
	tmpl.ExecuteTemplate(w, "search", data)
}
```

The standard query does not report this example.

## Limitations

A tag-name pattern written with character classes for each letter (for example `<[sS][cC][rR]...`) is still treated as a sanitizer.

## References

- [Go: html/template](https://pkg.go.dev/html/template)
- [OWASP: XSS (Cross Site Scripting) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
