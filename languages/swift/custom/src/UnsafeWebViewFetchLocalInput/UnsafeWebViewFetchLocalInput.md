# Unsafe WebView fetch of local user input

Building an HTML document from text that the user typed (for example the `text` of a `UITextField`, or the replacement string passed to a `UITextFieldDelegate`) and loading it with `UIWebView.loadHTMLString`, `WKWebView.loadHTMLString` or the `load(_:mimeType:...:baseURL:)` methods lets the input inject markup and script. If the `baseURL` is `nil` or also comes from the input, injected script may also be able to read local data.

The standard `swift/unsafe-webview-fetch` query only considers remote flow sources, so it does not report these cases. This query reports the same sinks when the data comes from local user input.

## Recommendation

HTML-encode user input before adding it to an HTML document, or set it through a safe API (for example, assign it as text content from JavaScript). Always pass a safe `baseURL` such as `about:blank` and prefer `WKWebView` to `UIWebView`.

## Example

The following code loads text typed by the user straight into a WebView without restricting the base URL:

```swift
let webText = "Welcome! \(textField.text ?? "")"
webview.loadHTMLString(webText, baseURL: nil) // BAD
```

Encode the input and use a safe base URL instead:

```swift
let webText = "Welcome! \(htmlEscape(textField.text ?? ""))"
webview.loadHTMLString(webText, baseURL: URL(string: "about:blank")) // GOOD
```

## References

- OWASP: [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- Apple Developer Documentation: [WKWebView.loadHTMLString(_:baseURL:)](https://developer.apple.com/documentation/webkit/wkwebview/1415004-loadhtmlstring).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-95](https://cwe.mitre.org/data/definitions/95.html).
- Common Weakness Enumeration: [CWE-749](https://cwe.mitre.org/data/definitions/749.html).
