---
category: newQuery
---

- Added a custom `swift/custom/unsafe-webview-fetch-local-input` query that complements `swift/unsafe-webview-fetch` by reporting local user input (such as `UITextField.text` or `UITextFieldDelegate` replacement strings) that is loaded into a `UIWebView` or `WKWebView` without a safe base URL. The standard query only considers remote flow sources, and Swift has no threat-model setting to enable local sources.
