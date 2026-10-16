# Android `WebView` that accepts all certificates behind a null check

`WebViewClient.onReceivedSslError` is called when a `WebView` encounters an invalid TLS certificate.
Calling `SslErrorHandler.proceed()` continues loading the page anyway, so an attacker who can
intercept the connection can serve content and steal data with any certificate.

The standard query `java/improper-webview-certificate-validation` reports handlers that call
`handler.proceed()` unconditionally. In Kotlin, the parameter is usually declared as
`SslErrorHandler?` and the call is written as `handler?.proceed()` (or `handler!!.proceed()`). The Kotlin
extractor turns a safe call into a null check followed by a conditional call on a temporary
variable, and a non-null assertion wraps the handler in an extra expression, so neither matches
the standard query. Java code sometimes adds an equivalent `if (handler != null)` guard. None of
these forms validates the certificate. This query reports these
null-guarded calls that are otherwise unconditional, and does not report handlers already reported
by the standard query.

## Recommendation

Do not override `onReceivedSslError` to call `proceed()`. Let the default implementation cancel the
load, or call `handler.cancel()`. If a custom certificate must be trusted, use a network security
configuration instead.

## Example

The following Kotlin handler accepts every certificate:

```kotlin
class CustomWebViewClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        handler?.proceed()
    }
}
```

The following handler rejects invalid certificates:

```kotlin
class SafeWebViewClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        handler?.cancel()
    }
}
```

## References

- Android Developers: [WebViewClient.onReceivedSslError](https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)).
- Android Developers: [Unsafe handling of SSL errors in WebView](https://developer.android.com/privacy-and-security/risks/unsafe-ssl-error-handling).
- Common Weakness Enumeration: [CWE-295](https://cwe.mitre.org/data/definitions/295.html).
