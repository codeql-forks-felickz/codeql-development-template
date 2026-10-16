package com.example.shop

import android.net.http.SslError
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient

class CustomWebViewClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        handler?.proceed() // $ Alert
    }
}

class LoggingWebViewClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        println("ignoring SSL error")
        handler?.proceed() // $ Alert
    }
}

class AssertedWebViewClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        handler!!.proceed() // $ Alert
    }
}

class NonNullWebViewClient : WebViewClient() {
    // Reported by java/improper-webview-certificate-validation, not by this query.
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler, error: SslError?) {
        handler.proceed()
    }
}

class CancellingWebViewClient : WebViewClient() {
    // Safe: the load is cancelled.
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        handler?.cancel()
    }
}

class ConditionalWebViewClient : WebViewClient() {
    // Safe: only proceeds for a specific, checked condition.
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        if (error?.primaryError == 3) {
            handler?.proceed()
        } else {
            handler?.cancel()
        }
    }
}
