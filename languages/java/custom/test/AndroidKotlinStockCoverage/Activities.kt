package com.example.shop

import android.app.Activity
import android.content.Intent
import android.net.http.SslError
import android.os.Bundle
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient

class NonNullWebViewClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler, error: SslError?) { handler.proceed() } // $ Alert[java/improper-webview-certificate-validation]
}

// Stock FN: the Kotlin safe call `handler?.proceed()` is extracted as a null check plus a call on a
// temporary variable, so it is reported by java/improper-webview-certificate-validation-null-safe instead.
class SafeCallWebViewClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) { handler?.proceed() } // $ MISSING: Alert[java/improper-webview-certificate-validation]
}

// Exported activity that returns the incoming Intent unchanged.
class ResultActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(-1, intent) // $ Alert[java/android/intent-uri-permission-manipulation]
        finish()
    }
}

// Implicitly exported activity that starts an attacker-supplied Intent and loads attacker-supplied URLs.
class WebView2Activity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val extraIntent = intent.getParcelableExtra<Intent>("extra_intent") // $ Source[java/android/intent-redirection]
        if (extraIntent != null) {
            startActivity(extraIntent) // $ Alert[java/android/intent-redirection]
            finish()
            return
        }

        val webview = WebView()
        webview.settings.javaScriptEnabled = true
        webview.settings.allowUniversalAccessFromFileURLs = true // $ Alert[java/android/websettings-file-access]
        if (!intent.dataString.isNullOrBlank()) {
            webview.loadUrl(intent.dataString) // $ Alert[java/android/unsafe-android-webview-fetch]
        } else if (!intent.data?.getQueryParameter("url").isNullOrBlank()) {
            webview.loadUrl(intent.data?.getQueryParameter("url")) // $ Alert[java/android/unsafe-android-webview-fetch]
        } else if (!intent.extras?.getString("url").isNullOrEmpty()) {
            webview.loadUrl(intent.extras?.getString("url")) // $ Alert[java/android/unsafe-android-webview-fetch]
        }
    }
}

// Deep-link activity that loads a URL taken from its data URI.
class WebViewActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webview = WebView()
        webview.settings.javaScriptEnabled = true
        webview.settings.allowUniversalAccessFromFileURLs = true // $ Alert[java/android/websettings-file-access]
        val uri = intent.data
        uri?.let {
            var data: String? = null
            if (uri.path.equals("/web")) {
                data = intent.data?.getQueryParameter("url") // $ Source[java/android/unsafe-android-webview-fetch]
            }
            if (data == null) {
                finish()
            }
            webview.loadUrl(data) // $ Alert[java/android/unsafe-android-webview-fetch]
        }
    }
}

// Safe: not exported, so its Intent is not attacker-controlled.
class PrivateActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webview = WebView()
        webview.settings.javaScriptEnabled = true
        webview.loadUrl(intent.dataString)
        setResult(-1, intent)
    }
}
