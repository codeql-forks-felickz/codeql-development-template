package com.example

import android.app.Activity
import android.os.Bundle
import android.webkit.WebView
import android.widget.Button
import android.widget.EditText

class WebViewUrlActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val loadButton = findViewById<Button>(1)
        val webView = findViewById<WebView>(2)
        val urlEditText = findViewById<EditText>(3)

        loadButton.setOnClickListener {
            val webViewSettings = webView.settings
            webViewSettings.javaScriptEnabled = true
            webViewSettings.allowFileAccess = true
            webViewSettings.allowContentAccess = true
            webViewSettings.allowFileAccessFromFileURLs = true
            webViewSettings.allowUniversalAccessFromFileURLs = true
            val url = urlEditText.text.toString() // $ Source
            webView.loadUrl(url) // $ Alert
        }
    }

    fun loadFromEditText(webView: WebView, urlEditText: EditText) {
        webView.settings.javaScriptEnabled = true
        webView.loadUrl(urlEditText.text.toString()) // $ Alert
    }

    // Already reported by `java/android/unsafe-android-webview-fetch`: no `toString()` involved.
    fun loadFromIntent(webView: WebView) {
        webView.settings.javaScriptEnabled = true
        webView.loadUrl(intent.getStringExtra("url")!!)
    }

    // JavaScript is not enabled on this WebView.
    fun loadWithoutJavaScript(webView: WebView, urlEditText: EditText) {
        webView.loadUrl(urlEditText.text.toString())
    }

    // The URL is not user-controlled.
    fun loadConstant(webView: WebView, other: Any) {
        webView.settings.javaScriptEnabled = true
        webView.loadUrl("https://example.com/" + other.toString())
    }
}
