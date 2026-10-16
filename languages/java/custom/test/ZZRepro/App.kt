package com.example.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.http.SslError
import android.os.Bundle
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient

class CustomWebViewClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        handler?.proceed()
    }
}

class CustomWebViewClient2 : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler, error: SslError?) {
        handler.proceed()
    }
}

class ResultActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(-1, intent)
        finish()
    }
}

class WebView2Activity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val extraIntent = intent.getParcelableExtra<Intent>("extra_intent")
        if (extraIntent != null) {
            startActivity(extraIntent)
            finish()
            return
        }
        val webview = WebView()
        webview.settings.javaScriptEnabled = true
        webview.settings.allowUniversalAccessFromFileURLs = true
        if (!intent.dataString.isNullOrBlank()) {
            webview.loadUrl(intent.dataString)
        } else if (!intent.data?.getQueryParameter("url").isNullOrBlank()) {
            webview.loadUrl(intent.data?.getQueryParameter("url"))
        }
    }
}

class LoginActivity : Activity() {
    fun onLogin() {
        for (info in packageManager.getInstalledPackages(0)) {
            val packageName = info.packageName
            if (packageName.startsWith("com.exampleplugin")) {
                val packageContext = createPackageContext(packageName, Context.CONTEXT_INCLUDE_CODE or Context.CONTEXT_IGNORE_SECURITY)
                packageContext.classLoader.loadClass("com.exampleplugin.MainInterface")
                    .getMethod("getInstance", Context::class.java).invoke(null, this)
            }
        }
    }
}
