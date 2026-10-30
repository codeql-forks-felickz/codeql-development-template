package com.example.shop;

import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class JavaWebViewClients {
    static class GuardedClient extends WebViewClient {
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            if (handler != null) {
                handler.proceed(); // $ Alert
            }
        }
    }

    static class EarlyReturnClient extends WebViewClient {
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            if (handler == null) {
                return;
            }
            handler.proceed(); // $ Alert
        }
    }

    static class UnconditionalClient extends WebViewClient {
        // Reported by java/improper-webview-certificate-validation, not by this query.
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.proceed();
        }
    }

    static class CheckedClient extends WebViewClient {
        private boolean trusted;

        // Safe: proceeds only when an additional check passes.
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            if (handler != null && trusted) {
                handler.proceed();
            } else if (handler != null) {
                handler.cancel();
            }
        }
    }
}
