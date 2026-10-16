package com.example.bench;

import javax.net.ssl.SSLContext;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.ssl.SSLContexts;

public class Client4Utils {
    public static SSLConnectionSocketFactory factory() throws Exception {
        SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build(); // $ Alert
        return new SSLConnectionSocketFactory(sslcontext, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER); // $ Alert
    }

    public static SSLConnectionSocketFactory noop(SSLContext sslcontext) {
        return new SSLConnectionSocketFactory(sslcontext, NoopHostnameVerifier.INSTANCE); // $ Alert
    }

    public static SSLConnectionSocketFactory allowAll(SSLContext sslcontext) {
        return new SSLConnectionSocketFactory(sslcontext, new AllowAllHostnameVerifier()); // $ Alert
    }

    // Safe: strict hostname verification.
    public static SSLConnectionSocketFactory strict(SSLContext sslcontext) {
        return new SSLConnectionSocketFactory(sslcontext, SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER);
    }
}
