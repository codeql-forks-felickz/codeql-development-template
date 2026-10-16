package com.example.bench;

import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.ssl.TrustStrategy;

public class Client5Utils {
    // BenchmarkJava pattern.
    public static SSLConnectionSocketFactory getSSLFactory() throws Exception {
        SSLContext sslcontext =
                SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build(); // $ Alert
        return new SSLConnectionSocketFactory(
                sslcontext, new String[] {"TLSv1"}, null, NoopHostnameVerifier.INSTANCE); // $ Alert
    }

    public static SSLConnectionSocketFactory trustAll() throws Exception {
        SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build(); // $ Alert
        return new SSLConnectionSocketFactory(sslcontext, new NoopHostnameVerifier()); // $ Alert
    }

    public static SSLContext lambda() throws Exception {
        return SSLContexts.custom().loadTrustMaterial(null, (chain, authType) -> true).build(); // $ Alert
    }

    public static SSLContext lambdaBlock() throws Exception {
        return SSLContexts.custom().loadTrustMaterial(null, (chain, authType) -> { return true; }).build(); // $ Alert
    }

    static class AcceptAll implements TrustStrategy {
        public boolean isTrusted(java.security.cert.X509Certificate[] chain, String authType) { return true; }
    }

    public static SSLContext custom() throws Exception {
        return SSLContexts.custom().loadTrustMaterial(null, new AcceptAll()).build(); // $ Alert
    }

    // Safe: the default trust material and hostname verifier.
    public static SSLConnectionSocketFactory safe(javax.net.ssl.HostnameVerifier verifier) throws Exception {
        SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, null).build();
        return new SSLConnectionSocketFactory(sslcontext, verifier);
    }

    // Safe: the strategy checks the chain.
    public static SSLContext pinned() throws Exception {
        return SSLContexts.custom().loadTrustMaterial(null, (chain, authType) -> chain.length > 1).build();
    }

    static class Pinned implements TrustStrategy {
        public boolean isTrusted(java.security.cert.X509Certificate[] chain, String authType) {
            if (chain.length == 0) {
                return false;
            }
            return true;
        }
    }

    public static SSLContext pinnedClass() throws Exception {
        return SSLContexts.custom().loadTrustMaterial(null, new Pinned()).build();
    }
}
