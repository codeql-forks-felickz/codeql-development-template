package org.apache.http.ssl;

import java.security.cert.X509Certificate;

public interface TrustStrategy {
    boolean isTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException;
}
