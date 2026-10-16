package org.apache.hc.core5.ssl;

import java.security.cert.X509Certificate;

public interface TrustStrategy {
    boolean isTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException;
}
