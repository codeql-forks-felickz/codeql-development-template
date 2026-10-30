package org.apache.hc.client5.http.ssl;

import java.security.cert.X509Certificate;
import org.apache.hc.core5.ssl.TrustStrategy;

public class TrustSelfSignedStrategy implements TrustStrategy {
    public static final TrustSelfSignedStrategy INSTANCE = new TrustSelfSignedStrategy();
    public boolean isTrusted(X509Certificate[] chain, String authType) { return true; }
}
