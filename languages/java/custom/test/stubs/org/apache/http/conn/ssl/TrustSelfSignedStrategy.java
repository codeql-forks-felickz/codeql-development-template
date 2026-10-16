package org.apache.http.conn.ssl;

import java.security.cert.X509Certificate;
import org.apache.http.ssl.TrustStrategy;

public class TrustSelfSignedStrategy implements TrustStrategy {
    public static final TrustSelfSignedStrategy INSTANCE = new TrustSelfSignedStrategy();
    public boolean isTrusted(X509Certificate[] chain, String authType) { return true; }
}
