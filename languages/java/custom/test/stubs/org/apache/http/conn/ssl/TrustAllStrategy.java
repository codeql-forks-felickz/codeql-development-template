package org.apache.http.conn.ssl;

import java.security.cert.X509Certificate;
import org.apache.http.ssl.TrustStrategy;

public class TrustAllStrategy implements TrustStrategy {
    public static final TrustAllStrategy INSTANCE = new TrustAllStrategy();
    public boolean isTrusted(X509Certificate[] chain, String authType) { return true; }
}
