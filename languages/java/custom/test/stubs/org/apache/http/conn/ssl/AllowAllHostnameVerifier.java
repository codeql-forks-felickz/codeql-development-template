package org.apache.http.conn.ssl;

import javax.net.ssl.SSLSession;

public class AllowAllHostnameVerifier implements X509HostnameVerifier {
    public static final AllowAllHostnameVerifier INSTANCE = new AllowAllHostnameVerifier();
    public boolean verify(String hostname, SSLSession session) { return true; }
}
