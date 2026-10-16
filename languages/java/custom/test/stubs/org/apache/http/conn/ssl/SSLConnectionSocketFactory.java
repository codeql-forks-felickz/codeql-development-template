package org.apache.http.conn.ssl;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

public class SSLConnectionSocketFactory {
    public static final X509HostnameVerifier ALLOW_ALL_HOSTNAME_VERIFIER = AllowAllHostnameVerifier.INSTANCE;
    public static final X509HostnameVerifier STRICT_HOSTNAME_VERIFIER = null;
    public SSLConnectionSocketFactory(SSLContext sslContext, HostnameVerifier hostnameVerifier) { }
    public SSLConnectionSocketFactory(SSLContext sslContext, String[] supportedProtocols, String[] supportedCipherSuites, HostnameVerifier hostnameVerifier) { }
}
