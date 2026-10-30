package org.apache.hc.client5.http.ssl;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

public class SSLConnectionSocketFactory {

    public SSLConnectionSocketFactory(SSLContext sslContext, HostnameVerifier hostnameVerifier) { }
    public SSLConnectionSocketFactory(SSLContext sslContext, String[] supportedProtocols, String[] supportedCipherSuites, HostnameVerifier hostnameVerifier) { }
}
