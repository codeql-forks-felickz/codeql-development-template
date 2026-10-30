package org.apache.http.ssl;

import javax.net.ssl.SSLContext;
import java.security.KeyStore;

public class SSLContextBuilder {
    public SSLContextBuilder loadTrustMaterial(KeyStore truststore, TrustStrategy trustStrategy) { return this; }
    public SSLContext build() { return null; }
}
