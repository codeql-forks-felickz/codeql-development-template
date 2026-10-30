# Apache HttpClient TLS validation disabled

Apache HttpClient 4.x and 5.x ship helpers that switch off parts of TLS validation:

- `NoopHostnameVerifier` and `AllowAllHostnameVerifier` (also exposed as
  `SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER`) accept a certificate for any host name.
- `TrustAllStrategy` trusts every certificate chain.
- `TrustSelfSignedStrategy` trusts any self-signed certificate, which an attacker can create for any
  host.

A `TrustStrategy` lambda or class whose `isTrusted` always returns `true` has the same effect as
`TrustAllStrategy`. With any of these, an attacker who can intercept the connection can present
their own certificate and read or change the traffic.

The standard queries `java/unsafe-hostname-verification` and `java/insecure-trustmanager` only
model `HostnameVerifier` and `X509TrustManager` implementations in the analyzed source, so they do
not report the Apache HttpClient classes or `TrustStrategy` implementations.

## Recommendation

Use the default hostname verifier and trust material. If a private certificate authority or a
self-signed server certificate must be trusted, load that specific certificate into a trust store
and pass it to `loadTrustMaterial`.

## Example

The following factory trusts any self-signed certificate and skips hostname verification:

```java
SSLContext sslcontext =
        SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
SSLConnectionSocketFactory sslsf =
        new SSLConnectionSocketFactory(
                sslcontext, new String[] {"TLSv1.3"}, null, NoopHostnameVerifier.INSTANCE);
```

The following factory trusts only the certificates in a dedicated trust store and verifies host
names:

```java
SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(trustStore, null).build();
SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
```

## References

- Apache HttpClient: [NoopHostnameVerifier](https://hc.apache.org/httpcomponents-client-5.4.x/current/httpclient5/apidocs/org/apache/hc/client5/http/ssl/NoopHostnameVerifier.html).
- OWASP: [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-295](https://cwe.mitre.org/data/definitions/295.html).
- Common Weakness Enumeration: [CWE-297](https://cwe.mitre.org/data/definitions/297.html).
