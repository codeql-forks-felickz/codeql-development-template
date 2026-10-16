# Certificate validation callback accepts any certificate

.NET lets applications override TLS server certificate validation with a callback, such as `ServicePointManager.ServerCertificateValidationCallback`, `HttpClientHandler.ServerCertificateCustomValidationCallback`, `SslClientAuthenticationOptions.RemoteCertificateValidationCallback`, or a `RemoteCertificateValidationCallback` passed to `SslStream`. A callback that always returns `true`, or `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`, accepts every certificate. That includes expired, self-signed and attacker-issued certificates. An attacker who can intercept the traffic can then impersonate the server and read or modify the data exchanged.

This query reports callbacks that unconditionally return `true` when they are used as a certificate validation callback.

## Recommendation

Do not override certificate validation. If a custom callback is needed, reject the certificate unless `sslPolicyErrors` is `SslPolicyErrors.None`, or validate it explicitly (for example by pinning the expected certificate).

## Example

In the following example, the first callback accepts any certificate. The second one only accepts certificates that the platform validated successfully.

```csharp
// BAD: every certificate is accepted.
ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

// GOOD: only certificates without validation errors are accepted.
ServicePointManager.ServerCertificateValidationCallback =
    (sender, certificate, chain, sslPolicyErrors) => sslPolicyErrors == SslPolicyErrors.None;
```

## References

- Microsoft Learn: [ServicePointManager.ServerCertificateValidationCallback](https://learn.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager.servercertificatevalidationcallback).
- Microsoft Learn: [CA5359: Do not disable certificate validation](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca5359).
- Common Weakness Enumeration: [CWE-295](https://cwe.mitre.org/data/definitions/295.html).
