---
category: minorAnalysis
---
* Added models for auth0 `java-jwt` (`JWT.decode` and header/claim accessors propagate taint, since decoding does not verify the signature) and `jwks-rsa` (`JwkProviderBuilder` and `UrlJwkProvider` constructors are `request-forgery` sinks). `java/ssrf` now reports an unverified JWT `jku` header or `iss` claim used as the JWKS location (CWE-918, CWE-345).
