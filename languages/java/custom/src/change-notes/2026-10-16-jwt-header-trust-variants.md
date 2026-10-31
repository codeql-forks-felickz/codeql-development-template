---
category: newQuery
---
* Added a new query, `java/jwt-header-embedded-key-trusted`, to detect Nimbus JWT signature verifiers built from the public key in the token's own attacker-controlled `jwk` header.
* Added a new query, `java/jwt-none-algorithm-used`, to detect Auth0 `Algorithm.none()` being used to sign tokens or to build a verifier, which produces or accepts unsigned tokens.
