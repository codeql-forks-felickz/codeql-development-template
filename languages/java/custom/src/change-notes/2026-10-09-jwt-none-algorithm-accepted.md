---
category: newQuery
---
* Added a new query, `java/jwt-none-algorithm-accepted`, to detect JWT validators that read the `alg` value from the attacker-controlled token header and return `true` (valid) when it is `none`, without verifying a signature. This complements `java/missing-jwt-signature-check`, which only covers JJWT `JwtParser` usage.
