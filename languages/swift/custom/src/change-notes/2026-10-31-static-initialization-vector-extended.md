---
category: newQuery
---

- Added a custom `swift/custom/static-initialization-vector-extended` query that extends `swift/static-initialization-vector`. It reports constant IVs passed to the CommonCrypto functions `CCCrypt`, `CCCryptorCreate`, `CCCryptorCreateWithMode` and `CCCryptorReset`, `nil` IVs passed to these functions (CommonCrypto then uses an all-zero IV), and IVs that come from a default parameter value. Calls in ECB mode or with the RC4 stream cipher, which ignore the IV, are not reported. Results that the standard query already reports are not repeated.
