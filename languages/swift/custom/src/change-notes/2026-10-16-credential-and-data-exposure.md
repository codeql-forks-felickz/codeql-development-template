---
category: minorAnalysis
---

- Added custom Swift queries and models for credential and data exposure: CommonCrypto (`CCCrypt`, `CCCryptorCreate`, `CCCryptorCreateWithMode`) hard-coded key and static IV sinks, request model struct taint for cleartext transmission, Core Data `insertNewObject` property writes for cleartext database storage, a new `swift/custom/base64-as-encryption` query and a new `swift/custom/request-headers-untrusted-url` query.
