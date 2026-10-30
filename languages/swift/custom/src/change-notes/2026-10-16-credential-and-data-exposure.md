---
category: minorAnalysis
---

- Added custom Swift queries and models for credential and data exposure: CommonCrypto (`CCCrypt`, `CCCryptorCreate`, `CCCryptorCreateWithMode`) hard-coded key and static IV sinks, request model struct taint for cleartext transmission, Core Data `insertNewObject` property writes and Objective-C Realm (`RLMObject`) writes for cleartext database storage (including hard-coded values written to sensitively named properties), sensitive UI inputs and `http://` request bodies for cleartext transmission, a new `swift/custom/base64-as-encryption` query, a new `swift/custom/encryption-key-from-cleartext-http` query and a new `swift/custom/request-headers-untrusted-url` query.
