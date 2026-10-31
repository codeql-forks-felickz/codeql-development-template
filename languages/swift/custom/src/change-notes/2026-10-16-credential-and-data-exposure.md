---
category: minorAnalysis
---

- Added custom Swift queries and models for credential and data exposure: CommonCrypto (`CCCrypt`, `CCCryptorCreate`, `CCCryptorCreateWithMode`) hard-coded key and static IV sinks, request model struct taint for cleartext transmission, Core Data `insertNewObject` and Objective-C Realm (`RLMObject`) writes plus sensitive `UserDefaults` token/PIN values for cleartext storage (including hard-coded values written to sensitively named properties), sensitive UI inputs and `http://` request bodies for cleartext transmission, a `swift/custom/cleartext-logging` variant that treats abbreviated sensitive UI inputs and plaintext values in encryption/decryption functions as sources, a new `swift/custom/base64-as-encryption` query, a new `swift/custom/encryption-key-from-cleartext-http` query and a new `swift/custom/request-headers-untrusted-url` query.
