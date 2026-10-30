# Encryption key derived from a device identifier

Encryption keys must be generated from cryptographically secure random data. Device identifiers such as `UIDevice.current.identifierForVendor` and `ASIdentifierManager.shared().advertisingIdentifier` are identifiers, not secrets: they are predictable, shared by every app from the same vendor (or with every advertiser), and readable by any code running on the device. Using such a value, or a string derived from it, as an encryption key (for example a SQLCipher `PRAGMA key`, `sqlite3_key`, a Realm `encryptionKey`, or a CryptoSwift `AES(key:)`) means that anyone who can obtain the identifier can decrypt the protected data.

## Recommendation

Generate key material with a cryptographically secure random number generator such as `SecRandomCopyBytes` or CryptoKit's `SymmetricKey(size:)`, and store the generated key in the Keychain. Do not derive keys from device identifiers or other non-secret values.

## Example

The following example uses the vendor identifier as the SQLCipher database key:

```swift
let deviceID = UIDevice.current.identifierForVendor?.uuidString
let encryptStmt = "PRAGMA key = '\(deviceID ?? "")'"
sqlite3_exec(db, encryptStmt, nil, nil, nil) // BAD
```

Instead, generate a random key once, keep it in the Keychain, and use it to open the database:

```swift
var key = [UInt8](repeating: 0, count: 32)
guard SecRandomCopyBytes(kSecRandomDefault, key.count, &key) == errSecSuccess else { return }
// store `key` in the Keychain, then:
sqlite3_key(db, key, Int32(key.count)) // GOOD
```

## References

- MITRE: [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html).
- MITRE: [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html).
- Apple Developer Documentation: [identifierForVendor](https://developer.apple.com/documentation/uikit/uidevice/identifierforvendor).
- Apple Developer Documentation: [SecRandomCopyBytes](<https://developer.apple.com/documentation/security/secrandomcopybytes(_:_:_:_:)>).
- OWASP MASVS: [MASVS-CRYPTO-2](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/).
