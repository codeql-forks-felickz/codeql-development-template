# Credential and sensitive data exposure in an iOS application

iOS applications often handle credentials, secrets and private information. Several common coding patterns expose that data to other applications, to the file system or to anyone with brief physical access to the device. This query (`swift/credential-and-data-exposure`) reports the following patterns:

| Pattern                                | CWE     | What is reported                                                                                                                                                                                                                   |
| -------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sensitive data on the pasteboard       | CWE-200 | A sensitive or decrypted value is written to `UIPasteboard` (`string`, `items`, `setValue(_:forPasteboardType:)`, `addItems(_:)`, `setItems(_:options:)`, ...) without the `.localOnly` or `.expirationDate` options.              |
| Credential-derived session token       | CWE-522 | A password flows into an `encrypt` function whose result is stored in a variable or property named like a token, session or cookie.                                                                                                |
| Missing background snapshot protection | CWE-200 | A `UIApplicationDelegate` does not implement `applicationDidEnterBackground(_:)` or `applicationWillResignActive(_:)` (and the app has no scene or notification based equivalent) although the app declares sensitive text inputs. |
| Weak keychain accessibility            | CWE-922 | `SecItemAdd` is called in a file that never sets `kSecAttrAccessible`/`kSecAttrAccessControl`, or an item uses `kSecAttrAccessibleAlways`/`kSecAttrAccessibleAlwaysThisDeviceOnly`.                                                |
| Sensitive response caching             | CWE-922 | A request uses `.returnCacheDataElseLoad` or `.returnCacheDataDontLoad` in a function that handles sensitive data.                                                                                                                 |
| Sensitive data retained in memory      | CWE-316 | A sensitive value is assigned to a `String`/`Data` property of a class, and that property is never cleared.                                                                                                                        |

All patterns are heuristic, so the query has `low` precision and is intended for security audits and community packs.

## Recommendation

- Copy secrets to the pasteboard only with `setItems(_:options:)` and the `.localOnly` and `.expirationDate` options, or avoid copying them at all.
- Use random, server-issued session tokens. Never derive a token from the user's credentials, even with encryption.
- Obscure or clear sensitive views in `applicationDidEnterBackground(_:)`/`applicationWillResignActive(_:)` (or the scene delegate equivalents) so that the system snapshot does not capture them.
- Always set a restrictive `kSecAttrAccessible` value, such as `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, when adding keychain items.
- Use `.reloadIgnoringLocalCacheData` (or an ephemeral `URLSession`) for requests that return sensitive data.
- Clear properties that hold sensitive values as soon as they are no longer needed.

## Example

The following code copies a decrypted secret to the general pasteboard, where any application can read it:

```swift
@IBAction func copyValue(_ sender: AnyObject) {
  UIPasteboard.general.string = self.decryptedValue // BAD
}
```

Instead, restrict the item to the local device and let it expire:

```swift
@IBAction func copyValue(_ sender: AnyObject) {
  UIPasteboard.general.setItems(
    [[UIPasteboard.typeAutomatic: self.decryptedValue]],
    options: [.localOnly: true, .expirationDate: Date(timeIntervalSinceNow: 60)]) // GOOD
}
```

The following code builds a session token by encrypting the user's email address and password:

```swift
let userData = "\(info.email):\(info.password)"
let token = Crypto.encrypt(userData) // BAD
```

## References

- OWASP MASVS: [MASVS-STORAGE](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/).
- Apple: [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility).
- Apple: [UIPasteboard.OptionsKey](https://developer.apple.com/documentation/uikit/uipasteboard/optionskey).
- Common Weakness Enumeration: [CWE-200](https://cwe.mitre.org/data/definitions/200.html).
- Common Weakness Enumeration: [CWE-316](https://cwe.mitre.org/data/definitions/316.html).
- Common Weakness Enumeration: [CWE-522](https://cwe.mitre.org/data/definitions/522.html).
- Common Weakness Enumeration: [CWE-922](https://cwe.mitre.org/data/definitions/922.html).
