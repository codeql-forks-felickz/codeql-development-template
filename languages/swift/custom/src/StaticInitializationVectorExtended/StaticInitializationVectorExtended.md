# Static initialization vector for encryption (extended)

When you encrypt data with a block cipher mode such as CBC, the initialization vector (IV) must be unique and unpredictable for each encryption. If the IV is a constant, encrypting the same plaintext with the same key always gives the same ciphertext, and an attacker can tell when two messages share a prefix.

The standard `swift/static-initialization-vector` query does not report the following cases, so this query reports them:

- A constant IV passed to the CommonCrypto C API: `CCCrypt`, `CCCryptorCreate`, `CCCryptorCreateWithMode` or `CCCryptorReset`.
- A `nil` IV passed to one of these functions. CommonCrypto then uses an IV of all zero bytes, which is also a constant.
- An IV that comes from the default value of a parameter, for example `func encrypt(..., iv: Data = ...)`. Every caller that omits the argument uses the same IV. This query reports the call that omits the argument, wherever the IV reaches a sink.

Calls that use ECB mode (`kCCOptionECBMode` or `kCCModeECB`) or the RC4 stream cipher (`kCCAlgorithmRC4` or `kCCModeRC4`) are not reported, because they do not use an IV. ECB and RC4 are weaknesses of their own.

## Recommendation

Generate a new random IV for every encryption, for example with `SecRandomCopyBytes`, and store or send it together with the ciphertext. Do not pass `nil` as the IV, and do not give an IV parameter a default value. If you can, use an authenticated encryption API such as CryptoKit's `AES.GCM`, which generates the nonce for you.

## Example

The following code passes `nil` as the IV, so CommonCrypto uses an IV of all zero bytes:

```swift
CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
        keyBytes, keyLength,
        nil, // BAD: all-zero IV
        dataBytes, dataLength, cryptBytes, cryptLength, &numBytesEncrypted)
```

The following code gives the IV parameter a constant default value, so every call that omits `ivData` uses the same IV:

```swift
extension Data {
    func aes(keyData: Data, ivData: Data = "abcdefghijklmnop".data(using: .utf8)!) -> Data {
        // ... passes ivData to CCCrypt ...
    }
}

let ciphertext = plaintext.aes(keyData: key) // BAD: uses the default IV
```

Instead, generate a random IV for each encryption:

```swift
var iv = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
guard SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv) == errSecSuccess else { return nil }
let ciphertext = plaintext.aes(keyData: key, ivData: Data(iv)) // GOOD
```

## Limitations

The CodeQL Swift extractor does not record the default value of a parameter, so the query cannot tell whether a default IV is a constant or is generated at random. A default value such as `iv: Data = randomIV()` is reported too.

## References

- Wikipedia: [Initialization vector](https://en.wikipedia.org/wiki/Initialization_vector).
- Apple Developer Documentation: [SecRandomCopyBytes(_:_:\_:)](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes).
- Common Weakness Enumeration: [CWE-329](https://cwe.mitre.org/data/definitions/329.html).
- Common Weakness Enumeration: [CWE-1204](https://cwe.mitre.org/data/definitions/1204.html).
