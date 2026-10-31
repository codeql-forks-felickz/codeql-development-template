# Fixed crypto key length may exceed the key buffer

CommonCrypto's `CCCrypt` reads the number of key bytes supplied as its key-length argument. Passing a caller-supplied `Data` buffer with a fixed AES-128 key length can read past the end when the buffer contains fewer than 16 bytes.

## Recommendation

Validate that the key buffer contains at least the number of bytes passed to `CCCrypt`, or derive the length from the same buffer.

## Example

```swift
func encrypt(keyData: Data) {
    let keyLength = size_t(kCCKeySizeAES128)
    keyData.withUnsafeBytes { keyBytes in
        // BAD: `keyData` may contain fewer than 16 bytes.
        CCCrypt(operation, algorithm, options, keyBytes, keyLength, ...)
    }
}
```

Check the buffer before passing its pointer:

```swift
func encrypt(keyData: Data) {
    guard keyData.count >= kCCKeySizeAES128 else { return }
    let keyLength = size_t(kCCKeySizeAES128)
    keyData.withUnsafeBytes { keyBytes in
        CCCrypt(operation, algorithm, options, keyBytes, keyLength, ...)
    }
}
```

## Known limitations

The query recognizes direct `CCCrypt` calls using a caller-supplied `Data`/`NSData` key or a `Data` value created from a `String` parameter. It recognizes the fixed `kCCKeySizeAES128` value and dominating comparisons with that key buffer's `count` on the left-hand side. Key buffers passed through other wrappers, aliases, or APIs are not analyzed.

## References

- Common Weakness Enumeration: [CWE-125](https://cwe.mitre.org/data/definitions/125.html).
- Common Weakness Enumeration: [CWE-823](https://cwe.mitre.org/data/definitions/823.html).
