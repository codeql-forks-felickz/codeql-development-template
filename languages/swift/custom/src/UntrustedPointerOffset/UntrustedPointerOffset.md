# Unsafe pointer access with user-controlled offset

Swift's unsafe pointer types (`UnsafePointer`, `UnsafeMutablePointer`, `UnsafeRawPointer`, `UnsafeMutableRawPointer` and their buffer counterparts) do not check that an offset, index or length stays inside the memory region they point to. Release builds also skip the debug-only checks on buffer pointer subscripts.

If a value from an untrusted source is used for pointer arithmetic, as a subscript index, as a byte offset, or as the byte count for an API that reads from a raw pointer, and the code doesn't check it against both bounds of the buffer, an attacker can read or write memory outside the buffer. This can disclose sensitive memory, corrupt data or crash the application. Negative offsets are dangerous too, because Swift's `Int` is signed: they reach memory before the start of the buffer.

## Recommendation

Avoid unsafe pointers where possible. Use safe collection APIs such as `Data.subdata(in:)`, `Array` slicing or `dropFirst(_:)`, which check their bounds.

If you must use unsafe pointers, check every untrusted offset, index or length against both the lower bound (usually `0`) and the upper bound (the size of the buffer) before you use it.

## Example

In the following example, a deep-link handler reads an `offset` query parameter from the URL and uses it directly in pointer arithmetic and to compute a byte count. A negative offset reads memory before the decoded data, and an offset larger than the data produces an invalid count:

```swift
func handleSave(_ url: URL) {
    if let dataParam = getQueryParameter(url, "data"),
       var data = Data(base64Encoded: dataParam),
       let offsetParam = getQueryParameter(url, "offset"),
       let offset = Int(offsetParam) {
        let arr = [UInt8](data)
        // BAD: `offset` is not checked against the bounds of `data`.
        data = Data(bytes: &data + offset, count: arr.count - offset)
    }
}
```

The fix is to check that the offset is inside the buffer before using it, or to use a bounds-checked API:

```swift
func handleSave(_ url: URL) {
    if let dataParam = getQueryParameter(url, "data"),
       let data = Data(base64Encoded: dataParam),
       let offsetParam = getQueryParameter(url, "offset"),
       let offset = Int(offsetParam),
       offset >= 0, offset <= data.count {
        // GOOD: `offset` is checked against both bounds, and `subdata(in:)` is bounds-checked.
        let trimmed = data.subdata(in: offset..<data.count)
    }
}
```

## References

- Apple Developer Documentation: [UnsafePointer](https://developer.apple.com/documentation/swift/unsafepointer).
- Apple Developer Documentation: [UnsafeRawPointer](https://developer.apple.com/documentation/swift/unsaferawpointer).
- Common Weakness Enumeration: [CWE-125](https://cwe.mitre.org/data/definitions/125.html).
- Common Weakness Enumeration: [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Common Weakness Enumeration: [CWE-823](https://cwe.mitre.org/data/definitions/823.html).
