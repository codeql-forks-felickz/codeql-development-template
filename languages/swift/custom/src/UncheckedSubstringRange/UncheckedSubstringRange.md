# Unchecked substring range

`NSString.range(of:)` returns a range whose `location` is `NSNotFound` (and whose `length` is `0`) when the text is not found. If the app uses that range to compute the bounds of a substring without checking for this case, input that does not contain the expected delimiter makes the computed bounds invalid. Calls such as `substring(with:)`, `substring(from:)` or `substring(to:)` then raise an `NSRangeException` and crash the app, or extract the wrong part of the string. This is a risk when the string comes from an untrusted source, such as a server response (CWE-20).

## Recommendation

Check the result of every `range(of:)` call before you use it. Compare `location` with `NSNotFound` (or check that `length` is not `0`), and check that the computed bounds are in order and inside the string. Better still, use a real parser for structured data such as HTML, JSON or XML.

## Example

In this example, the key is extracted from an HTTP response without checking that either delimiter was found:

```swift
func key(fromResponseString responseString: String?) -> String? {
  let searchFromRange: NSRange? = (responseString as NSString?)?.range(of: "<td>key</td><td>")
  let searchToRange: NSRange? = (responseString as NSString?)?.range(of: "</td></tr></table>")
  // BAD: if either delimiter is missing, the computed range is invalid
  return (responseString as NSString?)?.substring(with: NSRange(
    location: (searchFromRange?.location ?? 0) + (searchFromRange?.length ?? 0),
    length: (searchToRange?.location ?? 0) - (searchFromRange?.location ?? 0) - (searchFromRange?.length ?? 0)))
}
```

In this version, both lookups are checked before the substring is computed:

```swift
func key(fromResponseString responseString: String) -> String? {
  let ns = responseString as NSString
  let searchFromRange = ns.range(of: "<td>key</td><td>")
  let searchToRange = ns.range(of: "</td></tr></table>")
  // GOOD: both delimiters must be present and in order
  guard searchFromRange.location != NSNotFound, searchToRange.location != NSNotFound else {
    return nil
  }
  let start = searchFromRange.location + searchFromRange.length
  guard searchToRange.location >= start else { return nil }
  return ns.substring(with: NSRange(location: start, length: searchToRange.location - start))
}
```

## References

- Apple Developer Documentation: [range(of:)](<https://developer.apple.com/documentation/foundation/nsstring/range(of:)>).
- Common Weakness Enumeration: [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Common Weakness Enumeration: [CWE-129](https://cwe.mitre.org/data/definitions/129.html).
