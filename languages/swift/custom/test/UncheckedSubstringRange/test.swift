// --- stubs ---

let NSNotFound: Int = Int.max

struct _NSRange {
  var location: Int
  var length: Int
  init(location: Int, length: Int) {
    self.location = location
    self.length = length
  }
}

typealias NSRange = _NSRange

func NSMakeRange(_ loc: Int, _ len: Int) -> NSRange {
  return NSRange(location: loc, length: len)
}

class NSString {
  init(string: String) {}
  var length: Int { get { return 0 } }
  func range(of searchString: String) -> NSRange { return NSRange(location: NSNotFound, length: 0) }
  func range(of searchString: String, options mask: Int) -> NSRange { return NSRange(location: NSNotFound, length: 0) }
  func substring(with range: NSRange) -> String { return "" }
  func substring(from: Int) -> String { return "" }
  func substring(to: Int) -> String { return "" }
}

// --- tests ---

// BAD: neither delimiter lookup is checked before computing the substring range.
func key(fromResponseString responseString: String?) -> String? {
  let ns = responseString.map { NSString(string: $0) }
  let searchFromRange: NSRange? = ns?.range(of: "<td>key</td><td>") // $ Alert
  let searchToRange: NSRange? = ns?.range(of: "</td></tr></table>") // $ Alert
  let substring = ns?.substring(with: NSRange(location: Int((searchFromRange?.location ?? 0) + (searchFromRange?.length ?? 0)), length: Int((searchToRange?.location ?? 0) - (searchFromRange?.location ?? 0) - (searchFromRange?.length ?? 0))))
  return substring
}

// BAD: the location of a missing delimiter is NSNotFound, so the offset overflows.
func valueAfterEquals(_ s: NSString) -> String {
  let r = s.range(of: "=") // $ Alert
  return s.substring(from: r.location + r.length)
}

// BAD: unchecked range passed straight to `substring(with:)`.
func betweenMarkers(_ s: NSString) -> String {
  let start = s.range(of: "[", options: 0) // $ Alert
  return s.substring(with: NSMakeRange(start.location + 1, 3))
}

// BAD: unchecked range used directly.
func prefixUpTo(_ s: NSString) -> String {
  return s.substring(to: s.range(of: ";").location) // $ Alert
}

// GOOD: both lookups are checked against NSNotFound.
func keyChecked(fromResponseString responseString: String) -> String? {
  let ns = NSString(string: responseString)
  let searchFromRange = ns.range(of: "<td>key</td><td>")
  let searchToRange = ns.range(of: "</td></tr></table>")
  guard searchFromRange.location != NSNotFound, searchToRange.location != NSNotFound else {
    return nil
  }
  let start = searchFromRange.location + searchFromRange.length
  guard searchToRange.location >= start else {
    return nil
  }
  return ns.substring(with: NSRange(location: start, length: searchToRange.location - start))
}

// GOOD: the length of the match is checked.
func valueAfterEqualsChecked(_ s: NSString) -> String? {
  let r = s.range(of: "=")
  if r.length == 0 {
    return nil
  }
  return s.substring(from: r.location + r.length)
}

// GOOD: the range is only used to test whether the delimiter is present.
func hasDelimiter(_ s: NSString) -> Bool {
  return s.range(of: "=").location != NSNotFound
}

// GOOD: the range is not used to compute a substring.
func delimiterPosition(_ s: NSString) -> Int {
  let r = s.range(of: "=")
  return r.location
}
