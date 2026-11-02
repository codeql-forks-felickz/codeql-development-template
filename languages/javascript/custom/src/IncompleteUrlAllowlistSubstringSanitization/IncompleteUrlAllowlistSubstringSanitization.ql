/**
 * @name Incomplete URL substring sanitization against an allowlist
 * @description Checking whether an unparsed URL contains, starts with or ends with an entry of a
 *              URL allowlist is often vulnerable to bypassing, since arbitrary hosts may come
 *              before or after the allowlisted entry.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id js/incomplete-url-allowlist-substring-sanitization
 * @tags correctness
 *       security
 *       external/cwe/cwe-020
 *       external/cwe/cwe-601
 */

import javascript
import codeql.regex.HostnameRegexp::Utils

/**
 * Holds if `elem` is the `i`th element of the array or `Set` literal `coll`,
 * for example `[a, b]` or `new Set([a, b])`.
 */
predicate allowlistElement(DataFlow::SourceNode coll, int i, DataFlow::Node elem) {
  elem = coll.(DataFlow::ArrayCreationNode).getElement(i)
  or
  coll = DataFlow::globalVarRef("Set").getAnInstantiation() and
  allowlistElement(coll.(DataFlow::NewNode).getArgument(0).getALocalSource(), i, elem)
}

/** Gets a reference to the allowlist collection `coll`. */
DataFlow::Node allowlistRef(DataFlow::SourceNode coll) {
  allowlistElement(coll, _, _) and
  (
    result = coll.getALocalUse()
    or
    // the collection is stored in a variable (for example a module-level constant)
    // that is read from another function
    exists(Variable v |
      v.getAnAssignedExpr() = coll.asExpr() and
      count(v.getAnAssignedExpr()) = 1 and
      result.asExpr() = v.getAnAccess()
    )
  )
}

/**
 * Holds if `nd` refers to an element of the allowlist collection `coll`, that is, it
 * is the iteration variable of a `for-of` loop over `coll`, or the first parameter of a
 * callback passed to an array iteration method such as `coll.some(...)`.
 */
predicate isAllowlistElementRef(DataFlow::Node nd, DataFlow::SourceNode coll) {
  exists(ForOfStmt loop |
    loop.getIterationDomain().flow() = allowlistRef(coll) and
    nd.asExpr() = loop.getAnIterationVariable().getAnAccess() and
    loop.getBody().getAChild*() = nd.asExpr() and
    count(loop.getAnIterationVariable().getAnAssignedExpr()) = 0
  )
  or
  exists(DataFlow::MethodCallNode call, DataFlow::ParameterNode p |
    call.getReceiver() = allowlistRef(coll) and
    call.getMethodName() =
      ["some", "every", "find", "findIndex", "findLast", "findLastIndex", "filter", "forEach"] and
    p = call.getABoundCallbackParameter(0, 0) and
    p.flowsTo(nd)
  )
}

/** A check on a string for whether it contains a given substring. */
class SomeSubstringCheck extends DataFlow::Node {
  DataFlow::Node substring;

  SomeSubstringCheck() {
    this.(StringOps::StartsWith).getSubstring() = substring or
    this.(StringOps::Includes).getSubstring() = substring or
    this.(StringOps::EndsWith).getSubstring() = substring
  }

  /** Gets the substring. */
  DataFlow::Node getSubstring() { result = substring }
}

/**
 * Holds if the substring check `check` is incomplete when `target` is the value of
 * the substring, mirroring `js/incomplete-url-substring-sanitization`.
 */
bindingset[target]
predicate isIncompleteCheckFor(SomeSubstringCheck check, string target) {
  (
    // target contains a domain on a common TLD, and perhaps some other URL components
    target.regexpMatch("(?i)([a-z]*:?//)?\\.?([a-z0-9-]+\\.)+" + getACommonTld() + "(:[0-9]+)?/?")
    or
    // target is a HTTP URL to a domain on any TLD
    target.regexpMatch("(?i)https?://([a-z0-9-]+\\.)+([a-z]+)(:[0-9]+)?/?")
    or
    // target is a HTTP URL to a domain on any TLD with path elements, and the check is an includes check
    check instanceof StringOps::Includes and
    target.regexpMatch("(?i)https?://([a-z0-9-]+\\.)+([a-z]+)(:[0-9]+)?/[a-z0-9/_-]+")
  ) and
  not (
    // the leading dot in a subdomain sequence makes the suffix-check safe (if it is performed on the host of the url)
    check instanceof StringOps::EndsWith and
    target.regexpMatch("(?i)\\.([a-z0-9-]+)(\\.[a-z0-9-]+)+")
    or
    // the trailing port or slash makes the prefix-check safe
    check instanceof StringOps::StartsWith and
    target.regexpMatch(".*(:[0-9]+|/)")
  )
}

/**
 * Holds if `elem` is the `i`th element of `coll`, has string value `target`, and makes
 * the substring check `check` on an element of `coll` incomplete.
 */
predicate incompleteAllowlistCheck(
  SomeSubstringCheck check, DataFlow::SourceNode coll, int i, DataFlow::Node elem, string target
) {
  isAllowlistElementRef(check.getSubstring(), coll) and
  // constant substrings are already reported by `js/incomplete-url-substring-sanitization`
  not check.getSubstring().mayHaveStringValue(_) and
  allowlistElement(coll, i, elem) and
  elem.mayHaveStringValue(target) and
  isIncompleteCheckFor(check, target)
}

from SomeSubstringCheck check, DataFlow::Node elem, string target, string msg
where
  exists(DataFlow::SourceNode coll, int i |
    incompleteAllowlistCheck(check, coll, i, elem, target) and
    // report only the first problematic allowlist entry
    i = min(int j | incompleteAllowlistCheck(check, coll, j, _, _))
  ) and
  if check instanceof StringOps::StartsWith
  then msg = "Allowlist entry '$@' may be followed by an arbitrary host name."
  else
    if check instanceof StringOps::EndsWith
    then msg = "Allowlist entry '$@' may be preceded by an arbitrary host name."
    else
      msg =
        "Allowlist entry '$@' can be anywhere in the URL, and arbitrary hosts may come before or after it."
select check, msg, elem, target
