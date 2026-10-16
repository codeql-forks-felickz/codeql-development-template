/**
 * Provides an additional taint step for `get` method calls on dictionaries.
 *
 * The `dict.get` flow summaries in `codeql/python-all` only read the element at a
 * known string key (`DictionaryElement[key]`), so taint stored at an unknown key
 * (`DictionaryElementAny`, for example by `dict(iterable)`) is lost by
 * `d.get("key")`, while it is kept by `d["key"]`.
 *
 * Using this step as an additional flow step lets taint tracking implicitly read
 * any dictionary element at the receiver before stepping to the call result.
 */

private import python
private import semmle.python.dataflow.new.DataFlow

/** Provides a taint step from a dictionary to the result of calling `get` on it. */
module DictionaryGetFlow {
  /** Holds if `nodeTo` is a call `nodeFrom.get(...)`. */
  predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::MethodCallNode call |
      call.calls(nodeFrom, "get") and
      nodeTo = call
    )
  }
}
