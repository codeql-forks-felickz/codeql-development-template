/**
 * Provides an additional taint step for `get` method calls on dictionaries.
 *
 * The `dict.get` flow summaries in `codeql/python-all` only read the element at a
 * known string key (`DictionaryElement[key]`), so taint stored at an unknown key
 * (`DictionaryElementAny`, for example by `dict(iterable)`) is lost by
 * `d.get("key")`, while it is kept by `d["key"]`.
 *
 * The additional step is limited to dictionaries constructed from an iterable,
 * where keys are unknown and their values are stored in `DictionaryElementAny`.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.frameworks.Django

/** Provides a taint step from an unknown-key dictionary to the result of `get`. */
module DictionaryGetFlow {
  /** Holds if `nodeTo` is a call `nodeFrom.get(...)`. */
  predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::MethodCallNode call |
      call.calls(nodeFrom, "get") and
      nodeTo = call and
      (
        exists(Call dictCall |
          dictCall.getFunc().(Name).getId() = "dict" and
          exists(dictCall.getArg(0)) and
          DataFlow::localFlow(DataFlow::exprNode(dictCall), nodeFrom)
        )
        or
        nodeFrom = Django::MultiValueDict::instance()
      )
    )
  }
}
