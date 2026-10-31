/**
 * Provides an additional flow summary for `dict.get` that reads dictionary
 * elements stored under an unknown key.
 *
 * Dictionaries built from (key, value) pairs, e.g. `dict(<generator of pairs>)`
 * or `{k: v for ...}`, store their values in the unknown-key bucket
 * (`DictionaryElementAny`). Subscript reads such as `d["x"]` already read from
 * that bucket, but the built-in `dict.get` summaries in `codeql/python-all`
 * only read `DictionaryElement[<key>]`, so `d.get("x")` loses the flow.
 */
overlay[local?]
module;

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.FlowSummary

/**
 * A flow summary for `dict.get` that reads values stored under an unknown key.
 */
private class DictGetUnknownKeySummary extends SummarizedCallable::Range {
  DictGetUnknownKeySummary() { this = "dict.get (unknown key)" }

  override DataFlow::CallCfgNode getACall() {
    result.(DataFlow::MethodCallNode).getMethodName() = "get"
  }

  override DataFlow::ArgumentNode getACallback() { none() }

  override predicate propagatesFlow(string input, string output, boolean preservesValue) {
    input = "Argument[self].DictionaryElementAny" and
    output = "ReturnValue" and
    preservesValue = true
  }
}
