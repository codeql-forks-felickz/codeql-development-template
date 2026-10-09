/**
 * Provides additional taint steps that close false-negative gaps in the
 * standard `py/command-line-injection` query.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.ApiGraphs

/**
 * A local variable of a function that is read from a nested scope (a lambda,
 * nested function or comprehension), that is, a captured variable.
 */
private class CapturedLocalVariable extends LocalVariable {
  CapturedLocalVariable() {
    this.getScope() instanceof Function and
    exists(NameNode use | use.uses(this) and use.getScope() != this.getScope())
  }
}

/**
 * Holds if `def` is a definition of the captured variable `v` that has no
 * directly assigned value, such as a target of tuple unpacking
 * (`path, query = self.path.split("?", 1)`) or a `for`/`with` target.
 *
 * Such definitions are not modeled as writes by the standard variable-capture
 * library, so flow from them into nested scopes is otherwise lost.
 */
private predicate capturedDefinitionWithoutValue(NameNode def, CapturedLocalVariable v) {
  def.defines(v) and
  not exists(def.(DefinitionNode).getValue())
}

/**
 * A taint step from a definition of a captured variable without a directly
 * assigned value (for example a tuple-unpacking target) to the reads of that
 * variable in nested scopes (lambdas, nested functions and comprehensions).
 */
private class CapturedUnpackedVariableStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(CapturedLocalVariable v, NameNode def, NameNode use |
      capturedDefinitionWithoutValue(def, v) and
      nodeFrom.asCfgNode() = def and
      use.uses(v) and
      use.getScope() != v.getScope() and
      nodeTo.asCfgNode() = use
    )
  }
}

/**
 * A taint step for `urllib.parse.parse_qsl`, which parses a query string into
 * a list of `(name, value)` pairs.
 *
 * See https://docs.python.org/3/library/urllib.parse.html#urllib.parse.parse_qsl
 */
private class ParseQslStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(API::CallNode call |
      call = API::moduleImport("urllib").getMember("parse").getMember("parse_qsl").getACall() and
      nodeFrom = call.getParameter(0, "qs").asSink() and
      nodeTo = call
    )
  }
}
