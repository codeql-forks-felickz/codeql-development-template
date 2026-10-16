/**
 * Provides an additional taint step for local variables that are bound
 * without a direct value (e.g. by iterable unpacking such as
 * `path, query = ...`) and read from a nested scope (comprehension,
 * generator expression, lambda or inner function).
 *
 * Variable-capture flow in `codeql/python-all` only considers definitions
 * with a direct value (`x = ...`), so in
 *
 * ```python
 * path, query = self.path.split("?", 1)
 * params = dict((k, query) for k in keys)
 * ```
 *
 * the read of `query` inside the generator expression is not reached.
 */
overlay[local?]
module;

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking

/**
 * A taint step from a definition of a function-local variable that has no
 * direct value (e.g. a target of iterable unpacking) to a read of that
 * variable in a nested scope.
 */
private class CapturedUnpackedVariableStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(LocalVariable v, DefinitionNode def, Name load |
      v.getScope() instanceof Function and
      def.getNode() = v.getAStore() and
      not exists(def.getValue()) and
      load = v.getALoad() and
      load.getScope() != v.getScope() and
      nodeFrom.asCfgNode() = def and
      nodeTo.asExpr() = load
    )
  }
}
