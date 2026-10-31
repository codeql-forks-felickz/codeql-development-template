/**
 * Provides an additional flow step for local variables that are captured by a
 * nested scope (for example a generator expression, a comprehension or a lambda)
 * and that are defined without a single right-hand side value, such as targets of
 * iterable unpacking (`a, b = ...`) or of `for` loops.
 *
 * The variable-capture instantiation in `codeql/python-all` models a write to a
 * captured variable as flow from the value of its definition
 * (`DefinitionNode.getValue()`). Iterable-unpacking targets have no such value, and
 * the value of a `for` loop target is the `For` statement itself, which carries no
 * data flow, so flow from these definitions into nested scopes is lost.
 */

private import python
private import semmle.python.dataflow.new.DataFlow

/** Provides a flow step for captured variables defined without a value. */
module CapturedUnpackingFlow {
  /**
   * Holds if `def` defines the local variable `v` without a single value
   * expression, and `use` reads `v` from a nested scope.
   */
  private predicate capturedValuelessDefinition(NameNode def, NameNode use, LocalVariable v) {
    def.defines(v) and
    not def.getNode() instanceof Parameter and
    not def.(DefinitionNode).getValue().getNode() instanceof Expr and
    use.uses(v) and
    use.getScope() != v.getScope()
  }

  /**
   * Holds if data flows from the definition `nodeFrom` of a captured variable to
   * the read `nodeTo` of that variable in a nested scope.
   */
  predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    capturedValuelessDefinition(nodeFrom.asCfgNode(), nodeTo.asCfgNode(), _)
  }
}
