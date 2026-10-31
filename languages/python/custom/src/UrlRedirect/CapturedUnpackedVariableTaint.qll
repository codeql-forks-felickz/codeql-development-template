/**
 * Provides a taint step for local variables that are defined by iterable
 * unpacking and then read inside a nested scope.
 *
 * The variable-capture flow in `codeql/python-all` only tracks definitions
 * that have an assigned value (`DefinitionNode.getValue()`). Targets of an
 * unpacking assignment such as `path, query = self.path.split("?", 1)` have no
 * such value, so taint on `query` is lost when it is read inside a generator
 * expression, comprehension, lambda or nested function, for example:
 *
 * ```python
 * path, query = self.path.split("?", 1)
 * params = dict((k, query) for k in keys)
 * ```
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking

/**
 * Holds if `def` is an unpacking target that defines the local variable `v`
 * and `use` reads `v` from a scope nested inside the scope of `v`. Variables
 * with more than one write are excluded, since the unpacked value may have been
 * overwritten before the nested read.
 */
private predicate unpackedVariableCapturedRead(NameNode def, NameNode use) {
  exists(LocalVariable v |
    def.defines(v) and
    not exists(def.(DefinitionNode).getValue()) and
    def.getNode().getParentNode*() = any(Assign a).getATarget() and
    // `def` is the only write to `v`, so no later write can overwrite the unpacked value
    not exists(NameNode other | other.defines(v) and other != def) and
    use.uses(v) and
    use.getScope().getScope+() = v.getScope()
  )
}

/**
 * A taint step from a variable defined by iterable unpacking to a read of
 * that variable in a nested scope.
 */
private class CapturedUnpackedVariableTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    unpackedVariableCapturedRead(nodeFrom.asCfgNode(), nodeTo.asCfgNode())
  }
}
