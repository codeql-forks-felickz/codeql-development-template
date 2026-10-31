/**
 * Provides a flow step for local variables that are defined by iterable unpacking
 * (for example `path, query = self.path.split("?", 1)`) and then read inside a nested
 * scope such as a generator expression, comprehension, lambda or inner function.
 *
 * The variable-capture flow of the standard library only starts from definitions that
 * have a single assigned value. A target of iterable unpacking from a non-literal value
 * has no such value, so its taint does not reach reads of the variable in nested scopes.
 * For example, in
 *
 * ```python
 * path, query = self.path.split("?", 1)
 * params = dict((m.group(1), query) for m in re.finditer("...", query))
 * ```
 *
 * the read of `query` inside the generator expression is not tainted.
 */

private import python
private import semmle.python.dataflow.new.DataFlow

/**
 * Holds if `nodeFrom` is a definition of a function-local variable `v` by iterable
 * unpacking (or another definition without a single assigned value, such as a `for`
 * loop target) and `nodeTo` is a read of `v` in a scope nested inside the scope of `v`.
 */
predicate capturedUnpackedVariableStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(LocalVariable v, NameNode def |
    v.getScope() instanceof Function and
    def.defines(v) and
    not exists(def.(DefinitionNode).getValue()) and
    nodeFrom.asCfgNode() = def and
    nodeTo.asExpr() = v.getALoad() and
    nodeTo.asExpr().getScope() != v.getScope()
  )
}
