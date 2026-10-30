/**
 * Provides a taint step for local variables that are captured by a nested scope
 * (a comprehension, generator expression, lambda or nested function) when the
 * variable is defined without a direct right-hand side value.
 *
 * The shared variable-capture library only treats definitions of the form
 * `x = value` as sources of captured-variable flow. Definitions such as tuple
 * unpacking (`a, x = value`) and `for` loop targets (`for x in values:`) are not
 * propagated into nested scopes, so in
 *
 * ```python
 * path, query = self.path.split("?", 1)
 * params = dict((k, query) for k in keys)
 * ```
 *
 * taint from `query` does not reach the generator expression.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.essa.Essa

/**
 * Holds if `def` defines the local variable `v` without a direct value, that is,
 * it is not covered by the shared variable-capture library. This is the case for
 * tuple unpacking of a non-literal value (no value at all) and for `for` loop
 * targets (where the value is the `for` statement itself).
 */
private predicate definitionWithoutValue(NameNode def, LocalVariable v) {
  def.defines(v) and
  (
    not exists(def.(DefinitionNode).getValue())
    or
    def.(DefinitionNode).getValue().getNode() instanceof For
  )
}

/**
 * Holds if `use` reads the local variable `v` from a scope nested inside the
 * function that declares `v`.
 */
private predicate capturedUse(NameNode use, LocalVariable v) {
  use.uses(v) and
  v.getScope() instanceof Function and
  use.getScope().getScope+() = v.getScope()
}

private predicate comprehensionCreationPoint(Comp comp, LocalVariable v, ControlFlowNode point) {
  exists(DefinitionNode assignment |
    assignment.getScope() = v.getScope() and
    assignment.getValue().getNode().getAChildNode*() = comp and
    point = assignment
  )
  or
  not exists(DefinitionNode assignment |
    assignment.getScope() = v.getScope() and
    assignment.getValue().getNode().getAChildNode*() = comp
  ) and
  exists(AstNode parent |
    parent = comp.getParentNode+() and
    parent.getScope() = v.getScope() and
    point.getNode() = parent and
    not exists(AstNode closer |
      closer = comp.getParentNode+() and
      closer.getScope() = v.getScope() and
      parent.getAChildNode+() = closer and
      exists(ControlFlowNode n | n.getNode() = closer)
    )
  )
}

/**
 * Holds if `def` is the latest reaching SSA definition of `v` at a comprehension.
 */
private predicate definitionReachesComprehension(NameNode def, NameNode use, LocalVariable v) {
  exists(Comp comp, ControlFlowNode point, EssaNodeDefinition ssaDef |
    comp.getFunction() = use.getScope() and
    comprehensionCreationPoint(comp, v, point) and
    ssaDef.getSourceVariable() = v and
    ssaDef.getDefiningNode().getNode() = def.getNode() and
    ssaDef.getDefiningNode().strictlyDominates(point) and
    not exists(EssaNodeDefinition overwritten |
      overwritten.getSourceVariable() = v and
      ssaDef.getDefiningNode().strictlyDominates(overwritten.getDefiningNode()) and
      overwritten.getDefiningNode().strictlyDominates(point)
    )
  )
}

/**
 * Holds if taint should flow from `nodeFrom`, a definition of a local variable
 * without a direct value, to `nodeTo`, a read of that variable in a nested scope.
 */
predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(LocalVariable v, NameNode def, NameNode use |
    definitionWithoutValue(def, v) and
    capturedUse(use, v) and
    (
      not exists(Comp comp | comp.getFunction() = use.getScope())
      or
      definitionReachesComprehension(def, use, v)
    ) and
    nodeFrom.asCfgNode() = def and
    nodeTo.asCfgNode() = use
  )
}
