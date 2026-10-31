/**
 * @name Improper validation of user-provided array index
 * @description Using an externally controlled integer as an array index without checking
 *              that it is within the bounds of the array can cause an
 *              `IndexOutOfRangeException` and a denial of service.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id cs/improper-validation-of-array-index
 * @tags security
 *       external/cwe/cwe-129
 */

import csharp
import semmle.code.csharp.controlflow.Guards
import semmle.code.csharp.security.dataflow.flowsources.FlowSources
import ImproperArrayIndex::PathGraph

/**
 * Holds if the array index `index` is guarded by the relational comparison `guard`
 * evaluating to `branch`, where `operand` is the operand of `guard` that (after
 * stripping implicit conversions) is structurally equal to `index`.
 */
private predicate guardedIndex(Expr index, RelationalOperation guard, Expr operand, boolean branch) {
  exists(GuardValue v |
    guard.(Guard).controlsNode(index.getAControlFlowNode(), operand.stripImplicit(), v) and
    v.asBooleanValue() = branch and
    operand = guard.getAnOperand()
  )
}

/** Holds if `index` is known to be bounded from above by a dominating comparison. */
private predicate upperBoundChecked(Expr index) {
  exists(RelationalOperation guard, Expr operand, boolean branch |
    guardedIndex(index, guard, operand, branch)
  |
    branch = true and operand = guard.getLesserOperand()
    or
    branch = false and operand = guard.getGreaterOperand()
  )
}

/**
 * Holds if `index` cannot be negative, either because it has an unsigned type or
 * because it is bounded from below by a dominating comparison.
 */
private predicate lowerBoundChecked(Expr index) {
  index.getType() instanceof UnsignedIntegralType
  or
  exists(RelationalOperation guard, Expr operand, boolean branch |
    guardedIndex(index, guard, operand, branch)
  |
    branch = true and operand = guard.getGreaterOperand()
    or
    branch = false and operand = guard.getLesserOperand()
  )
}

/** An array index expression that is not checked against both array bounds. */
private class UncheckedArrayIndex extends Expr {
  UncheckedArrayIndex() {
    this = any(ArrayAccess aa).getAnIndex() and
    this.getType() instanceof IntegralType and
    not (upperBoundChecked(this) and lowerBoundChecked(this))
  }
}

module ImproperArrayIndexConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof UncheckedArrayIndex }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module ImproperArrayIndex = TaintTracking::Global<ImproperArrayIndexConfig>;

from ImproperArrayIndex::PathNode source, ImproperArrayIndex::PathNode sink
where ImproperArrayIndex::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This array index depends on a $@ and is not checked against the array bounds.", source.getNode(),
  "user-provided value"
