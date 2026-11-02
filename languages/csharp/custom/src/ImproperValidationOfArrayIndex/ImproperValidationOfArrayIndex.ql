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
import semmle.code.csharp.frameworks.System
import semmle.code.csharp.security.dataflow.flowsources.FlowSources
import ImproperArrayIndex::PathGraph

/**
 * Holds if the array index `index` is guarded by the relational comparison `guard`
 * evaluating to `branch`, where `operand` is the operand of `guard` that (after
 * stripping casts) is structurally equal to `index`.
 */
private predicate guardedIndex(Expr index, RelationalOperation guard, Expr operand, boolean branch) {
  exists(GuardValue v |
    guard.(Guard).controlsNode(index.getAControlFlowNode(), operand.stripCasts(), v) and
    v.asBooleanValue() = branch and
    operand = guard.getAnOperand()
  )
}

/** Holds if the array's length is compared against the indexed array's qualifier. */
private predicate isArrayLength(Expr length, Expr array) {
  exists(PropertyAccess access |
    length.stripCasts() = access and
    access.getTarget() = any(SystemArrayClass c).getLengthProperty() and
    sameArray(access.getQualifier(), array)
  )
}

private predicate sameArray(Expr array1, Expr array2) {
  array1.stripCasts() = array2.stripCasts()
  or
  array1 instanceof ThisAccess and array2 instanceof ThisAccess
  or
  exists(LocalScopeVariableAccess access1, LocalScopeVariableAccess access2 |
    array1.stripCasts() = access1 and
    array2.stripCasts() = access2 and
    access1.getTarget() = access2.getTarget()
  )
  or
  exists(MemberAccess access1, MemberAccess access2 |
    array1.stripCasts() = access1 and
    array2.stripCasts() = access2 and
    access1.getTarget() = access2.getTarget() and
    (
      sameArray(access1.getQualifier(), access2.getQualifier())
      or
      access1.hasImplicitThisQualifier() and access2.hasImplicitThisQualifier()
    )
  )
}

/** Holds if `index` is known to be bounded from above by a dominating comparison. */
private predicate upperBoundChecked(ArrayAccess access) {
  exists(RelationalOperation guard, Expr operand, Expr bound, boolean branch |
    guardedIndex(access.getAnIndex(), guard, operand, branch)
  |
    (
      branch = true and operand = guard.getLesserOperand() and bound = guard.getGreaterOperand()
      or
      branch = false and operand = guard.getGreaterOperand() and bound = guard.getLesserOperand()
    ) and
    (
      not isArrayLength(bound, access.getQualifier())
      or
      branch = true and guard.isStrict()
      or
      branch = false and not guard.isStrict()
    )
  )
}

/**
 * Holds if the comparison casts both the index and its array length to unsigned
 * integers, so a negative index cannot satisfy the upper-bound check.
 */
private predicate unsignedCastUpperBound(
  RelationalOperation guard, Expr indexOperand, Expr boundOperand, boolean branch
) {
  exists(CastExpr indexCast, CastExpr boundCast |
    indexOperand = indexCast and
    indexCast.getTargetType() instanceof UnsignedIntegralType and
    boundOperand = boundCast and
    boundCast.getTargetType() instanceof UnsignedIntegralType and
    (
      branch = true and
      guard instanceof LTExpr and
      indexOperand = guard.getLesserOperand() and
      boundOperand = guard.getGreaterOperand()
      or
      branch = false and
      guard instanceof GEExpr and
      indexOperand = guard.getGreaterOperand() and
      boundOperand = guard.getLesserOperand()
    )
  )
}

/**
 * Holds if `index` cannot be negative, either because it has an unsigned type or
 * because it is bounded from below by a dominating comparison.
 */
private predicate lowerBoundChecked(ArrayAccess access) {
  access.getAnIndex().getType() instanceof UnsignedIntegralType
  or
  exists(RelationalOperation guard, Expr operand, boolean branch |
    guardedIndex(access.getAnIndex(), guard, operand, branch)
  |
    branch = true and operand = guard.getGreaterOperand()
    or
    branch = false and operand = guard.getLesserOperand()
  )
  or
  exists(RelationalOperation guard, Expr indexOperand, Expr boundOperand, boolean branch |
    guardedIndex(access.getAnIndex(), guard, indexOperand, branch) and
    unsignedCastUpperBound(guard, indexOperand, boundOperand, branch) and
    isArrayLength(boundOperand, access.getQualifier())
  )
}

/** An array index expression that is not checked against both array bounds. */
private class UncheckedArrayIndex extends Expr {
  UncheckedArrayIndex() {
    exists(ArrayAccess aa |
      this = aa.getAnIndex() and
      this.getType() instanceof IntegralType and
      not (upperBoundChecked(aa) and lowerBoundChecked(aa))
    )
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
