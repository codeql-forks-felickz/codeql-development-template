/**
 * @name Untrusted divisor without zero check
 * @description Using a value read from a file, socket, environment variable or
 *              command line as the divisor of an integer division or remainder
 *              without first checking it against zero allows an attacker to
 *              crash the program with a divide-by-zero fault.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id cpp/tainted-divisor-without-zero-check
 * @tags security
 *       reliability
 *       external/cwe/cwe-369
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.controlflow.Dominance
import TaintedDivisorFlow::PathGraph

/** Gets the divisor operand of an integer division or remainder operation `op`. */
Expr getIntegerDivisor(Expr op) {
  (
    result = op.(DivExpr).getRightOperand() or
    result = op.(RemExpr).getRightOperand() or
    result = op.(AssignDivExpr).getRValue() or
    result = op.(AssignRemExpr).getRValue()
  ) and
  op.getUnspecifiedType() instanceof IntegralType
}

/**
 * Holds if `divisor` can be shown to be non-zero by range analysis, for
 * example `(x % 10) + 1`.
 */
predicate isProvablyNonZero(Expr divisor) {
  lowerBound(divisor.getFullyConverted()) > 0 or
  upperBound(divisor.getFullyConverted()) < 0
}

/**
 * Holds if `g` is a check that validates `e` on the `branch` edge. Any
 * comparison of `e`, or a test of `e` for truthiness, is treated as
 * validation since the exact non-zero bound is often expressed indirectly
 * (for example `if (height <= 0) return;`).
 */
predicate validatesValue(IRGuardCondition g, Expr e, boolean branch) {
  exists(ComparisonOperation cmp |
    cmp = g.getUnconvertedResultExpression() and
    e = cmp.getAnOperand() and
    branch = [true, false]
  )
  or
  e = g.getUnconvertedResultExpression() and
  not e instanceof ComparisonOperation and
  branch = true
  or
  exists(NotExpr not_ |
    not_ = g.getUnconvertedResultExpression() and
    e = not_.getOperand() and
    branch = false
  )
}

/**
 * Holds if `fa` accesses field `f` of the aggregate denoted by `base`, either
 * directly (`s.f`, `p->f`) or through an explicit dereference (`(*p).f`).
 */
predicate fieldAccessOf(FieldAccess fa, VariableAccess base, Field f) {
  f = fa.getTarget() and
  (
    base = fa.getQualifier()
    or
    base = fa.getQualifier().(PointerDereferenceExpr).getOperand()
  )
}

/**
 * Holds if field `f` of variable `v` is assigned by `assign`, which dominates
 * the field read `fa` or is itself the assignment's lvalue.
 */
predicate overwrittenBefore(
  DataFlow::Node aggregate, VariableAccess base, FieldAccess fa, Field f
) {
  exists(Assignment assign, VariableAccess otherBase, FunctionCall write, VariableAccess writeBase |
    fieldAccessOf(assign.getLValue(), otherBase, f) and
    otherBase.getTarget() = base.getTarget() and
    (
      aggregate.asIndirectExpr().(VariableAccess).getTarget() = base.getTarget()
      or aggregate.asExpr().(VariableAccess).getTarget() = base.getTarget()
    ) and
    write.getTarget().hasGlobalName(["fread", "recv"]) and
    writeBase.getParent*() = write.getAnArgument() and
    writeBase.getTarget() = base.getTarget() and
    dominates(write, assign) and
    (dominates(assign, fa) or fa = assign.getLValue())
  )
}

/**
 * Holds if `fieldRead` reads a field of an aggregate `base` that was written
 * as a whole (for example by `fread(&img, ...)` or `recv(s, &hdr, ...)`).
 */
predicate aggregateToFieldStep(DataFlow::Node aggregate, DataFlow::Node fieldRead) {
  exists(FieldAccess fa, VariableAccess base, Field f |
    fieldRead.asExpr() = fa and
    fieldAccessOf(fa, base, f) and
    not overwrittenBefore(aggregate, base, fa, f) and
    (
      aggregate.asIndirectExpr() = base
      or
      aggregate.asExpr() = base and base.getUnspecifiedType() instanceof Class
    )
  )
}

module TaintedDivisorConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(Expr divisor |
      divisor = getIntegerDivisor(_) and
      sink.asExpr() = divisor and
      not isProvablyNonZero(divisor)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::BarrierGuard<validatesValue/3>::getABarrierNode()
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    aggregateToFieldStep(n1, n2)
  }
}

module TaintedDivisorFlow = TaintTracking::Global<TaintedDivisorConfig>;

from
  TaintedDivisorFlow::PathNode source, TaintedDivisorFlow::PathNode sink, Expr op,
  FlowSource flowSource
where
  TaintedDivisorFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = getIntegerDivisor(op) and
  flowSource = source.getNode()
select sink.getNode(), source, sink,
  "This divisor depends on $@ and is not checked against zero before the $@.", flowSource,
  flowSource.getSourceType(), op, "division"
