/**
 * @name Untrusted value multiplied in allocation size without upper bound check
 * @description Multiplying an untrusted value in the size of a heap allocation,
 *              without first checking that it is within a safe range, can
 *              overflow and produce an allocation that is too small for the
 *              data later written into it.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id cpp/custom/allocation-size-overflow
 * @tags security
 *       external/cwe/cwe-680
 *       external/cwe/cwe-190
 *       external/cwe/cwe-122
 *       external/cwe/cwe-789
 */

import cpp
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.security.FlowSources as FS

/** Holds if a guard ensures that `v` is bounded from above (for example `v < 100`) in `bb`. */
predicate hasUpperBoundCheck(Variable v, BasicBlock bb) {
  exists(GuardCondition g, VariableAccess checked | checked = v.getAnAccess() |
    g.ensuresLt(checked, _, bb, true)
    or
    g.ensuresLt(checked, _, _, bb, true)
    or
    g.ensuresLt(_, checked, _, bb, false)
  )
}

/**
 * Holds if `operand` is an operand of the multiplication `mul`, which is part of
 * the size of `alloc`, and `operand` is not bounded so that `mul` cannot overflow
 * a 32-bit size or be negative.
 */
predicate isUnboundedFactor(AllocationExpr alloc, MulExpr mul, VariableAccess operand) {
  mul = alloc.getAChild+() and
  operand = mul.getAnOperand().getUnconverted() and
  not exists(operand.getValue()) and
  not hasUpperBoundCheck(operand.getTarget(), alloc.getBasicBlock()) and
  exists(Expr other | other = mul.getAnOperand() and other != operand.getFullyConverted() |
    upperBound(operand) * upperBound(other) > 2147483647.0
    or
    lowerBound(operand) < 0
  )
}

module AllocationSizeOverflowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FS::FlowSource }

  predicate isSink(DataFlow::Node sink) { isUnboundedFactor(_, _, sink.asExpr()) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module AllocationSizeOverflowFlow = TaintTracking::Global<AllocationSizeOverflowConfig>;

import AllocationSizeOverflowFlow::PathGraph

from
  AllocationSizeOverflowFlow::PathNode source, AllocationSizeOverflowFlow::PathNode sink,
  AllocationExpr alloc, MulExpr mul
where
  AllocationSizeOverflowFlow::flowPath(source, sink) and
  isUnboundedFactor(alloc, mul, sink.getNode().asExpr())
select alloc, source, sink,
  "This allocation size multiplies a value from $@ that is not checked against an upper bound, so $@ may overflow.",
  source.getNode(), source.getNode().(FS::FlowSource).getSourceType(), mul, mul.toString()
