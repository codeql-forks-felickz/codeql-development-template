/**
 * @name Untrusted array index checked only against its lower bound
 * @description Using untrusted data as an array index after checking only that
 *              it is non-negative allows an attacker to read or write past the
 *              end of the array.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id cpp/custom/array-index-missing-upper-bound
 * @tags security
 *       external/cwe/cwe-129
 *       external/cwe/cwe-121
 *       external/cwe/cwe-122
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.security.FlowSources as FS

/** Holds if a guard ensures that `v` is bounded from below (for example `v >= 0`) in `bb`. */
predicate hasLowerBoundCheck(Variable v, BasicBlock bb) {
  exists(GuardCondition g, VariableAccess checked | checked = v.getAnAccess() |
    g.ensuresLt(checked, _, bb, false)
    or
    g.ensuresLt(checked, _, _, bb, false)
    or
    g.ensuresLt(_, checked, _, bb, true)
  )
}

/** Holds if a guard ensures that `v` is bounded from above (for example `v < 10`) in `bb`. */
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
 * Holds if `ae` is indexed by variable `v`, `v` has been checked against a lower
 * bound but not against an upper bound, and range analysis cannot show that
 * the index fits in the array.
 */
predicate isIndexWithOnlyLowerBoundCheck(ArrayExpr ae, Variable v) {
  exists(VariableAccess idx, BasicBlock bb |
    idx = ae.getArrayOffset() and
    v = idx.getTarget() and
    bb = ae.getBasicBlock() and
    hasLowerBoundCheck(v, bb) and
    not hasUpperBoundCheck(v, bb) and
    not exists(ArrayType at | at = ae.getArrayBase().getUnspecifiedType() |
      upperBound(idx.getFullyConverted()) < at.getArraySize()
    )
  )
}

module ArrayIndexMissingUpperBoundConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FS::FlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(ArrayExpr ae |
      sink.asExpr() = ae.getArrayOffset() and
      isIndexWithOnlyLowerBoundCheck(ae, _)
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module ArrayIndexMissingUpperBoundFlow = TaintTracking::Global<ArrayIndexMissingUpperBoundConfig>;

import ArrayIndexMissingUpperBoundFlow::PathGraph

from
  ArrayIndexMissingUpperBoundFlow::PathNode source, ArrayIndexMissingUpperBoundFlow::PathNode sink,
  ArrayExpr ae, Variable v
where
  ArrayIndexMissingUpperBoundFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = ae.getArrayOffset() and
  isIndexWithOnlyLowerBoundCheck(ae, v)
select ae, source, sink,
  "Array index $@ depends on $@ and is only checked against a lower bound, not the array size.", v,
  v.getName(), source.getNode(), source.getNode().(FS::FlowSource).getSourceType()
