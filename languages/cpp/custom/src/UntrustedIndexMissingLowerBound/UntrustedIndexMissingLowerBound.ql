/**
 * @name Untrusted signed index or size checked only against its upper bound
 * @description Using an untrusted signed value as an array index or copy size
 *              after checking only that it is below an upper bound allows a
 *              negative value to write before the start of a buffer, or to be
 *              converted to a very large size.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id cpp/custom/untrusted-index-missing-lower-bound
 * @tags security
 *       external/cwe/cwe-124
 *       external/cwe/cwe-127
 *       external/cwe/cwe-129
 *       external/cwe/cwe-194
 *       external/cwe/cwe-195
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.models.interfaces.ArrayFunction
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
 * Holds if `use` is an access to a signed variable `v` that is used as an array
 * index or as the size argument of a buffer function, `v` has been checked
 * against an upper bound but not against a lower bound, and range analysis
 * cannot show that it is non-negative. `kind` describes the use.
 */
predicate isUseWithOnlyUpperBoundCheck(VariableAccess use, Variable v, string kind) {
  v = use.getTarget() and
  use.getUnspecifiedType().(IntegralType).isSigned() and
  hasUpperBoundCheck(v, use.getBasicBlock()) and
  not hasLowerBoundCheck(v, use.getBasicBlock()) and
  lowerBound(use) < 0 and
  (
    use = any(ArrayExpr ae).getArrayOffset() and kind = "array index"
    or
    exists(FunctionCall fc, ArrayFunction f, int countParam |
      f = fc.getTarget() and
      f.hasArrayWithVariableSize(_, countParam) and
      use = fc.getArgument(countParam) and
      kind = "size argument to " + f.getName()
    )
  )
}

module UntrustedIndexMissingLowerBoundConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FS::FlowSource }

  predicate isSink(DataFlow::Node sink) { isUseWithOnlyUpperBoundCheck(sink.asExpr(), _, _) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UntrustedIndexMissingLowerBoundFlow =
  TaintTracking::Global<UntrustedIndexMissingLowerBoundConfig>;

import UntrustedIndexMissingLowerBoundFlow::PathGraph

from
  UntrustedIndexMissingLowerBoundFlow::PathNode source,
  UntrustedIndexMissingLowerBoundFlow::PathNode sink, Variable v, string kind
where
  UntrustedIndexMissingLowerBoundFlow::flowPath(source, sink) and
  isUseWithOnlyUpperBoundCheck(sink.getNode().asExpr(), v, kind)
select sink.getNode(), source, sink,
  "This " + kind +
    " depends on $@ and is only checked against an upper bound, so $@ may be negative.",
  source.getNode(), source.getNode().(FS::FlowSource).getSourceType(), v, v.getName()
