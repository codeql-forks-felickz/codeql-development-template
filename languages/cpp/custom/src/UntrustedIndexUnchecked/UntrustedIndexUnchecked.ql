/**
 * @name Unchecked untrusted index into fixed-size array
 * @description Using an untrusted value as an index into a fixed-size array
 *              without any bounds check allows reads and writes outside the
 *              array.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id cpp/custom/untrusted-index-unchecked
 * @tags security
 *       external/cwe/cwe-121
 *       external/cwe/cwe-125
 *       external/cwe/cwe-129
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.security.FlowSources as FS
import semmle.code.cpp.valuenumbering.GlobalValueNumbering

/** Holds if a guard compares `v` with any bound in `bb`. */
predicate hasBoundCheck(Expr index, BasicBlock bb) {
  exists(GuardCondition g, Expr checked |
    globalValueNumber(checked) = globalValueNumber(index) and
    (
      g.ensuresLt(checked, _, bb, _)
      or
      g.ensuresLt(checked, _, _, bb, _)
      or
      g.ensuresLt(_, checked, _, bb, _)
    )
  )
}

/**
 * Holds if `index` is the index of `ae`, an access to an array of `size`
 * elements, no variable in `index` is bounds checked, and range analysis cannot
 * show that `index` is in bounds.
 */
predicate isUncheckedIndex(Expr index, ArrayExpr ae, int size) {
  index = ae.getArrayOffset() and
  size = ae.getArrayBase().getUnspecifiedType().(ArrayType).getArraySize() and
  not exists(index.getValue()) and
  (
    upperBound(index.getFullyConverted()) >= size
    or lowerBound(index.getFullyConverted()) < 0
  ) and
  not exists(VariableAccess va |
    va.getParent*() = index and
    hasBoundCheck(index, ae.getBasicBlock())
  )
}

module UntrustedIndexUncheckedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FS::FlowSource }

  predicate isSink(DataFlow::Node sink) { isUncheckedIndex(sink.asExpr(), _, _) }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    // A field read from a structure whose contents are tainted, for example
    // `img.width` after `fread(&img, sizeof(img), 1, fp)`.
    exists(FieldAccess fa |
      n1.asIndirectExpr() = fa.getQualifier() and
      n2.asExpr() = fa
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UntrustedIndexUncheckedFlow = TaintTracking::Global<UntrustedIndexUncheckedConfig>;

import UntrustedIndexUncheckedFlow::PathGraph

from
  UntrustedIndexUncheckedFlow::PathNode source, UntrustedIndexUncheckedFlow::PathNode sink,
  ArrayExpr ae, int size
where
  UntrustedIndexUncheckedFlow::flowPath(source, sink) and
  isUncheckedIndex(sink.getNode().asExpr(), ae, size)
select ae, source, sink,
  "This index into an array of " + size + " elements depends on $@ and is not bounds checked.",
  source.getNode(), source.getNode().(FS::FlowSource).getSourceType()
