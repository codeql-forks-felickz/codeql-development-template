/**
 * @name Fixed-size access to buffer with untrusted allocation size
 * @description Copying a fixed number of bytes into, or accessing a constant
 *              index of, a heap buffer whose size is computed from untrusted
 *              data, without checking that the size is large enough, can
 *              overflow the buffer.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id cpp/custom/copy-exceeds-tainted-allocation
 * @tags security
 *       external/cwe/cwe-122
 *       external/cwe/cwe-131
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.models.interfaces.ArrayFunction
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.security.FlowSources as FS
import semmle.code.cpp.valuenumbering.GlobalValueNumbering

/**
 * Holds if `fc` writes exactly `n` bytes (a compile-time constant) to the
 * buffer passed as its `dest` argument.
 */
predicate fixedSizeByteWrite(FunctionCall fc, Expr dest, int n) {
  exists(ArrayFunction f, int destParam, int countParam, Type base |
    f = fc.getTarget() and
    f.hasArrayOutput(destParam) and
    f.hasArrayWithVariableSize(destParam, countParam) and
    dest = fc.getArgument(destParam) and
    n = fc.getArgument(countParam).getValue().toInt() and
    n > 0 and
    base = f.getParameter(destParam).getUnspecifiedType().(PointerType).getBaseType() and
    (base instanceof VoidType or base.getSize() = 1)
  )
}

/**
 * Holds if `access` reads or writes the first `n` bytes of the buffer `dest`,
 * either as a fixed-size copy or as an array access with a constant index.
 * Accesses to index 0 are excluded, since they only fail for empty buffers.
 */
predicate fixedSizeAccess(Expr access, Expr dest, int n) {
  fixedSizeByteWrite(access, dest, n)
  or
  exists(ArrayExpr ae, int c |
    access = ae and
    dest = ae.getArrayBase() and
    dest.getUnspecifiedType() instanceof PointerType and
    c = ae.getArrayOffset().getValue().toInt() and
    c > 0 and
    n = (c + 1) * ae.getUnspecifiedType().getSize()
  )
}

/** Gets a description of the fixed-size `access`, which covers `n` bytes. */
bindingset[n]
string describeAccess(Expr access, int n) {
  access instanceof FunctionCall and result = "This call writes " + n + " bytes into"
  or
  access instanceof ArrayExpr and result = "This array access reaches byte " + n + " of"
}

/** Holds if a guard ensures that `size` is at least `n` in `bb`. */
bindingset[n]
predicate guardedAtLeast(Expr size, int n, BasicBlock bb) {
  exists(GuardCondition g, Expr checked, int k |
    globalValueNumber(checked) = globalValueNumber(size) and
    g.ensuresLt(checked, k, bb, false) and
    k >= n
  )
}

/**
 * Holds if `alloc` allocates `size` bytes, the result flows to the destination
 * of `fc`, which accesses `n` bytes, and neither range analysis nor a guard
 * shows that `size >= n`.
 */
predicate copyMayExceedAllocation(AllocationExpr alloc, Expr size, Expr fc, int n) {
  exists(Expr dest |
    size = alloc.getSizeExpr() and
    not exists(size.getValue()) and
    fixedSizeAccess(fc, dest, n) and
    DataFlow::localExprFlow(alloc, dest) and
    lowerBound(size.getFullyConverted()) < n and
    not guardedAtLeast(size, n, alloc.getBasicBlock()) and
    not guardedAtLeast(size, n, fc.getBasicBlock())
  )
}

module CopyExceedsTaintedAllocationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FS::FlowSource }

  predicate isSink(DataFlow::Node sink) { copyMayExceedAllocation(_, sink.asExpr(), _, _) }

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

module CopyExceedsTaintedAllocationFlow = TaintTracking::Global<CopyExceedsTaintedAllocationConfig>;

import CopyExceedsTaintedAllocationFlow::PathGraph

from
  CopyExceedsTaintedAllocationFlow::PathNode source,
  CopyExceedsTaintedAllocationFlow::PathNode sink, AllocationExpr alloc, Expr fc, int n
where
  CopyExceedsTaintedAllocationFlow::flowPath(source, sink) and
  copyMayExceedAllocation(alloc, sink.getNode().asExpr(), fc, n)
select fc, source, sink,
  describeAccess(fc, n) + " a buffer $@ whose size depends on $@ and is not checked to be at least "
    + n + ".", alloc, "allocated here", source.getNode(),
  source.getNode().(FS::FlowSource).getSourceType()
