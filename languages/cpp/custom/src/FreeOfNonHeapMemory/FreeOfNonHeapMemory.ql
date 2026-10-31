/**
 * @name Free of memory not on the heap
 * @description Passing the address of a stack, static or global array, or of
 *              memory from `alloca`, to a deallocation function corrupts the
 *              allocator's internal data structures.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cpp/custom/free-of-non-heap-memory
 * @tags security
 *       external/cwe/cwe-590
 *       external/cwe/cwe-761
 *       external/cwe/cwe-763
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/** Holds if `e` evaluates to the address of memory that is not on the heap. */
predicate isNonHeapAddress(Expr e, string kind) {
  exists(Variable v, ArrayType t |
    e = v.getAnAccess() and
    t = v.getUnspecifiedType() and
    not v instanceof Parameter and
    // Zero-sized and flexible trailing arrays are sometimes used as headers of heap blocks.
    t.getArraySize() > 0 and
    not v instanceof Field and
    // Only consider accesses that may let the address escape, rather than
    // element accesses or arguments to library functions such as `memset`.
    not e = any(ArrayExpr ae).getArrayBase() and
    not exists(Call c |
      e = c.getAnArgument() and
      not c instanceof DeallocationExpr and
      not c.getTarget().hasDefinition()
    )
  |
    if v instanceof LocalVariable and not v.isStatic()
    then kind = "stack array"
    else kind = "static array"
  )
  or
  e.(FunctionCall).getTarget().hasGlobalName(["alloca", "__builtin_alloca", "_alloca"]) and
  kind = "alloca allocation"
}

module FreeOfNonHeapMemoryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isNonHeapAddress(source.asExpr(), _) }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(DeallocationExpr d).getFreedExpr() }

  predicate isBarrierOut(DataFlow::Node node) { isSink(node) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module FreeOfNonHeapMemoryFlow = DataFlow::Global<FreeOfNonHeapMemoryConfig>;

import FreeOfNonHeapMemoryFlow::PathGraph

from
  FreeOfNonHeapMemoryFlow::PathNode source, FreeOfNonHeapMemoryFlow::PathNode sink,
  DeallocationExpr dealloc, string kind
where
  FreeOfNonHeapMemoryFlow::flowPath(source, sink) and
  isNonHeapAddress(source.getNode().asExpr(), kind) and
  sink.getNode().asExpr() = dealloc.getFreedExpr()
select dealloc, source, sink, "This frees memory from a $@, which is not on the heap.",
  source.getNode(), kind
