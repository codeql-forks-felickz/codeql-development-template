/**
 * @name Free of pointer not at start of buffer
 * @description Freeing a pointer that was advanced past the start of its heap
 *              allocation corrupts the allocator's internal data structures.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cpp/custom/free-not-at-start-of-buffer
 * @tags security
 *       external/cwe/cwe-761
 *       external/cwe/cwe-763
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.ir.IR

/**
 * Holds if `pai` computes a pointer that is offset from a pointer that was
 * returned by `alloc` in the same function.
 */
predicate offsetFromAllocation(PointerArithmeticInstruction pai, AllocationExpr alloc) {
  exists(DataFlow::Node allocNode, DataFlow::Node base |
    allocNode.asExpr() = alloc and
    base.asInstruction() = pai.getLeft() and
    DataFlow::localFlow(allocNode, base)
  )
}

module FreeNotAtStartOfBufferConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { offsetFromAllocation(source.asInstruction(), _) }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(DeallocationExpr d).getFreedExpr() }

  predicate isBarrierOut(DataFlow::Node node) { isSink(node) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module FreeNotAtStartOfBufferFlow = DataFlow::Global<FreeNotAtStartOfBufferConfig>;

import FreeNotAtStartOfBufferFlow::PathGraph

from
  FreeNotAtStartOfBufferFlow::PathNode source, FreeNotAtStartOfBufferFlow::PathNode sink,
  AllocationExpr alloc, DeallocationExpr dealloc
where
  FreeNotAtStartOfBufferFlow::flowPath(source, sink) and
  offsetFromAllocation(source.getNode().asInstruction(), alloc) and
  sink.getNode().asExpr() = dealloc.getFreedExpr()
select dealloc, source, sink,
  "This frees a pointer that may have been advanced from the start of the buffer $@.", alloc,
  "allocated here"
