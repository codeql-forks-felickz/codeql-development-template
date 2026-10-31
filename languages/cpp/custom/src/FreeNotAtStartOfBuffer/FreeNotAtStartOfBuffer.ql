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
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.ir.IR
import semmle.code.cpp.valuenumbering.GlobalValueNumbering

/**
 * Holds if `pai` computes a pointer that is offset from a pointer that was
 * returned by `alloc` in the same function.
 */
predicate offsetFromAllocation(PointerArithmeticInstruction pai, AllocationExpr alloc) {
  not exists(ConstantInstruction zero |
    pai.getRight() = zero and
    zero.getValue().toInt() = 0
  ) and
  exists(DataFlow::Node allocNode, DataFlow::Node base |
    allocNode.asExpr() = alloc and
    base.asInstruction() = pai.getLeft() and
    DataFlow::localFlow(allocNode, base)
  )
}

/** Holds if a dominating guard proves that the freed pointer equals the allocation base. */
predicate freesOriginalPointer(DeallocationExpr dealloc) {
  exists(GuardCondition g, Expr checked, Expr compared, PointerAddExpr add, AllocationExpr alloc |
    DataFlow::localExprFlow(alloc, add.getLeftOperand()) and
    globalValueNumber(checked) = globalValueNumber(dealloc.getFreedExpr()) and
    globalValueNumber(compared) = globalValueNumber(add.getLeftOperand()) and
    g.ensuresEq(checked, compared, 0, dealloc.getBasicBlock(), true)
  )
}

module FreeNotAtStartOfBufferConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { offsetFromAllocation(source.asInstruction(), _) }

  predicate isSink(DataFlow::Node sink) {
    exists(DeallocationExpr dealloc |
      sink.asExpr() = dealloc.getFreedExpr() and
      not freesOriginalPointer(dealloc)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DeallocationExpr dealloc |
      node.asExpr() = dealloc.getFreedExpr() and
      freesOriginalPointer(dealloc)
    )
  }

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
