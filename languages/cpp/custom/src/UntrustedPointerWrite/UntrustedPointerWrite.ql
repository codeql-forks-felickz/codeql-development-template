/**
 * @name Write through a pointer read from untrusted data
 * @description Writing through a pointer whose value was read from untrusted
 *              input lets an attacker choose both the address and the data of
 *              a memory write (a "write-what-where" condition).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id cpp/custom/untrusted-pointer-write
 * @tags security
 *       external/cwe/cwe-123
 *       external/cwe/cwe-787
 *       external/cwe/cwe-822
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.security.FlowSources as FS

/**
 * Holds if `e` is the target of an assignment, that is, the left-hand side of
 * an assignment or the operand of an increment or decrement.
 */
predicate isWrittenTo(Expr e) {
  e = any(Assignment a).getLValue()
  or
  e = any(CrementOperation c).getOperand()
}

/**
 * Holds if `ptr` is a pointer that is dereferenced by the write target
 * `target`, for example `ptr` in `ptr->next = x`, `*ptr = x` or `ptr[i] = x`.
 */
predicate isDereferencedForWrite(Expr ptr, Expr target) {
  isWrittenTo(target) and
  (
    ptr = target.(PointerFieldAccess).getQualifier()
    or
    ptr = target.(PointerDereferenceExpr).getOperand()
    or
    ptr = target.(ArrayExpr).getArrayBase() and
    ptr.getUnspecifiedType() instanceof PointerType
  )
}

module UntrustedPointerWriteConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FS::FlowSource }

  predicate isSink(DataFlow::Node sink) { isDereferencedForWrite(sink.asExpr(), _) }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    // A field read from a structure whose contents are tainted, for example
    // `data.list.prev` after `fgets((char *)&data, sizeof(data), stdin)`.
    exists(FieldAccess fa | n1.asIndirectExpr() = fa.getQualifier() |
      n2.asExpr() = fa
      or
      n2.asIndirectExpr() = fa
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UntrustedPointerWriteFlow = TaintTracking::Global<UntrustedPointerWriteConfig>;

import UntrustedPointerWriteFlow::PathGraph

from
  UntrustedPointerWriteFlow::PathNode source, UntrustedPointerWriteFlow::PathNode sink, Expr target
where
  UntrustedPointerWriteFlow::flowPath(source, sink) and
  isDereferencedForWrite(sink.getNode().asExpr(), target)
select target, source, sink, "This write goes through a pointer that is read from $@.",
  source.getNode(), source.getNode().(FS::FlowSource).getSourceType()
