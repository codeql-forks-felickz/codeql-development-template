/**
 * @name Write through a pointer read from untrusted data
 * @description Reading untrusted bytes directly over an object that contains pointers, and
 *              then writing through one of those pointers, lets an attacker choose both the
 *              address and the value of a memory write (a write-what-where condition).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cpp/tainted-write-what-where
 * @tags security
 *       external/cwe/cwe-123
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.ir.IR
import TaintedWriteWhatWhere::PathGraph

/**
 * Holds if an object of type `t` stores a pointer, either directly or in a
 * nested field or array element.
 */
predicate containsPointer(Type t) {
  t.getUnspecifiedType() instanceof PointerType
  or
  containsPointer(t.getUnspecifiedType().(Class).getAField().getType())
  or
  containsPointer(t.getUnspecifiedType().(ArrayType).getBaseType())
}

/**
 * Holds if `t` is an untyped byte buffer pointer such as `void *` or `char *`,
 * into which a function copies raw bytes.
 */
predicate isRawBufferType(Type t) {
  exists(Type base |
    base = t.getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType()
  |
    base instanceof VoidType or base instanceof CharType
  )
}

/**
 * A source of untrusted bytes that are written by reference over an object
 * that stores pointers, for example `recv(sock, (char *)&obj, sizeof(obj), 0)`
 * where `obj` is a structure holding linked list pointers.
 *
 * Only functions that copy raw bytes into an untyped buffer parameter are
 * considered, so that sources such as the line pointer allocated by `getdelim`,
 * or the program-owned `msghdr` passed to `recvmsg`, are excluded.
 */
class PointerOverwriteSource instanceof FlowSource {
  PointerOverwriteSource() {
    exists(Call call, int i, Expr arg |
      arg = this.asDefiningArgument(1) and
      arg = call.getArgument(i) and
      isRawBufferType(call.getTarget().getParameter(i).getType()) and
      containsPointer(arg.getUnspecifiedType().(DerivedType).getBaseType())
    )
  }

  /** Gets a string that describes the type of this flow source. */
  string getSourceType() { result = super.getSourceType() }

  /** Gets a textual representation of this element. */
  string toString() { result = super.toString() }

  /** Gets the location of this element. */
  Location getLocation() { result = super.getLocation() }
}

/**
 * Gets the pointer expression that is dereferenced to compute the memory
 * location denoted by the lvalue `lv`.
 */
Expr getDereferencedPointer(Expr lv) {
  result = lv.(PointerFieldAccess).getQualifier()
  or
  result = lv.(PointerDereferenceExpr).getOperand()
  or
  result = lv.(ArrayExpr).getArrayBase() and
  result.getUnspecifiedType() instanceof PointerType
  or
  result = getDereferencedPointer(lv.(ValueFieldAccess).getQualifier())
  or
  result = getDereferencedPointer(lv.(ArrayExpr).getArrayBase()) and
  lv.(ArrayExpr).getArrayBase().getUnspecifiedType() instanceof ArrayType
}

/** Holds if `ptr` is dereferenced to obtain the target of the memory write `write`. */
predicate isWriteThroughPointer(Expr write, Expr ptr) {
  ptr = getDereferencedPointer(write.(Assignment).getLValue())
  or
  ptr = getDereferencedPointer(write.(CrementOperation).getOperand())
}

/**
 * Holds if the field access `fa` reads a value that was last written by a
 * direct store to exactly that field, rather than by the bulk write of the
 * enclosing object (for example, a pointer that was reset after `recv`).
 */
predicate isReadOfOverwrittenField(FieldAccess fa) {
  exists(LoadInstruction load |
    load.getUnconvertedResultExpression() = fa and
    load.getSourceValueOperand().getDef() instanceof StoreInstruction
  )
}

/**
 * Holds if `n1` is the contents of an object and `n2` reads one of its fields.
 * Bytes copied over a whole object (as `recv` does) taint every field that is
 * not subsequently overwritten.
 */
predicate fieldReadFromTaintedObject(DataFlow::Node n1, DataFlow::Node n2) {
  exists(FieldAccess fa |
    n1.asIndirectExpr() = fa.getQualifier() and
    (n2.asExpr() = fa or n2.asIndirectExpr() = fa) and
    not isReadOfOverwrittenField(fa)
  )
}

module TaintedWriteWhatWhereConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof PointerOverwriteSource }

  predicate isSink(DataFlow::Node sink) { isWriteThroughPointer(_, sink.asExpr()) }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    fieldReadFromTaintedObject(n1, n2)
  }

  predicate isBarrier(DataFlow::Node node) {
    // Only track the attacker-controlled pointer values themselves; a pointer
    // computed from an untrusted integer is a different (out-of-bounds) problem.
    forex(Expr e | e = node.asExpr() | e.getUnspecifiedType() instanceof ArithmeticType)
  }
}

module TaintedWriteWhatWhere = TaintTracking::Global<TaintedWriteWhatWhereConfig>;

from
  TaintedWriteWhatWhere::PathNode source, TaintedWriteWhatWhere::PathNode sink, Expr write,
  PointerOverwriteSource src
where
  TaintedWriteWhatWhere::flowPath(source, sink) and
  isWriteThroughPointer(write, sink.getNode().asExpr()) and
  src = source.getNode()
select write, source, sink,
  "This write goes through a pointer that is overwritten with $@, allowing an attacker to write to an arbitrary address.",
  src, "untrusted data (" + src.getSourceType() + ")"
