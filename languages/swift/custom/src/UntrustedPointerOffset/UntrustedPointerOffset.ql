/**
 * @name Unsafe pointer access with user-controlled offset
 * @description Using a user-controlled value as an offset, index or length for an unsafe
 *              pointer operation without checking it against the bounds of the underlying
 *              buffer can cause out-of-bounds memory reads or writes.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id swift/untrusted-pointer-offset
 * @tags security
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 *       external/cwe/cwe-823
 */

import swift
import codeql.swift.controlflow.BasicBlocks
import codeql.swift.controlflow.CfgNodes
import codeql.swift.controlflow.ControlFlowGraph
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.ExternalFlow
import codeql.swift.dataflow.FlowSources
import codeql.swift.dataflow.FlowSteps
import codeql.swift.dataflow.TaintTracking
import UntrustedPointerOffsetFlow::PathGraph

/**
 * Taint propagation through `URLComponents`/`NSURLComponents`, which are commonly used to
 * extract query parameters from deep-link URLs.
 */
private class UrlComponentsSummaries extends SummaryModelCsv {
  override predicate row(string row) {
    row =
      [
        ";URLComponents;true;init(url:resolvingAgainstBaseURL:);;;Argument[0];ReturnValue;taint",
        ";URLComponents;true;init(string:);;;Argument[0];ReturnValue;taint",
        ";URLComponents;true;init(string:encodingInvalidCharacters:);;;Argument[0];ReturnValue;taint",
        ";NSURLComponents;true;init(url:resolvingAgainstBaseURL:);;;Argument[0];ReturnValue;taint",
        ";NSURLComponents;true;init(string:);;;Argument[0];ReturnValue;taint",
        ";NSURLComponents;true;init(string:encodingInvalidCharacters:);;;Argument[0];ReturnValue;taint",
        ";Sequence;true;first(where:);;;Argument[-1];ReturnValue;taint"
      ]
  }
}

/**
 * A content implying that, if a `URLComponents`, `NSURLComponents` or `URLQueryItem` is
 * tainted, then all its fields are tainted.
 */
private class UrlComponentsFieldsInheritTaint extends TaintInheritingContent,
  DataFlow::Content::FieldContent
{
  UrlComponentsFieldsInheritTaint() {
    this.getField().getEnclosingDecl().asNominalTypeDecl().getName() =
      ["URLComponents", "NSURLComponents", "URLQueryItem"]
  }
}

/** Gets `t` with any `inout`/l-value wrappers and type aliases removed. */
private Type stripType(Type t) {
  result = stripType(t.(InOutType).getObjectType())
  or
  result = stripType(t.(LValueType).getObjectType())
  or
  not t instanceof InOutType and
  not t instanceof LValueType and
  result = t.getUnderlyingType()
}

/** Holds if `t` is one of the Swift unsafe pointer types that support pointer arithmetic. */
private predicate isUnsafePointerType(Type t) {
  stripType(t).(AnyGenericType).getDeclaration().getName() =
    [
      "UnsafePointer", "UnsafeMutablePointer", "UnsafeRawPointer", "UnsafeMutableRawPointer",
      "AutoreleasingUnsafeMutablePointer"
    ]
}

/** Holds if `t` is one of the Swift unsafe buffer pointer types. */
private predicate isUnsafeBufferPointerType(Type t) {
  stripType(t).(AnyGenericType).getDeclaration().getName() =
    [
      "UnsafeBufferPointer", "UnsafeMutableBufferPointer", "UnsafeRawBufferPointer",
      "UnsafeMutableRawBufferPointer"
    ]
}

/** Gets the type of `e` after all implicit conversions have been applied. */
private Type convertedType(Expr e) { result = e.getFullyConverted().getType() }

/**
 * An expression that is used as an offset, index or length for an unsafe pointer
 * operation, where an out-of-range value leads to an out-of-bounds memory access.
 */
private class UnsafePointerOffsetSink extends DataFlow::Node {
  string kind;

  UnsafePointerOffsetSink() {
    // Pointer arithmetic, for example `ptr + offset`, `offset + ptr`, `ptr - offset`,
    // `ptr += offset` and `ptr -= offset`.
    exists(BinaryExpr be, Expr ptr |
      be.getStaticTarget().getShortName() = ["+", "-", "+=", "-="] and
      ptr = be.getAnOperand() and
      isUnsafePointerType(convertedType(ptr)) and
      this.asExpr() = be.getAnOperand() and
      this.asExpr() != ptr and
      not isUnsafePointerType(convertedType(this.asExpr())) and
      kind = "pointer arithmetic"
    )
    or
    // `ptr.advanced(by: offset)`, `rawPtr.load(fromByteOffset: offset, as: T.self)`
    exists(CallExpr call |
      call.getStaticTarget().getName() =
        ["advanced(by:)", "load(fromByteOffset:as:)", "loadUnaligned(fromByteOffset:as:)"] and
      (
        isUnsafePointerType(convertedType(call.getQualifier())) or
        isUnsafeBufferPointerType(convertedType(call.getQualifier()))
      ) and
      this.asExpr() = call.getArgument(0).getExpr() and
      kind = "pointer offset"
    )
    or
    // `ptr[index]` and `bufferPtr[index]` (buffer pointers are only bounds-checked in debug builds)
    exists(SubscriptExpr se |
      (
        isUnsafePointerType(convertedType(se.getBase())) or
        isUnsafeBufferPointerType(convertedType(se.getBase()))
      ) and
      this.asExpr() = se.getAnArgument().getExpr() and
      kind = "pointer subscript"
    )
    or
    // The length argument of APIs that read a number of bytes from a raw pointer, for
    // example `Data(bytes: ptr, count: length)` and `UnsafeBufferPointer(start: ptr, count: length)`.
    exists(CallExpr call, Method m, int i |
      m = call.getStaticTarget() and
      (
        m.hasQualifiedName("Data", ["init(bytes:count:)", "init(bytesNoCopy:count:deallocator:)"]) and
        i = 1
        or
        m.hasQualifiedName("NSData",
          [
            "init(bytes:length:)", "init(bytesNoCopy:length:)",
            "init(bytesNoCopy:length:freeWhenDone:)"
          ]) and
        i = 1
        or
        m.hasQualifiedName([
            "UnsafeBufferPointer", "UnsafeMutableBufferPointer", "UnsafeRawBufferPointer",
            "UnsafeMutableRawBufferPointer"
          ], "init(start:count:)") and
        i = 1
      ) and
      this.asExpr() = call.getArgument(i).getExpr() and
      kind = "pointer read length"
    )
  }

  /** Gets a description of the kind of unsafe pointer operation. */
  string getKind() { result = kind }
}

/**
 * Holds if the condition `cond` evaluating to `branch` implies that the variable `v` is
 * bounded from above (`isUpper = true`) or from below (`isUpper = false`).
 */
private predicate boundCheck(Expr cond, VarDecl v, boolean isUpper, boolean branch) {
  exists(BinaryExpr cmp, Expr lesser, Expr greater, boolean isUpperIfTrue |
    cond = cmp and
    (
      cmp.getStaticTarget().getShortName() = ["<", "<="] and
      lesser = cmp.getLeftOperand() and
      greater = cmp.getRightOperand()
      or
      cmp.getStaticTarget().getShortName() = [">", ">="] and
      lesser = cmp.getRightOperand() and
      greater = cmp.getLeftOperand()
    ) and
    (
      lesser.(DeclRefExpr).getDecl() = v and isUpperIfTrue = true
      or
      greater.(DeclRefExpr).getDecl() = v and isUpperIfTrue = false
    ) and
    (
      branch = true and isUpper = isUpperIfTrue
      or
      branch = false and isUpper = isUpperIfTrue.booleanNot()
    )
  )
  or
  // Range checks such as `(0..<count).contains(v)` or `0..<count ~= v`.
  exists(ApplyExpr call |
    cond = call and
    call.getStaticTarget().(Function).getShortName() = ["contains", "~="] and
    call.getAnArgument().getExpr().(DeclRefExpr).getDecl() = v and
    isUpper = [true, false] and
    branch = true
  )
}

/**
 * Holds if `n` is guarded by a condition that bounds the variable `v` from above
 * (`isUpper = true`) or from below (`isUpper = false`).
 */
private predicate guardedBy(DataFlow::Node n, VarDecl v, boolean isUpper) {
  exists(ConditionBlock cb, ExprCfgNode condNode, Expr cond, boolean branch |
    boundCheck(cond, v, isUpper, branch) and
    condNode.getExpr() = cond and
    cb.getLastNode() = condNode and
    cb.edgeDominates(n.getCfgNode().getBasicBlock(), any(BooleanSuccessor s | s.getValue() = branch))
  )
}

/**
 * A read of a variable that has been checked against both a lower and an upper bound
 * before the read.
 */
private class BoundsCheckedVariableBarrier extends DataFlow::Node {
  BoundsCheckedVariableBarrier() {
    exists(VarDecl v |
      this.asExpr().(DeclRefExpr).getDecl() = v and
      guardedBy(this, v, true) and
      guardedBy(this, v, false)
    )
  }
}

/**
 * A clamped value, for example `min(max(v, 0), count)` or `max(0, min(v, count))`.
 */
private class ClampBarrier extends DataFlow::Node {
  ClampBarrier() {
    exists(CallExpr outer, CallExpr inner, string outerName, string innerName |
      this.asExpr() = outer and
      outer.getStaticTarget().getName() = outerName + "(_:_:)" and
      inner = outer.getAnArgument().getExpr() and
      inner.getStaticTarget().getName() = innerName + "(_:_:)" and
      (
        outerName = "min" and innerName = "max"
        or
        outerName = "max" and innerName = "min"
      )
    )
  }
}

/**
 * The size of a buffer (for example `data.count`). Even if the buffer contents are
 * tainted, its own size is not an attacker-chosen offset.
 */
private class BufferSizeBarrier extends DataFlow::Node {
  BufferSizeBarrier() {
    this.asExpr().(MemberRefExpr).getMember().(VarDecl).getName() =
      ["count", "capacity", "startIndex", "endIndex"]
  }
}

module UntrustedPointerOffsetConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof FlowSource }

  predicate isSink(DataFlow::Node node) { node instanceof UnsafePointerOffsetSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof BoundsCheckedVariableBarrier or
    node instanceof ClampBarrier or
    node instanceof BufferSizeBarrier
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UntrustedPointerOffsetFlow = TaintTracking::Global<UntrustedPointerOffsetConfig>;

from
  UntrustedPointerOffsetFlow::PathNode source, UntrustedPointerOffsetFlow::PathNode sink,
  UnsafePointerOffsetSink sinkNode
where
  UntrustedPointerOffsetFlow::flowPath(source, sink) and
  sinkNode = sink.getNode()
select sink.getNode(), source, sink,
  "This value is used as an unchecked " + sinkNode.getKind() + " and depends on a $@.",
  source.getNode(), "user-provided value"
