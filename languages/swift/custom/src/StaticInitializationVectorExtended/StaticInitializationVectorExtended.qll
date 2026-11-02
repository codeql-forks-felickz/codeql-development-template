/**
 * Provides a taint-tracking configuration for finding static initialization
 * vectors (IVs) that the standard `swift/static-initialization-vector` query
 * does not report:
 *
 * - IVs passed to the CommonCrypto C API (`CCCrypt`, `CCCryptorCreate`,
 *   `CCCryptorCreateWithMode` and `CCCryptorReset`), which the standard query
 *   does not model as sinks.
 * - `nil` IVs passed to CommonCrypto, which CommonCrypto replaces with an
 *   all-zero IV.
 * - IVs that come from the default value of a parameter, which is used
 *   whenever a caller omits the argument.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.StaticInitializationVectorQuery
private import codeql.swift.generated.ParentChild

/**
 * Holds if `call` is a call to the CommonCrypto function `name`.
 */
private predicate isCommonCryptoCall(CallExpr call, string name) {
  call.getStaticTarget().(Function).getShortName() = name and
  name = ["CCCrypt", "CCCryptorCreate", "CCCryptorCreateWithMode", "CCCryptorReset"]
}

/**
 * Holds if `e` refers to a declaration named `name` through expressions that
 * preserve its value.
 */
bindingset[name]
private predicate refersTo(Expr e, string name) {
  exists(DeclRefExpr ref |
    ref.getDecl().(VarDecl).getName() = name and
    valuePreservingReference(e, ref)
  )
}

/**
 * Holds if `e` is `ref`, or is an expression that preserves the value of `ref`.
 */
private predicate valuePreservingReference(Expr e, DeclRefExpr ref) {
  e = ref
  or
  exists(ParenExpr parens |
    e = parens and
    valuePreservingReference(parens.getImmediateSubExpr(), ref)
  )
  or
  exists(CallExpr conversion |
    e = conversion and
    conversion.getStaticTarget() instanceof Initializer and
    conversion.getType().getName() = ["CCOptions", "UInt32"] and
    valuePreservingReference(conversion.getArgument(0).getExpr(), ref)
  )
  or
  exists(OrBitwiseExpr bitwiseOr |
    e = bitwiseOr and
    valuePreservingReference(bitwiseOr.getAnOperand(), ref)
  )
  or
  exists(DeclRefExpr localRef, VarDecl localVariable, Expr initializer |
    e = localRef and
    localRef.getDecl() = localVariable and
    initializer = localVariable.getParentInitializer() and
    DataFlow::localExprFlow(initializer, localRef) and
    valuePreservingReference(initializer, ref)
  )
  or
  exists(DeclRefExpr localRef, AssignExpr assignment |
    e = localRef and
    assignment.getDest() = localRef and
    DataFlow::localExprFlow(assignment.getSource(), localRef) and
    valuePreservingReference(assignment.getSource(), ref)
  )
}

/**
 * Holds if `call` is a CommonCrypto call that ignores the IV, because it uses
 * ECB mode or the RC4 stream cipher.
 */
private predicate ignoresInitializationVector(CallExpr call) {
  isCommonCryptoCall(call, ["CCCrypt", "CCCryptorCreate"]) and
  (
    refersTo(call.getArgument(1).getExpr(), "kCCAlgorithmRC4") or
    refersTo(call.getArgument(2).getExpr(), "kCCOptionECBMode")
  )
  or
  isCommonCryptoCall(call, "CCCryptorCreateWithMode") and
  (
    refersTo(call.getArgument(1).getExpr(), ["kCCModeECB", "kCCModeRC4"]) or
    refersTo(call.getArgument(2).getExpr(), "kCCAlgorithmRC4")
  )
}

/**
 * An IV argument of a CommonCrypto function. A `nil` IV is replaced by an
 * all-zero IV.
 */
class CommonCryptoInitializationVectorSink extends StaticInitializationVectorSink {
  CommonCryptoInitializationVectorSink() {
    exists(CallExpr call, string name, int ivIndex |
      isCommonCryptoCall(call, name) and
      (
        name = ["CCCrypt", "CCCryptorCreate"] and ivIndex = 5
        or
        name = "CCCryptorCreateWithMode" and ivIndex = 4
        or
        name = "CCCryptorReset" and ivIndex = 1
      ) and
      call.getArgument(ivIndex).getExpr() = this.asExpr() and
      not ignoresInitializationVector(call)
    )
  }
}

/**
 * A step from the receiver of `withUnsafeBytes` or `withUnsafeMutableBytes`
 * to the pointer parameter of the closure passed to it. This covers the
 * deprecated generic `Data.withUnsafeBytes` overloads that pass an
 * `UnsafePointer<ContentType>`, which is the usual way to pass a `Data` IV
 * to CommonCrypto.
 */
private class WithUnsafeBytesStep extends StaticInitializationVectorAdditionalFlowStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(CallExpr call, ClosureExpr closure |
      call.getStaticTarget().(Function).getShortName() =
        ["withUnsafeBytes", "withUnsafeMutableBytes"] and
      call.getQualifier() = nodeFrom.asExpr() and
      closure = call.getArgument(0).getExpr() and
      nodeTo.asParameter() = closure.getParam(0)
    )
  }
}

/**
 * A step from a (non-`inout`) parameter to a read of that parameter inside a
 * nested closure. CommonCrypto calls are usually nested in several closures
 * passed to library methods such as `withUnsafeBytes`, which have no body in
 * the database, so the dataflow library cannot see these closures being
 * called and does not track captured values into them. Parameters cannot be
 * reassigned, so the step is safe regardless of when the closure runs.
 */
private class CapturedParameterStep extends StaticInitializationVectorAdditionalFlowStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Callable c, ParamDecl p, DeclRefExpr read |
      p = c.getAParam() and
      not p.isInout() and
      nodeFrom.asParameter() = p and
      read.getDecl() = p and
      read.getEnclosingCallable() instanceof ClosureExpr and
      read.getEnclosingCallable() != c and
      nodeTo.asExpr() = read
    )
  }
}

/**
 * An expression that is a static IV for this query: a constant
 * array, string or number (as in the standard query), a `nil` literal, or a
 * default argument value that a caller does not override.
 */
class ExtendedStaticInitializationVectorSource extends Expr {
  ExtendedStaticInitializationVectorSource() {
    this instanceof StaticInitializationVectorSource
    or
    this instanceof NilLiteralExpr
    or
    this instanceof DefaultArgumentExpr and
    not this.(DefaultArgumentExpr).hasCallerSideDefault()
  }
}

/**
 * A taint-tracking configuration from static IVs (including `nil` and
 * default argument values) to expressions that use them as an IV.
 */
module StaticInitializationVectorExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node.asExpr() instanceof ExtendedStaticInitializationVectorSource
  }

  predicate isSink(DataFlow::Node node) { node instanceof StaticInitializationVectorSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof StaticInitializationVectorBarrier }

  predicate isBarrierIn(DataFlow::Node node) {
    // make sources barriers so that we only report the closest instance
    isSource(node)
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    any(StaticInitializationVectorAdditionalFlowStep s).step(nodeFrom, nodeTo)
  }
}

/** Taint flow from static IVs to expressions that use them as an IV. */
module StaticInitializationVectorExtendedFlow =
  TaintTracking::Global<StaticInitializationVectorExtendedConfig>;

/**
 * Holds if a static IV `source` flows to `sink` and the result is not
 * already reported by the standard `swift/static-initialization-vector`
 * query. `message` describes the result.
 */
predicate staticInitializationVectorExtended(
  StaticInitializationVectorExtendedFlow::PathNode source,
  StaticInitializationVectorExtendedFlow::PathNode sink, string message
) {
  StaticInitializationVectorExtendedFlow::flowPath(source, sink) and
  exists(Expr src | src = source.getNode().asExpr() |
    // `nil` means "all zeros" only for CommonCrypto; other libraries (for
    // example RNCryptor) generate a random IV instead.
    src instanceof NilLiteralExpr and
    sink.getNode() instanceof CommonCryptoInitializationVectorSink and
    message = "A nil initialization vector (all zero bytes) is used for encryption."
    or
    src instanceof DefaultArgumentExpr and
    message =
      "The default value of parameter '" + src.(DefaultArgumentExpr).getParamDecl().getName() +
        "' is used as an initialization vector for encryption."
    or
    // the standard query already reports static values that reach its own sinks
    src instanceof StaticInitializationVectorSource and
    sink.getNode() instanceof CommonCryptoInitializationVectorSink and
    message =
      "The static value '" + src.toString() +
        "' is used as an initialization vector for encryption."
  )
}
