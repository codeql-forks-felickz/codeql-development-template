/**
 * Provides a taint-tracking configuration for finding encryption functions
 * that only apply reversible Base64 encoding to their input.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking

/** A function declared in source code whose name claims that it encrypts data. */
class EncryptionNamedFunction extends Function {
  EncryptionNamedFunction() {
    this.getShortName().regexpMatch("(?i).*(encrypt|encipher).*") and
    exists(this.getBody())
  }
}

/** A call that Base64-encodes its receiver, such as `data.base64EncodedString()`. */
class Base64EncodeCall extends CallExpr {
  Base64EncodeCall() {
    this.getStaticTarget()
        .(Method)
        .hasQualifiedName(["Data", "NSData"],
          ["base64EncodedString(options:)", "base64EncodedData(options:)"])
  }
}

/**
 * Holds if `call` calls an actual cryptographic operation (or another function
 * that claims to perform one), as opposed to a mere encoding.
 */
private predicate isCryptoCall(CallExpr call) {
  call.getStaticTarget()
      .(Function)
      .getShortName()
      .regexpMatch("(?i).*(crypt|cipher|seal|aes|chacha|rsa|ecies|secKey).*") and
  not call instanceof Base64EncodeCall
}

module Base64AsEncryptionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node.(DataFlow::ParameterNode).asParameter() = any(EncryptionNamedFunction f).getAParam()
  }

  predicate isSink(DataFlow::Node node) {
    node.asExpr() = any(Base64EncodeCall call).getQualifier()
  }

  predicate isBarrier(DataFlow::Node node) {
    // values that are actually encrypted before being encoded are fine
    exists(CallExpr call | isCryptoCall(call) |
      node.asExpr() = call.getAnArgument().getExpr() or
      node.asExpr() = call.getQualifier()
    )
  }
}

module Base64AsEncryptionFlow = TaintTracking::Global<Base64AsEncryptionConfig>;

/**
 * Holds if `call` Base64-encodes the input of the encryption-named function
 * `f` without encrypting it first.
 */
predicate base64AsEncryption(Base64EncodeCall call, EncryptionNamedFunction f) {
  exists(DataFlow::Node source, DataFlow::Node sink |
    Base64AsEncryptionFlow::flow(source, sink) and
    source.(DataFlow::ParameterNode).asParameter() = f.getAParam() and
    sink.asExpr() = call.getQualifier() and
    call.getEnclosingFunction() = f
  )
}
