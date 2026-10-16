/**
 * Provides a taint-tracking configuration for hard-coded encryption keys that
 * extends the standard `swift/hardcoded-key` query with CommonCrypto sinks and
 * with keys that are stored in global constants or property initializers.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.HardcodedEncryptionKeyQuery
import CredentialAndDataExposure

/** Holds if `source` is a hard-coded key value originating from the literal `origin`. */
predicate isHardcodedKeySource(DataFlow::Node source, Expr origin) {
  source.asExpr() instanceof KeySource and origin = source.asExpr()
  or
  origin = source.(HardcodedNonLocalValue).getOrigin() and
  (origin instanceof KeySource or origin instanceof ArrayExpr)
}

module ExtendedHardcodedKeyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { isHardcodedKeySource(node, _) }

  predicate isSink(DataFlow::Node node) { node instanceof HardcodedEncryptionKeySink }

  predicate isBarrier(DataFlow::Node node) { node instanceof HardcodedEncryptionKeyBarrier }

  predicate isBarrierIn(DataFlow::Node node) {
    // make sources barriers so that we only report the closest instance
    isSource(node)
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    any(HardcodedEncryptionKeyAdditionalFlowStep s).step(nodeFrom, nodeTo)
  }
}

module ExtendedHardcodedKeyFlow = TaintTracking::Global<ExtendedHardcodedKeyConfig>;
