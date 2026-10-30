/**
 * Provides a taint-tracking configuration for cleartext logging of sensitive
 * information that extends the standard `swift/cleartext-logging` query with
 * sensitive user interface inputs (such as `cvvTextField`) as sources.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.CleartextLoggingQuery
import CredentialAndDataExposure

module ExtendedCleartextLoggingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    CleartextLoggingConfig::isSource(node) or
    node.asExpr() instanceof SensitiveUiInputExpr
  }

  predicate isSink(DataFlow::Node node) { CleartextLoggingConfig::isSink(node) }

  predicate isBarrier(DataFlow::Node node) { CleartextLoggingConfig::isBarrier(node) }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    CleartextLoggingConfig::isAdditionalFlowStep(nodeFrom, nodeTo)
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    // flow out of the variadic arguments array at a sink, for example
    // `NSLog("%@", cvvTextField.text ?? "")`
    isSink(node) and
    c.getAReadContent() instanceof DataFlow::Content::CollectionContent
  }
}

module ExtendedCleartextLoggingFlow = TaintTracking::Global<ExtendedCleartextLoggingConfig>;
